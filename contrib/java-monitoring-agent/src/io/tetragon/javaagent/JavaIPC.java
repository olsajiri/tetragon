/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Tetragon */

package io.tetragon.javaagent;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/** Fixed-size, non-blocking SPSC producer registered over the Unix socket. */
final class JavaIPC implements AutoCloseable {
	static final String DEFAULT_PATH = "/var/run/tetragon/java.sock";
	private static final int RECORD_LEN = 432;
	private static final int STRING_LEN = 128;
	private static final int RING_SIZE = 4 * 1024 * 1024;
	private static final int HEADER_LEN = 256;
	private static final int PRODUCER_OFF = 64;
	private static final int CONSUMER_OFF = 128;
	private static final int NOTIFY_OFF = 192;
	private static final int MAGIC = 0x4a52534a;
	private static final int VERSION = 1;
	private static final int REG_MAGIC = 0x4a524547;
	private static final int REG_VERSION = 1;
	private static final int ACK_MAGIC = 0x4a524143;
	private static final int AF_UNIX = 1;
	private static final int SOCK_SEQPACKET = 5;
	private static final int MSG_DONTWAIT = 0x40;
	private static final int MSG_NOSIGNAL = 0x4000;
	private static final int O_RDWR = 2;
	private static final int PROT_READ = 1;
	private static final int PROT_WRITE = 2;
	private static final int MAP_SHARED = 1;
	private static final int FUTEX_WAKE = 1;
	private static final int MSG_OP_JAVA = 29;
	private static final int SOCKET_ADDRESS_OFFSET = 2;
	private static final int SOCKET_ADDRESS_LEN = 110;

	private static final Linker LINKER = Linker.nativeLinker();
	private static final SymbolLookup LIBC = LINKER.defaultLookup();
	private static final MethodHandle SOCKET = downcall("socket", FunctionDescriptor.of(
			ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
	private static final MethodHandle CONNECT = downcall("connect", FunctionDescriptor.of(
			ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
	private static final MethodHandle SEND = downcall("send", FunctionDescriptor.of(
			ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
			ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT));
	private static final MethodHandle RECV = downcall("recv", FunctionDescriptor.of(
			ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
			ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT));
	private static final MethodHandle OPEN = downcall("open", FunctionDescriptor.of(
			ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
	private static final MethodHandle MMAP = downcall("mmap", FunctionDescriptor.of(
			ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
			ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
	private static final MethodHandle MUNMAP = downcall("munmap", FunctionDescriptor.of(
			ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
	private static final MethodHandle SYSCALL = downcall("syscall", FunctionDescriptor.of(
			ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
			ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
	private static final MethodHandle CLOSE = downcall("close", FunctionDescriptor.of(
			ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
	private static final MethodHandle GETTID = downcall("gettid", FunctionDescriptor.of(ValueLayout.JAVA_INT));

	private static final VarHandle INT = ValueLayout.JAVA_INT.withOrder(ByteOrder.LITTLE_ENDIAN).varHandle();
	private static final VarHandle LONG = ValueLayout.JAVA_LONG.withOrder(ByteOrder.LITTLE_ENDIAN).varHandle();
	private static final ValueLayout.OfShort NATIVE_SHORT = ValueLayout.JAVA_SHORT.withOrder(ByteOrder.nativeOrder());
	private static final long JVM_PID = ProcessHandle.current().pid();
	private static final int SYS_FUTEX = futexNumber();
	private static final ThreadLocal<Integer> LINUX_TID = ThreadLocal.withInitial(JavaIPC::gettid);

	private final Arena arena;
	private final int socketFd;
	private final int ringFd;
	private final Path ringPath;
	private final MemorySegment ring;
	private final MemorySegment packet;
	private final long mappedLength;
	private final long slots;
	private final long mask;
	private final Object writeLock = new Object();
	private boolean closed;

	private JavaIPC(Arena arena, int socketFd, int ringFd, Path ringPath,
			MemorySegment ring, long mappedLength, long slots) {
		this.arena = arena;
		this.socketFd = socketFd;
		this.ringFd = ringFd;
		this.ringPath = ringPath;
		this.ring = ring;
		this.packet = arena.allocate(RECORD_LEN, 8);
		this.mappedLength = mappedLength;
		this.slots = slots;
		this.mask = slots - 1;
	}

	private static MethodHandle downcall(String name, FunctionDescriptor descriptor) {
		MemorySegment symbol = LIBC.find(name)
				.orElseThrow(() -> new UnsatisfiedLinkError("libc symbol not found: " + name));
		return LINKER.downcallHandle(symbol, descriptor);
	}

	static JavaIPC open(String path) throws IOException {
		byte[] socketPath = path.getBytes(StandardCharsets.UTF_8);
		if (socketPath.length == 0 || socketPath.length >= 108) {
			throw new IOException("Unix socket path is empty or too long");
		}
		Path ringPath = null;
		Arena arena = Arena.ofShared();
		int socketFd = -1;
		int ringFd = -1;
		MemorySegment ring = null;
		long mappedLength = 0;
		try {
			ringPath = Files.createTempFile(Path.of("/dev/shm"), "tetragon-java-" + JVM_PID + "-", ".ring");
			Files.setPosixFilePermissions(ringPath, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
			long slots = 1;
			while (HEADER_LEN + (slots << 1) * RECORD_LEN <= RING_SIZE) {
				slots <<= 1;
			}
			slots >>= 1;
			mappedLength = HEADER_LEN + slots * RECORD_LEN;
			try (FileChannel channel = FileChannel.open(ringPath, java.nio.file.StandardOpenOption.WRITE)) {
				channel.position(mappedLength - 1);
				channel.write(ByteBuffer.wrap(new byte[] { 0 }));
			}

			MemorySegment cRingPath = cString(arena, ringPath.toString());
			ringFd = (int) OPEN.invokeExact(cRingPath, O_RDWR);
			if (ringFd < 0) {
				throw new IOException("open shared-memory ring failed");
			}
			MemorySegment mapped = (MemorySegment) MMAP.invokeExact(MemorySegment.NULL, mappedLength,
					PROT_READ | PROT_WRITE, MAP_SHARED, ringFd, 0L);
			if (mapped.address() == -1L) {
				throw new IOException("mmap shared-memory ring failed");
			}
			ring = mapped.reinterpret(mappedLength);
			INT.set(ring, 0L, MAGIC);
			INT.set(ring, 4L, VERSION);
			INT.set(ring, 8L, RECORD_LEN);
			LONG.set(ring, 16L, slots);
			LONG.setRelease(ring, PRODUCER_OFF, 0L);
			LONG.setRelease(ring, CONSUMER_OFF, 0L);
			INT.setRelease(ring, NOTIFY_OFF, 0);

			socketFd = (int) SOCKET.invokeExact(AF_UNIX, SOCK_SEQPACKET, 0);
			if (socketFd < 0) {
				throw new IOException("socket(AF_UNIX, SOCK_SEQPACKET) failed");
			}
			MemorySegment address = arena.allocate(SOCKET_ADDRESS_LEN, 1);
			address.fill((byte) 0);
			address.set(NATIVE_SHORT, 0, (short) AF_UNIX);
			MemorySegment.copy(MemorySegment.ofArray(socketPath), 0, address,
					SOCKET_ADDRESS_OFFSET, socketPath.length);
			if ((int) CONNECT.invokeExact(socketFd, address, SOCKET_ADDRESS_LEN) < 0) {
				throw new IOException("connect(" + path + ") failed");
			}
			byte[] registration = registration(ringPath.toString());
			MemorySegment registrationSegment = arena.allocate(registration.length, 1);
			MemorySegment.copy(MemorySegment.ofArray(registration), 0, registrationSegment, 0, registration.length);
			if ((long) SEND.invokeExact(socketFd, registrationSegment, (long) registration.length,
					MSG_NOSIGNAL) != registration.length) {
				throw new IOException("register shared-memory ring failed");
			}
			MemorySegment ack = arena.allocate(8, 4);
			if ((long) RECV.invokeExact(socketFd, ack, 8L, 0) != 8L ||
					(int) INT.get(ack, 0L) != ACK_MAGIC || (int) INT.get(ack, 4L) != 0) {
				throw new IOException("shared-memory ring registration was rejected");
			}
			return new JavaIPC(arena, socketFd, ringFd, ringPath, ring, mappedLength, slots);
		} catch (IOException | RuntimeException error) {
			cleanup(socketFd, ringFd, ring, mappedLength, ringPath, arena);
			throw error;
		} catch (Throwable error) {
			cleanup(socketFd, ringFd, ring, mappedLength, ringPath, arena);
			throw new IOException("opening Java shared-memory IPC failed", error);
		}
	}

	boolean submit(long methodId, String className, String methodName, String descriptor) {
		synchronized (writeLock) {
			if (closed) {
				return false;
			}
			long producer = (long) LONG.getAcquire(ring, PRODUCER_OFF);
			long consumer = (long) LONG.getAcquire(ring, CONSUMER_OFF);
			if (producer - consumer >= slots) {
				return false;
			}
			packet.fill((byte) 0);
			packet.set(ValueLayout.JAVA_BYTE, 0, (byte) MSG_OP_JAVA);
			INT.set(packet, 4L, RECORD_LEN);
			LONG.set(packet, 8L, System.nanoTime());
			INT.set(packet, 16L, (int) JVM_PID);
			LONG.set(packet, 32L, methodId);
			INT.set(packet, 40L, LINUX_TID.get());
			putString(44, className);
			putString(172, methodName);
			putString(300, descriptor);
			long offset = HEADER_LEN + (producer & mask) * RECORD_LEN;
			MemorySegment.copy(packet, 0, ring, offset, RECORD_LEN);
			LONG.setRelease(ring, PRODUCER_OFF, producer + 1);
			if (producer == consumer) {
				INT.getAndAdd(ring, NOTIFY_OFF, 1);
				try {
					SYSCALL.invokeExact((long) SYS_FUTEX, ring.asSlice(NOTIFY_OFF, 4L),
							(long) FUTEX_WAKE, 1L, MemorySegment.NULL, MemorySegment.NULL);
				} catch (Throwable ignored) {
				}
			}
			return true;
		}
	}

	private void putString(long offset, String value) {
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		int length = Math.min(bytes.length, STRING_LEN - 1);
		while (length > 0 && !validUtf8(bytes, length)) {
			length--;
		}
		MemorySegment.copy(MemorySegment.ofArray(bytes), 0, packet, offset, length);
	}

	private static boolean validUtf8(byte[] bytes, int length) {
		try {
			StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes, 0, length));
			return true;
		} catch (CharacterCodingException error) {
			return false;
		}
	}

	private static byte[] registration(String path) throws IOException {
		byte[] pathBytes = path.getBytes(StandardCharsets.UTF_8);
		ByteBuffer buffer = ByteBuffer.allocate(12 + pathBytes.length).order(ByteOrder.LITTLE_ENDIAN);
		buffer.putInt(REG_MAGIC).putInt(REG_VERSION).putInt(pathBytes.length).put(pathBytes);
		return buffer.array();
	}

	private static MemorySegment cString(Arena arena, String value) {
		byte[] bytes = (value + "\0").getBytes(StandardCharsets.UTF_8);
		MemorySegment result = arena.allocate(bytes.length, 1);
		MemorySegment.copy(MemorySegment.ofArray(bytes), 0, result, 0, bytes.length);
		return result;
	}

	private static int futexNumber() {
		return switch (System.getProperty("os.arch")) {
			case "aarch64", "riscv64" -> 98;
			case "ppc64le" -> 221;
			default -> 202;
		};
	}

	private static int gettid() {
		try {
			return (int) GETTID.invokeExact();
		} catch (Throwable error) {
			throw new IllegalStateException("gettid failed", error);
		}
	}

	private static void closeFd(int fd) {
		if (fd >= 0) {
			try { CLOSE.invokeExact(fd); } catch (Throwable ignored) { }
		}
	}

	private static void cleanup(int socketFd, int ringFd, MemorySegment ring, long length,
			Path ringPath, Arena arena) {
		closeFd(socketFd);
		if (ring != null && length != 0) {
			try { MUNMAP.invokeExact(ring, length); } catch (Throwable ignored) { }
		}
		closeFd(ringFd);
		if (ringPath != null) {
			try { Files.deleteIfExists(ringPath); } catch (IOException ignored) { }
		}
		arena.close();
	}

	@Override
	public void close() {
		synchronized (writeLock) {
			if (closed) return;
			closed = true;
		}
		cleanup(socketFd, ringFd, ring, mappedLength, ringPath, arena);
	}
}
