# Call graph: Tetragon side of the Java agent IPC

Function-level call graph for the Tetragon side of the communication with the
Java monitoring agent (`contrib/java-monitoring-agent`), covering ring
creation and the shared-memory ring drain — not the generic event pipeline
downstream of it (gRPC dispatch, encoder, filters), which is shared by every
Tetragon event type.

There is no handshake: Tetragon creates and owns the ring file at a
well-known path, the agent just opens the existing file, and there is no
authentication of who writes into it. This is a deliberate simplification
for local/trusted use — see `contrib/java-monitoring-agent/README.md`.

## Startup

```
Observer.RunEvents(stopCtx, ready)                          pkg/observer/observer_linux.go:~100
└─ javaipc.CreateRing(option.Config.JavaIPCPath) → *javaipc.Ring   pkg/javaipc/ring_linux.go:65
   ├─ ringGeometry() → slots, mappedLength                    ring_linux.go:55  (same formula the Java agent computes independently)
   ├─ unix.Open(path, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0660)
   ├─ unix.Ftruncate(fd, mappedLength)
   ├─ unix.Pwrite(fd, header)                                 writes magic/version/record-size/slot-count
   └─ openRing(path) → *Ring, error                           ring_linux.go:95  (mmap + re-validate what was just written)
└─ wg.Go(func(){ defer javaRing.Close(); javaRing.Serve(stopCtx, callback) })
```

`callback` is a closure owned by `observer_linux.go`: it takes a pooled
`[]byte`, copies the validated record into it, and pushes it onto the
observer's `eventsQueue` (or drops it and increments `queueLost` if the
queue is full).

## Steady state: draining the ring

```
(*Ring).Serve(ctx, callback)                                 ring_linux.go:163
└─ loop:
   ├─ (*Ring).drain(func(data){ ... }) → count                 ring_linux.go:181
   │  (walks consumer..producer, invoking the callback per record, advancing consumer with atomic.StoreUint64)
   │  └─ per record: javaapi.PreparePacket(data) → error        pkg/api/javaapi/javaapi.go:49
   │     (checks record length == MsgJavaSize, opcode == MSG_OP_JAVA,
   │      common.Size field, UTF-8-validates class/method/descriptor,
   │      copies Common.Ktime into ProcessKey.Ktime — the JVM's self-reported
   │      PID at offset 16 is trusted as-is — and clears
   │      MSG_COMMON_FLAG_PROCESS_NOT_FOUND)
   │     └─ on success (err == nil): callback(data)             → observer's pooled-copy/enqueue closure
   └─ if drain() returned 0: waitForRing(r, ctx.Done()) → bool   ring_linux.go:198
      └─ unix.Syscall6(SYS_FUTEX, &notify, FUTEX_WAIT, seq, timeout=100ms, 0, 0)
         (bounded wait so cancellation / a wake from the JVM's FUTEX_WAKE
         in JavaIPC.submit() are both observed within ~100ms)
(loop exits, and Serve returns, when ctx is cancelled or waitForRing gives up)
```

## Shutdown

```
(*Ring).Close()                                               ring_linux.go:157
├─ unix.Munmap(data)
└─ os.Remove(path)
```

## Where this hands off

`Serve`'s `callback(data)` is the exact point where a raw, validated
432-byte record crosses from `pkg/javaipc` into the observer's
`eventsQueue`. From there it's indistinguishable from a BPF-perf-ring event
and is decoded by `handleJava` (`pkg/sensors/tracing/genericjava.go:16`,
registered for `ops.MSG_OP_JAVA`) into a `grpctracing.MsgJavaEvent`, which is
the last step that's specific to this IPC path — everything after that
(`MsgJavaEvent.HandleMessage`, process-cache lookup, gRPC fan-out, encoder,
filters) is the same generic event pipeline every Tetragon event type goes
through.
