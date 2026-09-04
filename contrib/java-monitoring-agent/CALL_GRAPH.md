# Call graph: Java agent ↔ Tetragon

Detailed function-level call graph for the Java monitoring agent
(`contrib/java-monitoring-agent`) and the Tetragon side that consumes its
events (`pkg/javaipc`, `pkg/api/javaapi`, `pkg/sensors/tracing/genericjava.go`,
`pkg/grpc/tracing`, `pkg/process`).

## Java agent — class-load time

```
premain(agentArgs, instrumentation)                     TetragonAgent.java:26
├─ parseArgs(agentArgs) → Map<String,String>             TetragonAgent.java:55
├─ argument(args, "class") / argument(args, "method")    TetragonAgent.java:42
├─ JavaIPC.open(path) → JavaIPC                          JavaIPC.java:118
│  ├─ compute slots/mappedLength (same formula Tetragon's ringGeometry() uses, from
│  │  the same RECORD_LEN/RING_SIZE/HEADER_LEN constants — no negotiation needed)
│  ├─ OPEN.invokeExact(cRingPath, O_RDWR)                 → libc open()  (fails if Tetragon hasn't created the file yet)
│  ├─ MMAP.invokeExact(NULL, mappedLength, RW, MAP_SHARED, ringFd, 0) → libc mmap()
│  ├─ validate header: magic/version/recordLen/slots match what was just computed
│  ├─ on any failure: cleanup(ringFd, ring, mappedLength, arena)
│  │    ├─ closeFd(ringFd)                                 → libc close()
│  │    └─ MUNMAP.invokeExact(ring, length)                → libc munmap()
│  └─ new JavaIPC(arena, ringFd, ring, mappedLength, slots)
└─ instrumentation.addTransformer(new Transformer(className, methodName), false)
```

(The agent no longer creates or deletes the ring file — Tetragon owns its
lifecycle. There is no socket and no registration handshake.)

## Java agent — per-class transform (lazily, on each class load matching the filter)

```
Transformer.transform(loader, className, redefining, domain, bytes)  TetragonAgent.java:98
├─ excluded(className)                                    TetragonAgent.java:118  (skips java/, jdk/, sun/, org/objectweb/asm/, io/tetragon/javaagent/)
├─ new ClassReader(bytes)
├─ new ClassWriter(reader, COMPUTE_MAXS)
└─ reader.accept(new Visitor(writer, className, targetMethod), EXPAND_FRAMES)
   └─ Visitor.visitMethod(access, name, descriptor, signature, exceptions)   TetragonAgent.java:139
      ├─ super.visitMethod(...) → MethodVisitor
      ├─ methodId(className, name, descriptor) → long (FNV-1a-like hash)     TetragonAgent.java:76
      └─ new AdviceAdapter(...) { onMethodEnter() }                          TetragonAgent.java:148
         └─ onMethodEnter(): emits bytecode —
            visitLdcInsn(id/className/name/descriptor) × 4
            + visitMethodInsn(INVOKESTATIC, TetragonAgent, "onMethodEntry", "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V")
```

(`onMethodEnter` doesn't *call* `onMethodEntry` — it injects the bytecode that
calls it, executed later at method-entry time.)

## Java agent — runtime, once per instrumented method invocation

```
<instrumented method>()                                   (injected call, runs first)
└─ TetragonAgent.onMethodEntry(methodId, className, methodName, descriptor)   TetragonAgent.java:68
   └─ JavaIPC.submit(methodId, className, methodName, descriptor) → boolean  JavaIPC.java:196
      ├─ LONG.getAcquire(ring, PRODUCER_OFF/CONSUMER_OFF)   full-ring check
      ├─ putString(offset, value) × 3 (class/method/descriptor)              JavaIPC.java:231
      │  └─ validUtf8(bytes, length)                        JavaIPC.java:240 (truncates on invalid UTF-8 boundary)
      ├─ MemorySegment.copy(packet → ring[offset])           writes the 432-byte record
      ├─ LONG.setRelease(ring, PRODUCER_OFF, producer+1)
      └─ if ring was empty: INT.getAndAdd(NOTIFY_OFF,1) + SYSCALL.invokeExact(SYS_FUTEX, notify, FUTEX_WAKE, 1, ...)
```

---

## Tetragon — startup

```
Observer.RunEvents(stopCtx, ready)                          pkg/observer/observer_linux.go:~100
└─ javaipc.CreateRing(option.Config.JavaIPCPath) → *javaipc.Ring   pkg/javaipc/ring_linux.go:65
   ├─ ringGeometry() → slots, mappedLength                   ring_linux.go:55
   ├─ unix.Open(path, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0660)
   ├─ unix.Ftruncate(fd, mappedLength)
   ├─ unix.Pwrite(fd, header)                                 writes magic/version/record-size/slot-count
   └─ openRing(path) → *Ring, error                           ring_linux.go:95  (mmap + re-validate)
└─ wg.Go(func(){ defer javaRing.Close(); javaRing.Serve(stopCtx, callback) })
```

There is no socket and no registration handshake: Tetragon creates the ring
file directly at startup, and the Java agent just opens the existing file
(see the agent's `open()` above).

## Tetragon — draining the ring

```
(*Ring).Serve(ctx, callback)                                ring_linux.go:163
└─ loop:
   ├─ (*Ring).drain(func(data){ ... }) → count                ring_linux.go:181
   │  └─ per record: javaapi.PreparePacket(data) → error       javaapi.go:49
   │     (validates size/opcode/UTF-8, copies Common.Ktime into ProcessKey.Ktime;
   │      the JVM's self-reported PID is trusted as-is — no peer to authenticate it against)
   │     └─ on success: callback(data)                         → observer_linux.go's closure:
   │                                                              bufPtr from pool; copy; eventsQueue <- bufPtr (or drop, queueLost.Inc())
   └─ if nothing drained: waitForRing(r, ctx.Done())            ring_linux.go:198
      └─ unix.Syscall6(SYS_FUTEX, notify, FUTEX_WAIT, seq, timeout=100ms, ...)  (bounded wait, re-checks ctx each wake)
```

## Tetragon — event decode → gRPC dispatch (generic pipeline, Java's hook points marked)

```
(consumer goroutine) eventRawSample := <-eventsQueue        observer_linux.go:223
└─ Observer.receiveEvent(data)                               pkg/observer/observer.go:120
   └─ HandlePerfData(data) → (op, events, err)                observer.go:89
      └─ eventHandler[ops.MSG_OP_JAVA] = handleJava           pkg/sensors/tracing/genericjava.go:29 (registered at init via RegisterEventHandlerAtInit)
         └─ handleJava(r) → []observer.Event                  genericjava.go:16
            ├─ binary.Read(r, &msg javaapi.MsgJava)
            └─ returns &grpctracing.MsgJavaEvent{Msg: &msg}
   └─ Observer.observerListeners(event)                       observer.go:45
      └─ for each listener: listener.Notify(event)
         └─ ProcessManager.Notify(event)                      pkg/grpc/process_manager.go:58
            └─ event.HandleMessage() → *tetragon.GetEventsResponse   pkg/grpc/tracing/tracing.go:523  (MsgJavaEvent.HandleMessage)
               ├─ process.GetParentProcessInternalByPID(pid, ktime)  pkg/process/process.go:565
               │  └─ procCache.getByPID(pid, ktime)                  pkg/process/cache.go:273 (PID secondary index, newest exec ≤ event ktime)
               ├─ proc.AnnotateProcess(...) / process.GetAncestorProcessesInternal(...)  (if proc found / ancestors enabled)
               ├─ on cache-miss: MsgJavaEvent.RetryInternal / .Retry → eventcache.HandleGenericEvent   tracing.go:501,512
               └─ builds tetragon.ProcessJava{...} → GetEventsResponse_ProcessJava
            └─ pm.NotifyListener(event, processedEvent)              → fan-out to gRPC GetEvents subscribers
               → pkg/encoder/encoder.go / pkg/filters/filters.go apply the generic export/filter path (ProcessJava case already wired in both)
```

The two halves meet at exactly one point now: the **shared-memory ring file**
that Tetragon creates and the agent opens (Java's `submit()` writes ↔ Go's
`drain()` reads). There is no socket, no handshake, and no authentication of
the writer — a deliberate simplification for local/trusted use.
