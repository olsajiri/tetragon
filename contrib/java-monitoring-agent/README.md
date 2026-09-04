# Tetragon Java method monitoring agent

This JDK 22+ `-javaagent` instruments selected method entries and publishes
fixed 432-byte records into a per-JVM SPSC shared-memory ring. The Unix socket
at `/var/run/tetragon/java.sock` is used only to authenticate the JVM and
register the ring; submission is non-blocking and drops when the ring is full.

Build with ASM 9.x and a JDK 22 or newer:

```shell
make JAVA_HOME=/path/to/jdk-22 \
  ASM_JAR=/path/to/asm-9.x.jar \
  ASM_COMMONS_JAR=/path/to/asm-commons-9.x.jar
```

Start Tetragon with its normal Java IPC socket enabled, then run an application
with native access enabled:

```shell
/path/to/jdk-22/bin/java --enable-native-access=ALL-UNNAMED \
  -javaagent:./tetragon-java-monitoring-agent.jar=class=sample.Sample,method=work \
  -cp build/sample:/path/to/asm-9.x.jar:/path/to/asm-commons-9.x.jar \
  sample.Sample
```

The `class` and `method` arguments are required and may be empty to match all
non-excluded classes or methods. Overloads include their JVM descriptor.
Records contain the Java submission timestamp, stable FNV-1a method ID, class,
method, descriptor, authenticated JVM PID, and Linux TID.
