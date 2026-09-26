package space.seclume.bench;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.tls.RecordProtection;

/**
 * One TLS 1.3 record of seclume's own stack, sealed and opened - no socket,
 * no database, only the record layer and the AES-GCM beneath it.
 *
 * <p>A query result arrives as records of up to 16 KiB, a small statement
 * leaves as one short record, so both sizes are measured. {@code cipher}
 * picks the AES-GCM: {@code native} is OpenSSL on Linux and CNG on Windows,
 * {@code java} the constant-time fallback a platform without either gets.
 * The difference between the payload's own cost and the time per record is
 * what the record layer adds around the cipher.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Thread)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class RecordBenchmark {

    @Param({"64", "16384"})
    int payload;

    @Param({"native", "java"})
    String cipher;

    private Arena arena;
    private MemorySegment plain;
    private MemorySegment wire;
    private MemorySegment opened;
    private MemorySegment sealed;
    private int sealedLength;
    private RecordProtection sealer;
    private RecordProtection opener;

    @Setup(Level.Trial)
    public void keys() {
        String before = System.getProperty("seclume.crypto.aesGcm");
        if ("java".equals(cipher)) {
            System.setProperty("seclume.crypto.aesGcm", "java");
        } else {
            System.clearProperty("seclume.crypto.aesGcm");
        }
        arena = Arena.ofShared();
        MemorySegment secret = arena.allocate(32);
        for (int i = 0; i < 32; i++) {
            secret.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 7 + 1));
        }
        sealer = RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16);
        opener = RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16);
        if (before == null) {
            System.clearProperty("seclume.crypto.aesGcm");
        } else {
            System.setProperty("seclume.crypto.aesGcm", before);
        }
        boolean gotJava = "java".equals(sealer.cipherImplementation());
        if (gotJava != "java".equals(cipher)) {
            throw new IllegalStateException("asked for " + cipher + ", got "
                    + sealer.cipherImplementation());
        }

        int max = RecordProtection.sealedLength(16384) + 256;
        plain = arena.allocate(payload);
        wire = arena.allocate(max);
        opened = arena.allocate(max);
        sealed = arena.allocate(max);
        // One record sealed ahead, always opened under sequence 0.
        sealedLength = sealer.seal(RecordProtection.APPLICATION_DATA, plain, 0, payload, sealed, 0);
        sealer.sequence(0);
    }

    @Benchmark
    public int seal() {
        return sealer.seal(RecordProtection.APPLICATION_DATA, plain, 0, payload, wire, 0);
    }

    @Benchmark
    public int open() {
        opener.sequence(0);
        return opener.open(sealed, 0, sealedLength, opened, 0).length();
    }

    @TearDown(Level.Trial)
    public void close() {
        sealer.close();
        opener.close();
        arena.close();
    }
}
