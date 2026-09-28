package space.seclume.bench;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.infra.Blackhole;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Pbkdf2;

/**
 * PBKDF2 as a login pays for it: SCRAM-SHA-256's default of 4096 rounds, and
 * Oracle 12c's SHA-512. Once per new connection, so it is the part of a
 * connect that does not depend on the network.
 *
 * <p>The JDK's {@code PBKDF2WithHmac...} is the yardstick, not a candidate:
 * it takes the password as a {@code char[]} and would put it on the heap. It
 * runs on the CPU's SHA instructions where there are some, which seclume's
 * digests do not.
 *
 * <p>No database. {@code java -jar seclume-bench.jar Pbkdf2Benchmark}
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Thread)
public class Pbkdf2Benchmark {

    @Param({"SHA_256", "SHA_512"})
    public String algorithm;

    @Param({"4096"})
    public int iterations;

    private static final String PASSWORD = "benchmark-password-not-a-secret";

    private Arena arena;
    private HashAlgorithm hash;
    private MemorySegment password;
    private MemorySegment salt;
    private MemorySegment out;
    private SecretKeyFactory jdk;
    private byte[] saltBytes;

    @Setup(Level.Trial)
    public void prepare() throws GeneralSecurityException {
        hash = HashAlgorithm.valueOf(algorithm);
        arena = Arena.ofConfined();
        byte[] bytes = PASSWORD.getBytes(StandardCharsets.US_ASCII);
        password = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, password, ValueLayout.JAVA_BYTE, 0, bytes.length);
        saltBytes = new byte[16];
        salt = arena.allocate(saltBytes.length);
        out = arena.allocate(hash.digestLength());
        jdk = SecretKeyFactory.getInstance(hash == HashAlgorithm.SHA_512
                ? "PBKDF2WithHmacSHA512" : "PBKDF2WithHmacSHA256");
    }

    @TearDown(Level.Trial)
    public void release() {
        arena.close();
    }

    @Benchmark
    public void seclume(Blackhole sink) {
        Pbkdf2.derive(hash, password, salt, iterations, out);
        sink.consume(out.get(ValueLayout.JAVA_BYTE, 0));
    }

    @Benchmark
    public byte[] jdk() throws GeneralSecurityException {
        return jdk.generateSecret(new PBEKeySpec(PASSWORD.toCharArray(), saltBytes, iterations,
                hash.digestLength() * 8)).getEncoded();
    }
}
