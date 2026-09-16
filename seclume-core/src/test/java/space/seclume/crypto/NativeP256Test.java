package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import javax.crypto.KeyAgreement;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/** The same tests run against Windows CNG and Linux OpenSSL, without an OS skip. */
class NativeP256Test {
    static Stream<String[]> vectors() throws Exception {
        try (var in = NativeP256Test.class.getResourceAsStream("/rfc5903-p256.tsv");
                var reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.US_ASCII))) {
            return reader.lines().filter(s -> !s.startsWith("#") && !s.isBlank())
                    .map(s -> s.split("\t")).toList().stream();
        }
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void agreesWithPublishedVector(String name, String scalar, String own, String peer, String expected) {
        try (Arena arena = Arena.ofConfined();
                NativeP256 key = NativeP256.importKey(hex(arena, own), hex(arena, scalar))) {
            MemorySegment out = arena.allocate(32);
            key.derive(hex(arena, peer), out);
            assertEquals(-1, hex(arena, expected).mismatch(out), name + " shared x");
            MemorySegment publicKey = arena.allocate(65);
            key.publicKey(publicKey);
            assertEquals(-1, hex(arena, own).mismatch(publicKey));
            key.privateScalar(out);
            assertEquals(-1, hex(arena, scalar).mismatch(out));
            out.fill((byte) 0);
        }
    }

    @Test
    void generatedKeysAgreeWithIndependentJcaPeer() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec curve = parameters.getParameterSpec(ECParameterSpec.class);
        for (int attempt = 0; attempt < 16; attempt++) {
            try (Arena arena = Arena.ofConfined(); NativeP256 key = NativeP256.generate()) {
                KeyPair peer = generator.generateKeyPair();
                MemorySegment point = arena.allocate(65);
                ECPublicKey peerPublic = (ECPublicKey) peer.getPublic();
                point.set(ValueLayout.JAVA_BYTE, 0, (byte) 4);
                coordinate(peerPublic.getW().getAffineX(), point.asSlice(1, 32));
                coordinate(peerPublic.getW().getAffineY(), point.asSlice(33, 32));
                MemorySegment actual = arena.allocate(32);
                key.derive(point, actual);
                key.publicKey(point);
                byte[] publicBytes = point.toArray(ValueLayout.JAVA_BYTE);
                ECPoint coordinates = new ECPoint(new BigInteger(1, Arrays.copyOfRange(publicBytes, 1, 33)),
                        new BigInteger(1, Arrays.copyOfRange(publicBytes, 33, 65)));
                KeyAgreement jca = KeyAgreement.getInstance("ECDH");
                jca.init(peer.getPrivate());
                jca.doPhase(KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(coordinates, curve)), true);
                assertArrayEquals(jca.generateSecret(), actual.toArray(ValueLayout.JAVA_BYTE));
                actual.fill((byte) 0);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 2, 3, 4, 6, 7})
    void rejectsInvalidPeerPointsWithoutChangingOutput(int prefix) {
        try (Arena arena = Arena.ofConfined(); NativeP256 key = NativeP256.generate()) {
            MemorySegment peer = arena.allocate(65); // (0,0) is not on P-256
            peer.set(ValueLayout.JAVA_BYTE, 0, (byte) prefix);
            MemorySegment out = arena.allocate(32).fill((byte) 0x5a);
            assertThrows(RuntimeException.class, () -> key.derive(peer, out));
            for (int i = 0; i < 32; i++) assertEquals(0x5a, out.get(ValueLayout.JAVA_BYTE, i));
            // A rejected peer must not destroy or corrupt our private key.
            try (NativeP256 good = NativeP256.generate()) {
                good.publicKey(peer);
                key.derive(peer, out);
            }
            out.fill((byte) 0);
        }
    }

    @Test
    void rejectsOutOfFieldCoordinates() {
        try (Arena arena = Arena.ofConfined(); NativeP256 key = NativeP256.generate()) {
            MemorySegment peer = arena.allocate(65).fill((byte) 0xff);
            peer.set(ValueLayout.JAVA_BYTE, 0, (byte) 4);
            assertThrows(RuntimeException.class, () -> key.derive(peer, arena.allocate(32)));
        }
    }

    @Test
    void lifetimeAndBuffersAreCheckedBeforeNativeCalls() throws Exception {
        try (Arena arena = Arena.ofConfined()) {
            NativeP256 key = NativeP256.generate();
            try {
                MemorySegment peer = arena.allocate(65);
                key.publicKey(peer);
                MemorySegment out = arena.allocate(32);
                assertThrows(IllegalArgumentException.class, () -> key.derive(peer, MemorySegment.ofArray(new byte[32])));
                assertThrows(IllegalArgumentException.class, () -> key.derive(peer, out.asReadOnly()));
                assertThrows(IllegalArgumentException.class, () -> key.derive(peer, out.asSlice(0, 31)));
                assertThrows(IllegalArgumentException.class, () -> key.derive(peer.asSlice(0, 64), out));
                AtomicReference<Throwable> failure = new AtomicReference<>();
                Thread thread = Thread.ofPlatform().start(() -> {
                    try { key.publicKey(peer); } catch (Throwable e) { failure.set(e); }
                });
                thread.join();
                assertInstanceOf(IllegalStateException.class, failure.get());
            } finally {
                key.close();
            }
            key.close();
            assertThrows(IllegalStateException.class, () -> key.publicKey(arena.allocate(65)));
            assertThrows(IllegalStateException.class, () -> key.derive(arena.allocate(65), arena.allocate(32)));
        }
    }

    static MemorySegment hex(Arena arena, String text) {
        return arena.allocateFrom(ValueLayout.JAVA_BYTE, HexFormat.of().parseHex(text));
    }

    private static void coordinate(BigInteger integer, MemorySegment out) {
        for (int i = 0; i < 32; i++) out.set(ValueLayout.JAVA_BYTE, 31 - i, integer.shiftRight(8 * i).byteValue());
    }
}
