package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

import javax.crypto.KEM;
import javax.crypto.KeyAgreement;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import space.seclume.internal.Platform;

/**
 * The hybrid against the JDK's own ML-KEM and X25519 as the server side: the
 * same test for OpenSSL on Linux and CNG on Windows.
 */
class HybridMlKemTest {

    /** SubjectPublicKeyInfo for ML-KEM-768 (OID 2.16.840.1.101.3.4.4.2) up to the key. */
    private static final byte[] ML_KEM_768_SPKI = HexFormat.of()
            .parseHex("308204b2300b0609608648016503040402038204a100");

    @BeforeEach
    void needsTheHybrid() {
        Assumptions.assumeTrue(HybridMlKem.available(),
                "no ML-KEM here: neither OpenSSL 3.5 nor CNG with the post-quantum update");
    }

    @Test
    void windowsElevenWithThePostQuantumUpdateOffersIt() {
        // This machine is updated; a regression in the probe would silently
        // take the hybrid away and fall back to P-256 alone.
        Assumptions.assumeTrue(Platform.isWindows());
        assertTrue(CngMlKem.AVAILABLE);
    }

    @Test
    void agreesWithTheJdkAsServer() throws Exception {
        for (int round = 0; round < 20; round++) {
            try (Arena arena = Arena.ofConfined(); HybridMlKem client = HybridMlKem.generate()) {
                MemorySegment share = arena.allocate(HybridMlKem.CLIENT_SHARE);
                client.publicShare(share);
                byte[] bytes = share.toArray(ValueLayout.JAVA_BYTE);

                // ML-KEM: the server encapsulates to the client's key.
                byte[] spki = Arrays.copyOf(ML_KEM_768_SPKI, ML_KEM_768_SPKI.length + 1184);
                System.arraycopy(bytes, 0, spki, ML_KEM_768_SPKI.length, 1184);
                PublicKey kemKey = KeyFactory.getInstance("ML-KEM")
                        .generatePublic(new X509EncodedKeySpec(spki));
                KEM.Encapsulated sent = KEM.getInstance("ML-KEM").newEncapsulator(kemKey).encapsulate();

                // X25519: the server's own pair, agreed with the client's u.
                KeyPair server = KeyPairGenerator.getInstance("X25519").generateKeyPair();
                PublicKey clientX = KeyFactory.getInstance("X25519").generatePublic(
                        new XECPublicKeySpec(NamedParameterSpec.X25519,
                                littleEndian(Arrays.copyOfRange(bytes, 1184, 1216))));
                KeyAgreement agreement = KeyAgreement.getInstance("X25519");
                agreement.init(server.getPrivate());
                agreement.doPhase(clientX, true);
                byte[] ecdh = agreement.generateSecret();

                byte[] expected = new byte[64];
                System.arraycopy(sent.key().getEncoded(), 0, expected, 0, 32);
                System.arraycopy(ecdh, 0, expected, 32, 32);

                MemorySegment serverShare = arena.allocate(HybridMlKem.SERVER_SHARE);
                MemorySegment.copy(sent.encapsulation(), 0, serverShare, ValueLayout.JAVA_BYTE, 0, 1088);
                MemorySegment.copy(u(((XECPublicKey) server.getPublic()).getU()), 0,
                        serverShare, ValueLayout.JAVA_BYTE, 1088, 32);
                MemorySegment out = arena.allocate(HybridMlKem.SECRET);
                client.derive(serverShare, out);
                assertArrayEquals(expected, out.toArray(ValueLayout.JAVA_BYTE), "round " + round);
            }
        }
    }

    @Test
    void refusesAServerShareOfTheWrongLength() {
        try (Arena arena = Arena.ofConfined(); HybridMlKem client = HybridMlKem.generate()) {
            assertThrows(IllegalArgumentException.class, () -> client.derive(
                    arena.allocate(HybridMlKem.SERVER_SHARE - 1), arena.allocate(HybridMlKem.SECRET)));
        }
    }

    @Test
    void refusesALowOrderX25519Point() {
        // u = 0: every scalar gives the all-zero secret, which RFC 8446 forbids.
        try (Arena arena = Arena.ofConfined(); HybridMlKem client = HybridMlKem.generate()) {
            MemorySegment serverShare = arena.allocate(HybridMlKem.SERVER_SHARE);
            assertThrows(IllegalStateException.class,
                    () -> client.derive(serverShare, arena.allocate(HybridMlKem.SECRET)));
        }
    }

    @Test
    void twoKeyPairsDiffer() {
        try (Arena arena = Arena.ofConfined();
                HybridMlKem a = HybridMlKem.generate(); HybridMlKem b = HybridMlKem.generate()) {
            MemorySegment first = arena.allocate(HybridMlKem.CLIENT_SHARE);
            MemorySegment second = arena.allocate(HybridMlKem.CLIENT_SHARE);
            a.publicShare(first);
            b.publicShare(second);
            assertNotEquals(-1, first.mismatch(second));
        }
    }

    private static BigInteger littleEndian(byte[] u) {
        byte[] big = new byte[u.length];
        for (int i = 0; i < u.length; i++) big[i] = u[u.length - 1 - i];
        return new BigInteger(1, big);
    }

    private static byte[] u(BigInteger value) {
        byte[] big = value.toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < 32 && i < big.length; i++) out[i] = big[big.length - 1 - i];
        return out;
    }
}
