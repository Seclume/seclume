package space.seclume.inventory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.InputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.crypto.PrivateSigningKey;
import space.seclume.field.FieldKeys;
import space.seclume.inventory.CryptoInventory.Asset;
import space.seclume.inventory.CryptoInventory.Kind;
import space.seclume.secret.ExpiringCredentials;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * What the inventory records, from where seclume does the work: a secret
 * read through {@link SecretScope#fromProvider}, a field encryption ring, a
 * private key, a TLS session and its certificate - and that no value of a
 * secret is ever among it.
 *
 * <p>Isolated: the inventory is the process's.
 */
@Isolated
class CryptoInventoryTest {

    /** A secret that must never appear in an inventory or a CBOM. */
    static final String CANARY = "zl-inventory-canary-5d0c8e17a4";

    @BeforeEach
    void empty() {
        CryptoInventory.clear();
    }

    static class CanaryProvider implements SecretProvider, ExpiringCredentials {
        private final Instant until;

        CanaryProvider(Instant until) {
            this.until = until;
        }

        @Override
        public int writeSecret(MemorySegment target) {
            byte[] bytes = CANARY.getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        }

        @Override
        public int maxSecretLength() {
            return 64;
        }

        @Override
        public Instant credentialsValidUntil() {
            return until;
        }

        @Override
        public String toString() {
            return "CanaryProvider[/run/secrets/db]";
        }
    }

    static X509Certificate certificate(String resource) throws Exception {
        try (InputStream in = CryptoInventoryTest.class.getResourceAsStream(resource)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
        }
    }

    private static List<Asset> of(Kind kind) {
        return CryptoInventory.snapshot().stream().filter(a -> a.kind() == kind).toList();
    }

    @Test
    void aKeySizeThatIsNotANumberIsZeroNotAnException() {
        assertEquals(2048, CryptoInventory.number("2048"));
        assertEquals(0, CryptoInventory.number("0"));
        assertEquals(0, CryptoInventory.number(null));
        assertEquals(0, CryptoInventory.number(""));
        assertEquals(0, CryptoInventory.number("25519x"));
        assertEquals(0, CryptoInventory.number("-1"));
        assertEquals(0, CryptoInventory.number("+256"));
        assertEquals(0, CryptoInventory.number("9999999999"));
        assertEquals(0, CryptoInventory.number("\u0663\u0662"));
    }

    @Test
    void aSecretReadIsRecordedAsWhereItCameFromAndWhenNeverAsWhatItIs() {
        Instant until = Instant.parse("2031-01-01T00:00:00Z");
        CanaryProvider provider = new CanaryProvider(until);
        for (int i = 0; i < 3; i++) {
            try (SecretScope scope = SecretScope.fromProvider(provider)) {
                assertEquals(CANARY.length(), scope.length());
            }
        }
        List<Asset> secrets = of(Kind.SECRET);
        assertEquals(1, secrets.size());
        Asset secret = secrets.get(0);
        assertEquals(3, secret.uses());
        assertEquals("canary-provider", secret.facts().get("provider"));
        assertEquals("CanaryProvider[/run/secrets/db]", secret.source());
        assertEquals(until, secret.expires(), "the expiry, asked when the inventory is");
        assertNull(secret.algorithm());
        assertFalse(secret.toString().contains(CANARY));
        assertFalse(CycloneDxCbom.write("t").contains(CANARY));
        assertFalse(CycloneDxCbom.write("t").contains(Integer.toString(CANARY.length()) + " bytes"));
    }

    @Test
    void aProviderThatFailsIsNotRecordedAndAnExpiryThatThrowsIsNone() {
        SecretProvider broken = new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                throw new IllegalStateException("unreachable source");
            }

            @Override
            public int maxSecretLength() {
                return 8;
            }
        };
        try {
            SecretScope.fromProvider(broken).close();
        } catch (IllegalStateException expected) {
            // said
        }
        assertTrue(of(Kind.SECRET).isEmpty());

        class Throwing extends CanaryProvider {
            Throwing() {
                super(null);
            }

            @Override
            public Instant credentialsValidUntil() {
                throw new IllegalStateException("its own bug");
            }
        }
        SecretScope.fromProvider(new Throwing()).close();
        assertNull(of(Kind.SECRET).get(0).expires());
        assertEquals("callback", CryptoInventory.kindOf(new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                return 0;
            }

            @Override
            public int maxSecretLength() {
                return 1;
            }
        }), "an anonymous provider");
    }

    @Test
    void aRingIsItsKeysWhileItIsOpen() {
        FieldKeys keys = FieldKeys.builder().key(1, new CanaryProvider(null) {
            @Override
            public int writeSecret(MemorySegment target) {
                target.asSlice(0, 32).fill((byte) 7);
                return 32;
            }
        }).key(4, new CanaryProvider(null) {
            @Override
            public int writeSecret(MemorySegment target) {
                target.asSlice(0, 32).fill((byte) 9);
                return 32;
            }
        }).primary(1).build();
        List<Asset> dataKeys = of(Kind.DATA_KEY);
        assertEquals(2, dataKeys.size());
        assertEquals("AES-256-GCM-SIV", dataKeys.get(0).algorithm());
        assertEquals(256, dataKeys.get(0).bits());
        assertEquals("true", dataKeys.get(0).facts().get("primary"));
        assertEquals("4", dataKeys.get(1).facts().get("keyNumber"));
        assertEquals("false", dataKeys.get(1).facts().get("primary"));
        keys.close();
        assertTrue(of(Kind.DATA_KEY).isEmpty(), "a closed ring is no key");
    }

    @Test
    void aPrivateKeyIsItsAlgorithmAndSize() {
        assumeTrue(PrivateSigningKey.available(), "OpenSSL 3 or CNG");
        try (PrivateSigningKey key = PrivateSigningKey.generateP256()) {
            List<Asset> keys = of(Kind.PRIVATE_KEY);
            assertEquals(1, keys.size());
            assertEquals("EC P-256", keys.get(0).algorithm());
            assertEquals(256, keys.get(0).bits());
            assertTrue(List.of("OpenSSL", "CNG").contains(keys.get(0).source()));
            assertNotNull(key);
        }
    }

    @Test
    void publicKeysAreNamed() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(3072);
        assertEquals("RSA", CryptoInventory.algorithmOf(rsa.generateKeyPair().getPublic()
                .getEncoded())[0]);
        assertEquals("3072", CryptoInventory.algorithmOf(rsa.generateKeyPair().getPublic()
                .getEncoded())[1]);
        assertEquals("Ed25519", CryptoInventory.algorithmOf(KeyPairGenerator
                .getInstance("Ed25519").generateKeyPair().getPublic().getEncoded())[0]);
        assertEquals("EC P-384", CryptoInventory.algorithmOf(
                certificate("vault-p384.pem").getPublicKey().getEncoded())[0]);
        assertEquals("unknown", CryptoInventory.algorithmOf(new byte[] {1, 2, 3})[0]);
    }

    @Test
    void aTlsSessionAndItsCertificate() throws Exception {
        X509Certificate certificate = certificate("db-rsa2048.pem");
        for (int i = 0; i < 2; i++) {
            CryptoInventory.tls("db.inventory.test", "seclume",
                    "TLSv1.3 / TLS_AES_256_GCM_SHA384 with X25519MLKEM768", certificate);
        }
        CryptoInventory.tls("db.inventory.test:5432", "JSSE",
                "TLSv1.2 / TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", null);
        List<Asset> sessions = of(Kind.PROTOCOL);
        assertEquals(2, sessions.size());
        Asset hybrid = sessions.get(0);
        assertEquals("1.3", hybrid.facts().get("version"));
        assertEquals("TLS_AES_256_GCM_SHA384", hybrid.facts().get("cipherSuite"));
        assertEquals("X25519MLKEM768", hybrid.facts().get("keyExchange"));
        assertEquals(2, hybrid.uses());
        assertEquals("1.2", sessions.get(1).facts().get("version"));
        assertNull(sessions.get(1).facts().get("keyExchange"));
        List<Asset> certificates = of(Kind.CERTIFICATE);
        assertEquals(1, certificates.size(), "the same certificate twice is one asset");
        Asset cert = certificates.get(0);
        assertEquals("RSA", cert.algorithm());
        assertEquals(2048, cert.bits());
        assertEquals(certificate.getNotAfter().toInstant(), cert.expires());
        assertEquals("CN=db.inventory.test", cert.facts().get("subject"));
        assertEquals("SHA256withRSA", cert.facts().get("signatureAlgorithm"));
    }

    @Test
    void sessionsAreBoundedOldestOut() {
        for (int i = 0; i < CryptoInventory.MAX_SESSIONS + 40; i++) {
            CryptoInventory.tls("host-" + i, "seclume", "TLSv1.3 / TLS_AES_128_GCM_SHA256 with X25519",
                    null);
        }
        List<Asset> sessions = of(Kind.PROTOCOL);
        assertEquals(CryptoInventory.MAX_SESSIONS, sessions.size());
        assertFalse(sessions.stream().anyMatch(a -> a.facts().get("peer").equals("host-0")),
                "the oldest stayed");
    }

    @Test
    void descriptionsAreTakenApart() {
        CryptoInventory.Tls own = CryptoInventory.Tls.parse(
                "TLSv1.3 / TLS_AES_128_GCM_SHA256 with x25519 (seclume)");
        assertEquals("1.3", own.version());
        assertEquals("TLS_AES_128_GCM_SHA256", own.suite());
        assertEquals("x25519", own.group());
        CryptoInventory.Tls jsse = CryptoInventory.Tls.parse("TLSv1.2 / TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        assertEquals("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", jsse.suite());
        assertNull(jsse.group());
        assertEquals("", CryptoInventory.Tls.parse(null).suite());
    }

    @Test
    void recordingNeverThrows() {
        CryptoInventory.tls(null, null, null, null);
        CryptoInventory.privateKey(new Object(), null, null);
        CryptoInventory.ring(new Object(), null, null, 0, null);
        CryptoInventory.secretRead(null);
        assertTrue(CryptoInventory.snapshot().stream().noneMatch(a -> a.kind() == Kind.DATA_KEY));
    }
}
