package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

/**
 * The IAM token, checked against an independently computed one.
 *
 * <p>The expected value was not produced by this code. It comes from a few
 * lines of Python using {@code hmac} and {@code hashlib} over the same inputs -
 * a second implementation of the same specification, which is the only kind of
 * expectation worth pinning. A test that compares the code against itself
 * proves that it is deterministic and nothing else.
 *
 * <p>An independent computation shares the misreadings of whoever wrote
 * it: until 26.09.2026 both this expectation and the code signed for the
 * service {@code rds}, and every token was refused by a real Aurora cluster.
 * The service is {@code rds-db}; the token from the AWS CLI, made in the same
 * second, now matches this code's byte for byte ({@code proof/TokenCheck.java}).
 *
 * <p>The key in it is the example key pair from Amazon's own signing
 * documentation, which exists precisely so that signatures can be shown in
 * public.
 */
@org.junit.jupiter.api.parallel.Isolated
class RdsIamSecretProviderTest {

    private static final String ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    /** 2026-09-10T12:00:00Z, so that the signature is reproducible. */
    private static final Clock FIXED =
            Clock.fixed(Instant.parse("2026-09-10T12:00:00Z"), ZoneOffset.UTC);

    private static final String EXPECTED =
            "db.example.com:5432/?Action=connect&DBUser=app"
            + "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
            + "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260910%2Feu-central-1%2Frds-db"
            + "%2Faws4_request"
            + "&X-Amz-Date=20260910T120000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host"
            + "&X-Amz-Signature="
            + "d4a70a4eceee2cebc57b35bfce526f7a12cb4c7ae6a6d7bea641e816cf3c3a37";

    @Test
    void theTokenMatchesAnIndependentlySignedOne() {
        assertEquals(EXPECTED, token(new PlainKey(SECRET_KEY)));
    }

    /** A different key gives a different signature and the same rest. */
    @Test
    void anotherKeyChangesOnlyTheSignature() {
        String other = token(new PlainKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEZ"));
        assertEquals(EXPECTED.substring(0, EXPECTED.indexOf("&X-Amz-Signature=")),
                other.substring(0, other.indexOf("&X-Amz-Signature=")));
        assertFalse(EXPECTED.equals(other), "the signature did not change with the key");
    }

    /** Without a key there is nothing to sign, and the message says so. */
    @Test
    void aSourceWithoutAKeyIsRefusedWithTheReason() {
        SecretUnavailableException thrown = assertThrows(SecretUnavailableException.class,
                () -> token(new PlainKey("")));
        assertTrue(thrown.getMessage().contains("cannot be signed"), thrown.getMessage());
    }

    /**
     * The point of the whole class: the memory the AWS key was read into is
     * gone when signing is over.
     *
     * <p>The check is that touching it fails - the arena is closed, so the
     * memory is not merely overwritten but released. That is stronger than a
     * wipe, and it is why the test cannot simply read zeroes back: there is
     * nothing left to read. The explicit {@code fill((byte) 0)} in the provider
     * stays anyway, for the day somebody hands in an arena that outlives the
     * call.
     */
    @Test
    void theMemoryOfTheKeyIsGoneAfterSigning() {
        WatchedKey key = new WatchedKey(SECRET_KEY);
        token(key);
        IllegalStateException thrown = assertThrows(IllegalStateException.class, key::isWiped);
        assertTrue(thrown.getMessage().contains("closed"), thrown.getMessage());
    }

    /**
     * Temporary credentials: the session token is URL-encoded into the query,
     * placed between {@code X-Amz-Expires} and {@code X-Amz-SignedHeaders},
     * and covered by the signature.
     */
    @Test
    void aSessionTokenIsSignedAndSentAndRaisesTheMaxLength() {
        String rawSession = "FwoGZXIvYXdzE/session+token==";
        String encodedSession = "FwoGZXIvYXdzE%2Fsession%2Btoken%3D%3D";
        RdsIamSecretProvider provider = new RdsIamSecretProvider(
                new PlainKey(SECRET_KEY), new PlainKey(rawSession),
                ACCESS_KEY, "eu-central-1", "db.example.com", 5432, "app", FIXED);
        assertEquals(8192, provider.maxSecretLength());

        String signed = read(provider);
        assertTrue(signed.contains("&X-Amz-Expires=900&X-Amz-Security-Token=" + encodedSession
                + "&X-Amz-SignedHeaders=host&X-Amz-Signature="), signed);

        String canonicalQuery = "Action=connect&DBUser=app"
                + "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
                + "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260910%2Feu-central-1%2Frds-db"
                + "%2Faws4_request"
                + "&X-Amz-Date=20260910T120000Z&X-Amz-Expires=900"
                + "&X-Amz-Security-Token=" + encodedSession
                + "&X-Amz-SignedHeaders=host";
        String canonical = "GET\n/\n" + canonicalQuery + "\nhost:db.example.com:5432\n\n"
                + "host\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String toSign = "AWS4-HMAC-SHA256\n20260910T120000Z\n"
                + "20260910/eu-central-1/rds-db/aws4_request\n"
                + space.seclume.internal.AwsSigV4.sha256Hex(canonical);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sig = space.seclume.internal.AwsSigV4.sign(
                    arena, new PlainKey(SECRET_KEY)::writeSecret,
                    toSign, "20260910", "eu-central-1", "rds-db");
            String expected = "db.example.com:5432/?" + canonicalQuery
                    + "&X-Amz-Signature=" + space.seclume.internal.AwsSigV4.hex(sig);
            assertEquals(expected, signed);
        }
    }

    @Test
    void closingTheProviderClosesBothKeyAndSessionToken() {
        PlainKey key = new PlainKey(SECRET_KEY);
        PlainKey session = new PlainKey("session-token");
        RdsIamSecretProvider provider = new RdsIamSecretProvider(
                key, session, ACCESS_KEY, "eu-central-1", "db.example.com", 5432, "app", FIXED);
        provider.close();
        assertTrue(key.closed, "the secret key provider was not closed");
        assertTrue(session.closed, "the session token provider was not closed");
    }

    @Test
    void secretProvidersWiresSessionTokenAndFallsBackToUser(
            @org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        java.nio.file.Path keyFile = dir.resolve("key");
        java.nio.file.Path tokenFile = dir.resolve("token");
        java.nio.file.Files.writeString(keyFile, SECRET_KEY);
        java.nio.file.Files.writeString(tokenFile, "FwoGZXIvYXdzESessionToken");

        try (SecretProvider provider = SecretProviders.of(java.util.Map.of(
                "provider", "rds-iam",
                "access-key-id", ACCESS_KEY,
                "region", "eu-central-1",
                "host", "db.example.com",
                "port", "5432",
                "user", "from-url-user",
                "key-provider", "file",
                "key-path", keyFile.toString(),
                "session-token-provider", "file",
                "session-token-path", tokenFile.toString()))) {
            assertEquals(8192, provider.maxSecretLength());
            String signed = read(provider);
            assertTrue(signed.startsWith("db.example.com:5432/?Action=connect&DBUser=from-url-user"),
                    signed);
            assertTrue(signed.contains("&X-Amz-Security-Token=FwoGZXIvYXdzESessionToken&"),
                    signed);
        }
    }

    private static String token(SecretProvider key) {
        return read(new RdsIamSecretProvider(
                key, ACCESS_KEY, "eu-central-1", "db.example.com", 5432, "app", FIXED));
    }

    private static String read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            StringBuilder text = new StringBuilder(length);
            for (int i = 0; i < length; i++) {
                text.append((char) (target.get(ValueLayout.JAVA_BYTE, i) & 0xff));
            }
            return text.toString();
        }
    }

    /** A key from a String - for a test, and only for a test. */
    private static class PlainKey implements SecretProvider {

        private final String key;
        boolean closed;

        PlainKey(String key) {
            this.key = key;
        }

        @Override
        public int writeSecret(MemorySegment target) {
            for (int i = 0; i < key.length(); i++) {
                target.set(ValueLayout.JAVA_BYTE, i, (byte) key.charAt(i));
            }
            return key.length();
        }

        @Override
        public int maxSecretLength() {
            return 256;
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    /** The same, but it remembers the buffer to see whether it was wiped. */
    private static final class WatchedKey extends PlainKey {

        private MemorySegment written;
        private int length;

        WatchedKey(String key) {
            super(key);
        }

        @Override
        public int writeSecret(MemorySegment target) {
            length = super.writeSecret(target);
            written = target;
            return length;
        }

        boolean isWiped() {
            for (int i = 0; i < length; i++) {
                if (written.get(ValueLayout.JAVA_BYTE, i) != 0) {
                    return false;
                }
            }
            return true;
        }
    }
}
