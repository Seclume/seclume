package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * STS's XML answer and the container endpoint's JSON one, read by
 * {@link AwsInstanceRole}'s parsers directly: an element at the first byte of
 * the answer and one ending at its last, a key id of exactly the room it has
 * and one byte more, a secret of exactly its room, an element that is missing
 * or only half there, and the scopes wiped when parsing fails. Written against
 * the mutants PIT left alive in this package.
 *
 * <p>Isolated: the count of open secret scopes is the JVM's.
 */
@Isolated
class AwsCredentialsParserTest {

    private static final String EXPIRES = "2026-11-06T12:00:00Z";

    private static AwsInstanceRole.Fetched xml(String text) {
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
            MemorySegment segment = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return AwsInstanceRole.parseXml(segment, bytes.length);
        }
    }

    private static String text(SecretScope scope) {
        return new String(scope.segment().asSlice(0, scope.length()).toArray(ValueLayout.JAVA_BYTE),
                StandardCharsets.US_ASCII);
    }

    private static String answer(String keyId, String secret, String token) {
        return "<AccessKeyId>" + keyId + "</AccessKeyId><Expiration>" + EXPIRES + "</Expiration>"
                + "<SecretAccessKey>" + secret + "</SecretAccessKey><SessionToken>" + token + "</SessionToken>";
    }

    private static void close(AwsInstanceRole.Fetched fetched) {
        fetched.secretKey().close();
        fetched.sessionToken().close();
    }

    @Test
    void elementsAtTheFirstAndTheLastByteOfTheAnswerAreFound() {
        AwsInstanceRole.Fetched fetched = xml(answer("ASIAEDGE", "s3cr3t", "tok"));
        try {
            assertEquals("ASIAEDGE", fetched.accessKeyId(), "the first element starts at byte 0");
            assertEquals(Instant.parse(EXPIRES), fetched.expires());
            assertEquals("s3cr3t", text(fetched.secretKey()));
            assertEquals("tok", text(fetched.sessionToken()), "the last element ends at the last byte");
        } finally {
            close(fetched);
        }
        AwsInstanceRole.Fetched spaced = xml("<x>" + answer(" ASIA ", "k", "") + "</x>");
        try {
            assertEquals("ASIA", spaced.accessKeyId(), "the key id is trimmed");
            assertEquals(0, spaced.sessionToken().length(), "an empty element is empty, not missing");
        } finally {
            close(spaced);
        }
    }

    @Test
    void theKeyIdHas256BytesOfRoomAndTheSecretKey256() {
        AwsInstanceRole.Fetched fetched = xml(answer("A".repeat(256), "k".repeat(256), "t".repeat(8 * 1024)));
        try {
            assertEquals(256, fetched.accessKeyId().length());
            assertEquals(256, fetched.secretKey().length());
            assertEquals(8 * 1024, fetched.sessionToken().length());
        } finally {
            close(fetched);
        }
        assertEquals("AccessKeyId is longer than expected", assertThrows(SecretUnavailableException.class,
                () -> xml(answer("A".repeat(257), "k", "t"))).getMessage());
        assertEquals("SecretAccessKey is longer than expected", assertThrows(SecretUnavailableException.class,
                () -> xml(answer("A", "k".repeat(257), "t"))).getMessage());
        assertEquals("SessionToken is longer than expected", assertThrows(SecretUnavailableException.class,
                () -> xml(answer("A", "k", "t".repeat(8 * 1024 + 1)))).getMessage());
    }

    @Test
    void aMissingOrHalfElementIsNamedAndTheScopesAreWiped() {
        long before = SecretScope.open();
        String full = answer("A", "k", "t");
        for (String[] broken : new String[][] {
                {full.replace("<SessionToken>t</SessionToken>", ""), "SessionToken"},
                {full.replace("</SessionToken>", ""), "SessionToken"},
                {full.replace("<SecretAccessKey>", ""), "SecretAccessKey"},
                {full.replace("</AccessKeyId>", ""), "AccessKeyId"},
                {"</SessionToken>" + full.replace("<SessionToken>t</SessionToken>", "<SessionToken>t"),
                        "SessionToken"},
                {full.substring(0, full.length() - 1), "SessionToken"}}) {
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class, () -> xml(broken[0]),
                    broken[0]);
            assertEquals("STS's answer has no " + broken[1], e.getMessage(), broken[0]);
        }
        assertEquals(before, SecretScope.open(), "nothing left open by a failed parse");
    }

    @Test
    void theContainerAnswerIsJson() {
        String json = "{\"AccessKeyId\":\"ASIAJSON\",\"SecretAccessKey\":\"sk\",\"Token\":\"st\",\"Expiration\":\""
                + EXPIRES + "\"}";
        try (Arena arena = Arena.ofConfined()) {
            byte[] bytes = json.getBytes(StandardCharsets.US_ASCII);
            MemorySegment segment = arena.allocate(bytes.length);
            MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
            AwsInstanceRole.Fetched fetched = AwsInstanceRole.parseJson(segment, bytes.length);
            try {
                assertEquals("ASIAJSON", fetched.accessKeyId());
                assertEquals(Instant.parse(EXPIRES), fetched.expires());
                assertEquals("sk", text(fetched.secretKey()));
                assertEquals("st", text(fetched.sessionToken()));
            } finally {
                close(fetched);
            }
        }
    }
}
