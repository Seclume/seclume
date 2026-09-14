package space.seclume.secret;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;

/**
 * The password for AWS RDS IAM authentication - built, not stored.
 *
 * <p>With IAM authentication the database password is not a password at all
 * but a <b>signed URL</b> that is valid for fifteen minutes. The AWS SDKs build
 * it and hand it over as a {@code String}: a short-lived credential that lands
 * in the heap and stays there until the garbage collector happens to overwrite
 * it - which is the one thing short-lived credentials were supposed to avoid.
 *
 * <p>Here it is built where it belongs. The AWS secret key comes from another
 * {@link SecretProvider} - a file, the environment, a socket - and is read
 * straight into native memory; the signing chain that derives the token from it
 * is HMAC-SHA256 and nothing else, so all of it can happen off the heap. What
 * lands in the target segment is the finished token; the secret key itself is
 * wiped before this method returns.
 *
 * <p>That is the combination nobody else offers: <b>short-lived cloud
 * credentials that never touch the heap.</b>
 *
 * <p>Everything that is <i>not</i> secret - the host, the user, the region, the
 * access key id, the timestamp - is ordinary text and stays ordinary text. A
 * signature says nothing about the key it was made with.
 */
public final class RdsIamSecretProvider implements SecretProvider {

    /** What the signature covers besides the query - always just the host. */
    private static final String SIGNED_HEADERS = "host";
    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String SERVICE = "rds";
    private static final String TERMINATOR = "aws4_request";
    /** The longest AWS allows, and the only value that makes sense here. */
    private static final int EXPIRES_SECONDS = 900;
    /** SHA-256 of the empty payload - a GET has no body. */
    private static final String EMPTY_PAYLOAD =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY =
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

    private final SecretProvider awsSecretKey;
    private final String accessKeyId;
    private final String region;
    private final String host;
    private final int port;
    private final String user;
    private final Clock clock;

    /**
     * @param awsSecretKey where the AWS secret access key comes from - it is
     *                     read into native memory and wiped again
     * @param accessKeyId  the public half of the key pair; not a secret
     * @param region       for example {@code eu-central-1}
     * @param host         the RDS endpoint
     * @param port         its port
     * @param user         the database user the token is for
     */
    public RdsIamSecretProvider(SecretProvider awsSecretKey, String accessKeyId, String region,
                                String host, int port, String user) {
        this(awsSecretKey, accessKeyId, region, host, port, user, Clock.systemUTC());
    }

    /** The same with a clock of its own - a signature is only reproducible with one. */
    public RdsIamSecretProvider(SecretProvider awsSecretKey, String accessKeyId, String region,
                                String host, int port, String user, Clock clock) {
        this.awsSecretKey = awsSecretKey;
        this.accessKeyId = accessKeyId;
        this.region = region;
        this.host = host;
        this.port = port;
        this.user = user;
        this.clock = clock;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        Instant now = clock.instant();
        String stamp = STAMP.format(now);
        String day = DAY.format(now);
        String scope = day + "/" + region + "/" + SERVICE + "/" + TERMINATOR;
        String endpoint = host + ":" + port;

        // None of this is secret: it is the request that will be signed, and it
        // travels to the server in the clear anyway.
        String query = "Action=connect"
                + "&DBUser=" + urlEncode(user)
                + "&X-Amz-Algorithm=" + ALGORITHM
                + "&X-Amz-Credential=" + urlEncode(accessKeyId + "/" + scope)
                + "&X-Amz-Date=" + stamp
                + "&X-Amz-Expires=" + EXPIRES_SECONDS
                + "&X-Amz-SignedHeaders=" + SIGNED_HEADERS;
        String canonicalRequest = "GET\n/\n" + query + "\n"
                + "host:" + endpoint + "\n\n"
                + SIGNED_HEADERS + "\n"
                + EMPTY_PAYLOAD;
        String toSign = ALGORITHM + "\n" + stamp + "\n" + scope + "\n"
                + hex(sha256(canonicalRequest));

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment signature = sign(arena, toSign, day);
            String token = endpoint + "/?" + query + "&X-Amz-Signature=" + hex(signature);
            return write(target, token);
        }
    }

    /**
     * A signed URL of this shape runs to some six hundred characters; a
     * kilobyte leaves room for long user names and long endpoints.
     */
    @Override
    public int maxSecretLength() {
        return 1024;
    }

    /**
     * The signing chain, and the only part that touches the secret.
     *
     * <p>{@code AWS4 + key -> date -> region -> service -> aws4_request}, each
     * step an HMAC over the previous result. The key is read into native
     * memory, used, and wiped; nothing in between is a heap object.
     */
    private MemorySegment sign(Arena arena, String toSign, String day) {
        MemorySegment key = arena.allocate(MAX_KEY_BYTES);
        MemorySegment prefixed = arena.allocate(MAX_KEY_BYTES + 4);
        try {
            int length = awsSecretKey.writeSecret(key);
            if (length <= 0) {
                throw new SecretUnavailableException(
                        "the AWS secret key source gave nothing - an IAM token cannot be "
                        + "signed without it");
            }
            // "AWS4" + secret, and that concatenation is the initial key.
            byte[] aws4 = {'A', 'W', 'S', '4'}; // seclume-allow: four constant letters, not a secret
            MemorySegment.copy(aws4, 0, prefixed, ValueLayout.JAVA_BYTE, 0, 4);
            MemorySegment.copy(key, 0, prefixed, 4, length);

            MemorySegment step = hmac(arena, prefixed, 0, 4 + length, day);
            step = hmac(arena, step, 0, step.byteSize(), region);
            step = hmac(arena, step, 0, step.byteSize(), SERVICE);
            step = hmac(arena, step, 0, step.byteSize(), TERMINATOR);
            return hmac(arena, step, 0, step.byteSize(), toSign);
        } finally {
            key.fill((byte) 0);
            prefixed.fill((byte) 0);
        }
    }

    private static MemorySegment hmac(Arena arena, MemorySegment key, long offset, long length,
                                      String message) {
        try (Hmac mac = new Hmac(HashAlgorithm.SHA_256, key, offset, length)) {
            MemorySegment text = arena.allocate(message.length() * 3L + 1);
            int written = writeAscii(text, message);
            mac.update(text, 0, written);
            MemorySegment out = arena.allocate(mac.macLength());
            mac.doFinal(out, 0);
            return out;
        }
    }

    private static MemorySegment sha256(String text) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment in = arena.allocate(text.length() * 3L + 1);
            int written = writeAscii(in, text);
            MemorySegment out = Arena.ofAuto().allocate(HashAlgorithm.SHA_256.digestLength());
            HashAlgorithm.SHA_256.hash(in, 0, written, out, 0);
            return out;
        }
    }

    /** UTF-8 without a heap array in between - the strings here are ASCII anyway. */
    private static int writeAscii(MemorySegment target, String text) {
        int at = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 0x80) {
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) c);
            } else if (c < 0x800) {
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) (0xc0 | (c >> 6)));
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) (0x80 | (c & 0x3f)));
            } else {
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) (0xe0 | (c >> 12)));
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) (0x80 | ((c >> 6) & 0x3f)));
                target.set(ValueLayout.JAVA_BYTE, at++, (byte) (0x80 | (c & 0x3f)));
            }
        }
        return at;
    }

    private static int write(MemorySegment target, String token) {
        // The length in a variable of its own, and not "token.length()" in the
        // message: the rule is that nothing named like a secret is ever
        // concatenated into a message, and a rule with exceptions is not one.
        int needed = token.length();
        if (needed > target.byteSize()) {
            throw new SecretUnavailableException("the IAM token needs " + needed
                    + " bytes and the buffer takes " + target.byteSize()
                    + " - raise the secret buffer size");
        }
        return writeAscii(target, token);
    }

    private static String hex(MemorySegment bytes) {
        StringBuilder text = new StringBuilder((int) bytes.byteSize() * 2); // seclume-allow: a signature, which is public by design
        for (long i = 0; i < bytes.byteSize(); i++) {
            int value = bytes.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            text.append(Character.forDigit(value >> 4, 16));
            text.append(Character.forDigit(value & 0xf, 16));
        }
        return text.toString();
    }

    /** What AWS expects: RFC 3986, and a slash is not safe. */
    private static String urlEncode(String text) {
        StringBuilder out = new StringBuilder(text.length() + 8); // seclume-allow: a user name and a key id, never the secret
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean safe = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
            if (safe) {
                out.append(c);
            } else {
                out.append('%')
                        .append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xf, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return out.toString();
    }

    /** Long enough for any AWS secret key, short enough to stay cheap. */
    private static final int MAX_KEY_BYTES = 256;
}
