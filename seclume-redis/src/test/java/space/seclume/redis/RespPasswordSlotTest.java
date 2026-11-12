package space.seclume.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;

/**
 * The password goes into the password argument of AUTH or HELLO ... AUTH and
 * nowhere else. The placeholder is on the client's heap - its "password" - and
 * a heap dump gives it away; anyone who has it and can make the application
 * store a string of their choosing (a cached value, a session field) would
 * otherwise have had the password written into Redis in its place, for them
 * to read back. So these commands are followed from the connection's first
 * byte, over writes split anywhere, and only the password slot is replaced.
 */
class RespPasswordSlotTest {

    private static final String PASSWORD = "the-real-password";

    @TempDir
    Path dir;

    private String placeholder;
    private RespPasswordRewriter rewriter;

    @BeforeEach
    void aClient() throws Exception {
        placeholder = RespPasswordRewriter.newPlaceholder();
        aConnection();
    }

    /** A new connection of the same client: same placeholder, the stream from its start. */
    private void aConnection() throws Exception {
        Path file = Files.createTempFile(dir, "redis", ".pw");
        Files.writeString(file, PASSWORD);
        rewriter = new RespPasswordRewriter(placeholder,
                SecretProviders.of(Map.of("provider", "file", "path", file.toString())));
    }

    private static String bulk(String value) {
        return "$" + value.length() + "\r\n" + value + "\r\n";
    }

    private static String command(String... arguments) {
        StringBuilder out = new StringBuilder("*" + arguments.length + "\r\n");
        for (String argument : arguments) {
            out.append(bulk(argument));
        }
        return out.toString();
    }

    // ---- where the password belongs -----------------------------------------

    @Test
    void authWithThePasswordOnly() throws Exception {
        assertEquals(command("AUTH", PASSWORD), sent(command("AUTH", placeholder)));
    }

    @Test
    void authWithAUserAndInLowerCase() throws Exception {
        assertEquals(command("auth", "orders", PASSWORD),
                sent(command("auth", "orders", placeholder)));
    }

    @Test
    void helloWithAuthAndASetnameAfterIt() throws Exception {
        assertEquals(command("HELLO", "3", "AUTH", "orders", PASSWORD, "SETNAME", "app"),
                sent(command("HELLO", "3", "AUTH", "orders", placeholder, "SETNAME", "app")));
        assertEquals(command("hello", "3", "auth", "default", PASSWORD),
                sent(command("hello", "3", "auth", "default", placeholder)));
    }

    @Test
    void anAuthLaterOnTheConnectionAfterWritesWithoutThePlaceholder() throws Exception {
        // The handler hands writes without the placeholder to observe(), the
        // engine hands everything to next(); both have to keep the place.
        String before = command("SET", "k", "v") + command("GET", "AUTH") + command("PING");
        rewriter.observe(ByteBuffer.wrap(before.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(command("AUTH", "orders", PASSWORD),
                sent(command("AUTH", "orders", placeholder)));
    }

    @Test
    void theCommandsSplitAtEveryByteBeforeThePasswordStillFindIt() throws Exception {
        String stream = command("CLIENT", "SETNAME", "app") + command("AUTH", "orders",
                placeholder) + command("SELECT", "2");
        String expected = command("CLIENT", "SETNAME", "app") + command("AUTH", "orders",
                PASSWORD) + command("SELECT", "2");
        int header = stream.indexOf("$" + placeholder.length() + "\r\n" + placeholder);
        for (int cut = 1; cut <= header; cut++) {
            aConnection();
            assertEquals(expected, sent(stream.substring(0, cut), stream.substring(cut)),
                    "split at " + cut);
        }
    }

    @Test
    void anotherAuthAfterwardsGetsThePasswordAgain() throws Exception {
        assertEquals(command("AUTH", PASSWORD) + command("GET", "k") + command("AUTH", PASSWORD),
                sent(command("AUTH", placeholder) + command("GET", "k")
                        + command("AUTH", placeholder)));
    }

    // ---- where it does not --------------------------------------------------

    @Test
    void thePlaceholderStoredAsAValueStaysThePlaceholder() throws Exception {
        for (String stream : List.of(
                command("SET", "session:42", placeholder),
                command("SET", "AUTH", placeholder),
                command("HSET", "user:7", "AUTH", placeholder),
                command("RPUSH", "l", "AUTH", "orders", placeholder),
                command("HELLO", "3", "SETNAME", "x", placeholder),
                command("HELLO", "3", "AUTH", placeholder, "pw"),
                command("CONFIG", "SET", "masterauth", placeholder))) {
            assertEquals(stream, sent(stream), stream);
            aConnection();
        }
    }

    @Test
    void theUserSlotIsNotThePasswordSlot() throws Exception {
        String stream = command("AUTH", placeholder, "pw");
        assertEquals(stream, sent(stream));
    }

    @Test
    void anAuthCommandInsideAValueIsAValue() throws Exception {
        // The whole AUTH command, framing and all, as the value of a SET.
        String stream = command("SET", "k", command("AUTH", placeholder));
        assertEquals(stream, sent(stream));
        // And as the value of one AUTH's own user name.
        aConnection();
        String nested = command("AUTH", command("AUTH", placeholder), "pw");
        assertEquals(nested, sent(nested));
    }

    @Test
    void anInlineCommandEndsTheReplacingForTheConnection() throws Exception {
        String stream = "PING\r\n" + command("AUTH", placeholder);
        assertEquals(stream, sent(stream));
    }

    @Test
    void aMalformedLengthEndsTheReplacingForTheConnection() throws Exception {
        for (String broken : List.of("*x\r\n", "*1\r\n$\r\n", "*1\r\n$12345678901\r\n",
                "*1\r\n:1\r\n", "*1\r\n$1\r\nab\r\n")) {
            String stream = broken + command("AUTH", placeholder);
            assertEquals(stream, sent(stream), broken);
            aConnection();
        }
    }

    @Test
    void aPlaceholderSplitAcrossWritesIsNotGuessedAt() throws Exception {
        // The login fails then - the placeholder reaches the server as it is -
        // but no byte of the password goes anywhere it should not.
        String stream = command("AUTH", placeholder);
        int middle = stream.indexOf(placeholder) + 5;
        assertEquals(stream, sent(stream.substring(0, middle), stream.substring(middle)));
    }

    // ---- values passed over in runs -------------------------------------------

    /**
     * A value is not read byte by byte: what is left of it in a write is
     * passed over at once. The command after it is found all the same -
     * wherever the writes fall, and whatever the value holds.
     */
    @Test
    void anAuthAfterLongValuesIsFoundWhereverTheWritesFall() throws Exception {
        String looksLikeMore = "\r\n*2\r\n$4\r\nAUTH\r\n$" + placeholder.length() + "\r\n"
                + placeholder + "\r\n";
        String stream = command("SET", "k".repeat(300), "v".repeat(40_000))
                + command("MSET", "a", looksLikeMore, "b", "")
                + command("AUTH", "orders", placeholder)
                + command("SET", "after", placeholder);
        String expected = stream.replace(command("AUTH", "orders", placeholder),
                command("AUTH", "orders", PASSWORD));
        int header = stream.indexOf(command("AUTH", "orders", placeholder))
                + command("AUTH", "orders").length();
        for (int size : new int[] {1, 2, 3, 5, 7, 64, 1000, 16_384, 16_385, 100_000}) {
            aConnection();
            java.util.List<String> writes = new java.util.ArrayList<>();
            int at = 0;
            while (at < header) {
                int end = Math.min(header, at + size);
                writes.add(stream.substring(at, end));
                at = end;
            }
            writes.add(stream.substring(header));      // the password's bulk string, whole
            assertEquals(expected, sent(writes.toArray(String[]::new)), "writes of " + size);
        }
    }

    @Test
    void aNameThatOnlyBeginsLikeAuthIsNotAuth() throws Exception {
        for (String stream : List.of(
                command("AUTHENTICATE", placeholder),
                command("AUTHXX", "orders", placeholder),
                command("AUTH42", placeholder),
                command("HELLOWORLD", "3", "AUTH", "orders", placeholder),
                command("HELLO", "3", "AUTHXX", "orders", placeholder),
                command("HELLO", "3", "AUTHENTICATION", "orders", placeholder))) {
            assertEquals(stream, sent(stream), stream);
            assertEquals(stream, sent(stream), "and once more on the same connection");
            aConnection();
        }
    }

    /**
     * Whatever commands come before, of whatever sizes and in whatever writes:
     * the AUTH after them gets the password, nothing else does - the same
     * whether the bytes before it went through next() or, on the Netty path,
     * through observe().
     */
    @Test
    void randomCommandsInRandomWrites() throws Exception {
        java.util.Random random = new java.util.Random(20261112);
        String alphabet = "abAUTH*$\r\n:-+ 0123456789";
        for (int round = 0; round < 300; round++) {
            StringBuilder before = new StringBuilder();
            int commands = random.nextInt(6);
            for (int c = 0; c < commands; c++) {
                String[] arguments = new String[1 + random.nextInt(5)];
                for (int i = 0; i < arguments.length; i++) {
                    int length = switch (random.nextInt(6)) {
                        case 0 -> 0;
                        case 1 -> 20_000 + random.nextInt(30_000);
                        case 2 -> 4 + random.nextInt(3);
                        default -> random.nextInt(40);
                    };
                    StringBuilder argument = new StringBuilder(length);
                    for (int j = 0; j < length; j++) {
                        argument.append(alphabet.charAt(random.nextInt(alphabet.length())));
                    }
                    arguments[i] = argument.toString();
                }
                // Not a login of its own: these are the commands around the one that is.
                if (arguments[0].equalsIgnoreCase("AUTH")
                        || arguments[0].equalsIgnoreCase("HELLO")) {
                    arguments[0] = "GET";
                }
                before.append(command(arguments));
            }
            String[] login = random.nextBoolean() ? new String[] {"AUTH", placeholder}
                    : random.nextBoolean() ? new String[] {"auth", "orders", placeholder}
                    : new String[] {"HELLO", "3", "AUTH", "orders", placeholder};
            String auth = command(login);
            login[login.length - 1] = PASSWORD;
            String loggedIn = command(login);
            String after = command("SET", "k", placeholder);
            String stream = before + auth + after;
            String expected = before + loggedIn + after;
            int header = before.length() + auth.indexOf("$" + placeholder.length() + "\r\n"
                    + placeholder);

            aConnection();
            java.util.List<String> writes = new java.util.ArrayList<>();
            int at = 0;
            while (at < header) {
                int end = Math.min(header, at + 1 + random.nextInt(
                        random.nextBoolean() ? 9 : 30_000));
                writes.add(stream.substring(at, end));
                at = end;
            }
            writes.add(stream.substring(header));
            String got = sent(writes.toArray(String[]::new));
            assertEquals(expected, got, "round " + round);

            // The same with everything before the login only observed.
            aConnection();
            at = 0;
            while (at < before.length()) {
                int end = Math.min(before.length(), at + 1 + random.nextInt(30_000));
                rewriter.observe(ByteBuffer.wrap(stream.substring(at, end)
                        .getBytes(StandardCharsets.US_ASCII)));
                at = end;
            }
            assertEquals(loggedIn + after, sent(auth + after),
                    "observed, round " + round);
        }
    }

    /** What the rewriter sends for these writes, each one through next(). */
    private String sent(String... writes) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String write : writes) {
            ByteBuffer plain = ByteBuffer.wrap(write.getBytes(StandardCharsets.US_ASCII));
            while (plain.hasRemaining()) {
                SeclumeSslEngine.Outgoing.Step step = rewriter.next(plain);
                if (step.replacement() == null) {
                    byte[] same = new byte[step.unchanged()];
                    plain.get(same);
                    out.write(same);
                } else {
                    try (SecretScope bytes = step.replacement()) {
                        byte[] secret = new byte[bytes.length()];
                        MemorySegment.copy(bytes.segment(), ValueLayout.JAVA_BYTE, 0, secret, 0,
                                secret.length);
                        out.write(secret);
                    }
                    plain.position(plain.position() + step.replaced());
                }
            }
        }
        return out.toString(StandardCharsets.US_ASCII);
    }
}
