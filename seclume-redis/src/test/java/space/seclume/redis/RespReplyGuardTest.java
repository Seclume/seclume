package space.seclume.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretProvider;

/**
 * A server that answers a command it does not know with the command's
 * arguments gives the password back - Redis 5 to Lettuce's
 * {@code HELLO 3 AUTH user password}. Found in the review of 11.11.2026: the
 * client made a {@code String} of that answer. What the guard lets through
 * to the client is checked here, byte for byte.
 */
class RespReplyGuardTest {

    private static final String PASSWORD = "s3cret-of-the-orders-service";

    @TempDir
    Path directory;
    private SecretProvider secret;

    @BeforeEach
    void secret() throws Exception {
        Path file = directory.resolve("redis");
        Files.writeString(file, PASSWORD);
        secret = new FileSecretProvider(file, 256);
    }

    /** An array as {@link RespReplyGuard.Bytes}. */
    private static RespReplyGuard.Bytes bytes(byte[] array, int from, int to) {
        return new RespReplyGuard.Bytes() {
            @Override
            public int length() {
                return to - from;
            }

            @Override
            public byte get(int index) {
                return array[from + index];
            }

            @Override
            public void set(int index, byte value) {
                array[from + index] = value;
            }
        };
    }

    /** What reaches the client of {@code wire}, read in pieces of the sizes {@code cuts} gives. */
    private static String through(RespReplyGuard guard, String wire, Random cuts) {
        byte[] all = wire.getBytes(StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream client = new ByteArrayOutputStream();
        byte[] held = new byte[0];
        int at = 0;
        while (at < all.length) {
            int n = cuts == null ? all.length - at : Math.min(all.length - at, 1 + cuts.nextInt(40));
            byte[] buffer = new byte[held.length + n];
            System.arraycopy(held, 0, buffer, 0, held.length);
            System.arraycopy(all, at, buffer, held.length, n);
            at += n;
            int passed = guard.scan(bytes(buffer, 0, buffer.length));
            client.write(buffer, 0, passed);
            held = java.util.Arrays.copyOfRange(buffer, passed, buffer.length);
        }
        client.writeBytes(held);
        return client.toString(StandardCharsets.ISO_8859_1);
    }

    private static String stars(int n) {
        return "*".repeat(n);
    }

    @Test
    void redisFivesAnswerToHelloComesWithoutThePassword() {
        RespReplyGuard guard = new RespReplyGuard(secret);
        guard.arm();
        String answer = "-ERR unknown command `HELLO`, with args beginning with: `3`, `AUTH`, "
                + "`orders`, `" + PASSWORD + "`, \r\n+OK\r\n";
        assertEquals(answer.replace(PASSWORD, stars(PASSWORD.length())), through(guard, answer, null));
    }

    @Test
    void theBeginningOfThePasswordWhereTheServerCutItsLine() {
        for (int kept = 1; kept < PASSWORD.length(); kept++) {
            RespReplyGuard guard = new RespReplyGuard(secret);
            guard.arm();
            String answer = "-ERR unknown command 'HELLO', with args beginning with: '3' 'AUTH' "
                    + "'orders' '" + PASSWORD.substring(0, kept) + "' \r\n";
            String seen = through(guard, answer, null);
            assertEquals(answer.replace("'" + PASSWORD.substring(0, kept) + "'",
                    "'" + stars(kept) + "'"), seen, kept + " bytes of it");
        }
    }

    @Test
    void howeverTheAnswerIsCutIntoReads() {
        String answers = "-ERR unknown command `HELLO`, with args beginning with: `3`, `AUTH`, "
                + "`orders`, `" + PASSWORD + "`, \r\n"
                + "!" + (19 + PASSWORD.length()) + "\r\nSYNTAX not a user: " + PASSWORD + "\r\n"
                + "*2\r\n-WRONGPASS " + PASSWORD + "\r\n$3\r\nabc\r\n"
                + "+OK\r\n";
        String expected = answers.replace(PASSWORD, stars(PASSWORD.length()));
        Random cuts = new Random(20261111);
        for (int round = 0; round < 500; round++) {
            RespReplyGuard guard = new RespReplyGuard(secret);
            guard.arm();
            assertEquals(expected, through(guard, answers, cuts), "round " + round);
        }
    }

    @Test
    void aValueIsNeverTouchedEvenIfItIsThePassword() {
        RespReplyGuard guard = new RespReplyGuard(secret);
        guard.arm();
        // A bulk string, an array of them, a map, a status line, a push, a
        // verbatim string - with the password and with what looks like an
        // error in them. Only errors are an error's text.
        String values = "$" + PASSWORD.length() + "\r\n" + PASSWORD + "\r\n"
                + "*2\r\n$" + (PASSWORD.length() + 8) + "\r\n\r\n-ERR " + PASSWORD + "\r\n\r\n$-1\r\n"
                + "%1\r\n+key\r\n$" + PASSWORD.length() + "\r\n" + PASSWORD + "\r\n"
                + "+" + PASSWORD + "\r\n"
                + ">2\r\n$7\r\nmessage\r\n$" + PASSWORD.length() + "\r\n" + PASSWORD + "\r\n"
                + "=" + (4 + PASSWORD.length()) + "\r\ntxt:" + PASSWORD + "\r\n"
                + "|1\r\n+ttl\r\n:3600\r\n$" + PASSWORD.length() + "\r\n" + PASSWORD + "\r\n"
                + ":42\r\n_\r\n#t\r\n,1.5\r\n(12345678901234567890\r\n~1\r\n+x\r\n*0\r\n*-1\r\n$0\r\n\r\n";
        assertEquals(values, through(guard, values, null));
        assertEquals(values, through(new RespReplyGuardArmed(secret).guard, values, new Random(7)));
    }

    /** A guard, armed. */
    private static final class RespReplyGuardArmed {
        final RespReplyGuard guard;

        RespReplyGuardArmed(SecretProvider secret) {
            guard = new RespReplyGuard(secret);
            guard.arm();
        }
    }

    @Test
    void onlyTheAnswersThatFollowAPassword() {
        RespReplyGuard guard = new RespReplyGuard(secret);
        String error = "-ERR what was sent: " + PASSWORD + "\r\n";
        assertEquals(error, through(guard, error, null), "no password went out: nothing is looked at");
        assertFalse(guard.armed());

        guard.arm();
        StringBuilder answers = new StringBuilder();
        for (int i = 0; i < RespReplyGuard.REPLIES; i++) {
            answers.append("*2\r\n:").append(i).append("\r\n+OK\r\n");     // one answer each
        }
        assertEquals(answers.toString(), through(guard, answers.toString(), null));
        assertFalse(guard.armed(), RespReplyGuard.REPLIES + " whole answers later it is over");
        assertEquals(error, through(guard, error, null));

        guard.arm();
        assertTrue(guard.armed());
        assertEquals(error.replace(PASSWORD, stars(PASSWORD.length())), through(guard, error, null));
    }

    @Test
    void anErrorTooLongToHoldAndAnAnswerThatIsNoRespGoThroughAsTheyAre() {
        RespReplyGuard guard = new RespReplyGuard(secret);
        guard.arm();
        String endless = "-ERR " + "x".repeat(RespReplyGuard.MAX_HELD + 10);
        assertEquals(endless, through(guard, endless, null), "held no longer than the limit");

        guard = new RespReplyGuard(secret);
        guard.arm();
        String http = "HTTP/1.1 400 Bad Request\r\n\r\n-ERR " + PASSWORD + "\r\n";
        assertEquals(http, through(guard, http, null), "not RESP: nothing is told apart any more");
    }

    @Test
    void aSecretThatCannotBeReadMasksTheWholeText() {
        RespReplyGuard guard = new RespReplyGuard(new FileSecretProvider(directory.resolve("gone"), 64));
        guard.arm();
        assertEquals("-ERR *******************\r\n",
                through(guard, "-ERR unknown command 'X'\r\n", null));
    }

    @Test
    void theShortestBeginningsAreLeftWhereTheyAreNotAtTheEnd() {
        RespReplyGuard guard = new RespReplyGuard(secret);
        guard.arm();
        // "s3c" is three bytes of the password in the middle of a text: a word.
        String error = "-ERR s3c is no command, s3cr is\r\n";
        assertEquals("-ERR s3c is no command, **** is\r\n", through(guard, error, null));
        // ... and at the end only as a quoted argument, where a server cuts.
        guard.arm();
        assertEquals("-ERR args: 'a' '***' \r\n", through(guard, "-ERR args: 'a' 's3c' \r\n", null));
        assertEquals("-ERR it was thus\r\n", through(guard, "-ERR it was thus\r\n", null));
    }
}
