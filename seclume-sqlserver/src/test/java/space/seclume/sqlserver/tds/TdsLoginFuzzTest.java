package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.WireBuffer;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.tck.fuzz.ByteCorpus;
import space.seclume.tck.fuzz.HostileTransport;

/**
 * The SQL Server login, interrupted everywhere, and the password afterwards.
 *
 * <p>PostgreSQL and MySQL are fuzzed through {@code open()}, because a script
 * can be the whole server: both of them talk in the clear until the login is
 * done. <b>TDS cannot be reached that way.</b> The password never travels
 * outside TLS - 7.4 runs the handshake inside the pre-login packets, 8.0 wraps
 * the socket before the first TDS byte - so a scripted transport would have to
 * be a TLS server before it could be a SQL Server, and the bytes under test
 * would be the JDK's, not this driver's.
 *
 * <p>So this enters one layer lower, where the credential actually is.
 * {@link TdsChannel#over} builds a channel on any transport, {@link Login7}
 * writes the packet that carries the password, and {@link LoginResponse} reads
 * what comes back. That pair <b>is</b> the login: everything above it is
 * connecting, and everything TLS does is carry bytes this code never sees
 * differently. What is given up is the pre-login negotiation, which holds no
 * secret; what is kept is every path the password takes.
 *
 * <p><b>The assertion that counts is the last one.</b> A refused login is
 * expected and uninteresting. What is checked after every case is that
 * {@link SecretScope#open()} is back where it started - a scope still open is
 * a password still in this process, on a path nobody wrote a test for.
 */
@Timeout(600)
class TdsLoginFuzzTest {

    private static final String PASSWORD = "ein Testpasswort";

    private static final int HEADER = 8;
    private static final int END_OF_MESSAGE = 0x01;

    private static SecretProvider secret() {
        byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(256, target -> {
            for (int i = 0; i < bytes.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
            }
            return bytes.length;
        });
    }

    private static Login7.Settings settings() {
        return new Login7.Settings("scripted", "seclume", "seclume_test", secret(),
                "seclume", "seclume");
    }

    // ---- what a server says after a LOGIN7 --------------------------------

    private static byte[] packet(int status, byte[] payload) {
        int length = HEADER + payload.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Tds.TYPE_TABULAR_RESULT);
        out.write(status);
        out.write((length >> 8) & 0xff);
        out.write(length & 0xff);
        out.write(0x00);
        out.write(0x00);
        out.write(0x01);
        out.write(0x00);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    private static byte[] join(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /** UCS-2, which is what every string in a TDS token is. */
    private static byte[] utf16(String value) {
        return value.getBytes(StandardCharsets.UTF_16LE);
    }

    private static void writeUShort(ByteArrayOutputStream out, int value) {
        out.write(value & 0xff);
        out.write((value >> 8) & 0xff);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write(value & 0xff);
        out.write((value >> 8) & 0xff);
        out.write((value >> 16) & 0xff);
        out.write((value >> 24) & 0xff);
    }

    private static byte[] token(int tag, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeUShort(out, body.length);
        out.writeBytes(body);
        return out.toByteArray();
    }

    /** LOGINACK: the server agrees, and says what it is. */
    private static byte[] loginAck() {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(1);                              // interface
        writeInt(body, 0x74000004);                 // TDS version
        byte[] name = utf16("Microsoft SQL Server");
        body.write(name.length / 2);
        body.writeBytes(name);
        body.write(16);                             // major
        body.write(0);                              // minor
        writeUShort(body, 4003);                    // build
        return token(Tds.TOKEN_LOGIN_ACK, body.toByteArray());
    }

    /** ENVCHANGE: the database, and the packet size. */
    private static byte[] envChange(int kind, String newValue, String oldValue) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(kind);
        byte[] fresh = utf16(newValue);
        body.write(fresh.length / 2);
        body.writeBytes(fresh);
        byte[] stale = utf16(oldValue);
        body.write(stale.length / 2);
        body.writeBytes(stale);
        return token(Tds.TOKEN_ENVCHANGE, body.toByteArray());
    }

    /** The body both ERROR and INFO carry - they differ only in the tag. */
    private static byte[] messageBody(int number, int severity, String message) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeInt(body, number);
        body.write(1);                              // state
        body.write(severity);
        byte[] text = utf16(message);
        writeUShort(body, text.length / 2);
        body.writeBytes(text);
        byte[] server = utf16("seclume-test");
        body.write(server.length / 2);
        body.writeBytes(server);
        body.write(0);                              // procedure name
        writeInt(body, 1);                          // line number
        return body.toByteArray();
    }

    /** ERROR: what a wrong password looks like - number 18456. */
    private static byte[] error(int number, int severity, String message) {
        return token(Tds.TOKEN_ERROR, messageBody(number, severity, message));
    }

    /** INFO: the same shape, and not a failure. */
    private static byte[] info(int number, String message) {
        return token(Tds.TOKEN_INFO, messageBody(number, 0, message));
    }

    private static byte[] done() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Tds.TOKEN_DONE);
        out.writeBytes(new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        return out.toByteArray();
    }

    /** FEATUREEXTACK, which a modern server sends even when nothing was asked. */
    private static byte[] featureExtAck() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Tds.TOKEN_FEATURE_EXT_ACK);
        out.write(0x04);                            // feature id: column encryption
        writeInt(out, 1);
        out.write(0x01);
        out.write(0xff);                            // terminator
        return out.toByteArray();
    }

    private static Map<String, byte[]> seeds() {
        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("logged in", packet(END_OF_MESSAGE, join(
                envChange(1, "seclume", "master"),
                loginAck(), envChange(4, "4096", "4096"), done())));
        seeds.put("logged in, with a feature acknowledgement", packet(END_OF_MESSAGE, join(
                featureExtAck(), loginAck(), done())));
        seeds.put("refused", packet(END_OF_MESSAGE, join(
                error(18456, 14, "Login failed for user 'seclume_test'."), done())));
        seeds.put("an informational message, then refused", packet(END_OF_MESSAGE, join(
                info(5701, "Changed database context."),
                error(18456, 14, "Login failed for user 'seclume_test'."), done())));
        seeds.put("acknowledged over two packets", join(
                packet(0, join(envChange(1, "seclume", "master"), loginAck())),
                packet(END_OF_MESSAGE, join(envChange(4, "8192", "4096"), done()))));
        seeds.put("nothing at all", new byte[0]);
        return seeds;
    }

    /**
     * Every case, and after every one of them the same question.
     *
     * <p>Chunked at one byte: the answer arrives in pieces a reader that keeps
     * no state between reads cannot survive, and the login is the one place
     * where that reader runs before anything else has been proved.
     */
    @Test
    void noLoginLeavesAPasswordBehind() {
        ByteCorpus corpus = ByteCorpus.from(seeds());
        Map<String, byte[]> chosen = corpus.selected();
        Map<String, String> breaches = new TreeMap<>();
        Map<String, Integer> tally = new TreeMap<>();

        long openBefore = SecretScope.open();
        long readBefore = SecretScope.allocations();

        chosen.forEach((name, script) -> {
            long open = SecretScope.open();
            TdsChannel channel = TdsChannel.over(HostileTransport.of(script));
            try {
                Login7.send(channel, settings());
                LoginResponse response = new LoginResponse();
                response.read(channel);
                if (response.failure() != null) {
                    tally.merge("refused", 1, Integer::sum);
                } else if (response.isLoggedIn()) {
                    tally.merge("logged in", 1, Integer::sum);
                } else {
                    tally.merge("no LOGINACK", 1, Integer::sum);
                }
            } catch (SQLException | IOException | WireBuffer.Truncated expected) {
                // Every one of these is a failure the driver above turns into
                // a 08001 - see TdsSession.connectAndLogIn, whose Truncated
                // clause stands before its RuntimeException clause for exactly
                // the cases this corpus produces.
                tally.merge(expected.getClass().getSimpleName(), 1, Integer::sum);
            } catch (Throwable thrown) {
                breaches.put(name, "failed with " + thrown.getClass().getName()
                        + ", which is not a failure a caller can act on: " + thrown.getMessage());
                return;
            } finally {
                channel.close();
            }
            if (SecretScope.open() != open) {
                breaches.put(name, "left " + (SecretScope.open() - open)
                        + " secret scope(s) open - a password still in this process");
            }
        });

        System.err.println("[login fuzz sqlserver] " + chosen.size() + " cases, " + tally
                + ", secrets read " + (SecretScope.allocations() - readBefore));

        assertTrue(SecretScope.allocations() > readBefore,
                "no secret was ever read, so this proves nothing");
        assertTrue(SecretScope.open() == openBefore,
                "scopes were left open across the whole run: "
                + (SecretScope.open() - openBefore));

        if (!breaches.isEmpty()) {
            StringBuilder report = new StringBuilder(breaches.size() + " of " + chosen.size()
                    + " logins broke the contract:\n");
            breaches.entrySet().stream().limit(8).forEach(entry ->
                    report.append("\n== ").append(entry.getKey()).append('\n')
                          .append(entry.getValue()).append('\n'));
            if (breaches.size() > 8) {
                report.append("\n... and ").append(breaches.size() - 8).append(" more");
            }
            throw new AssertionError(report.toString());
        }
    }

    /**
     * The control: the unspoilt seed has to get all the way through.
     *
     * <p>Without it a mistake in the seeds - a token length off by one, a
     * LOGINACK the reader rejects - would make every case above "pass" by
     * failing identically, and the report would look the same.
     */
    @Test
    void theHappyPathReallyLogsIn() throws Exception {
        byte[] script = seeds().get("logged in");
        TdsChannel channel = TdsChannel.over(HostileTransport.of(script));
        try {
            Login7.send(channel, settings());
            LoginResponse response = new LoginResponse();
            response.read(channel);
            assertTrue(response.isLoggedIn(), "the seed does not log in, so the sweep above "
                    + "never reached the code it claims to fuzz");
            assertTrue("seclume".equals(response.database()),
                    "the ENVCHANGE was not read: " + response.database());
        } finally {
            channel.close();
        }
    }
}
