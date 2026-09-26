package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.tck.fuzz.ByteCorpus;
import space.seclume.tck.fuzz.ScriptedTransportProvider;

/**
 * The MySQL login, interrupted everywhere, and the password afterwards.
 *
 * <p>The same question as the PostgreSQL sweep, and worth asking twice
 * because the two handshakes share nothing but {@link SecretScope}.
 * PostgreSQL reads the password once and may use it over several rounds of
 * SASL; <b>MySQL hashes it into the very first packet it sends</b> and finds
 * out afterwards whether the server agreed - and then may be told to start
 * again with a different plugin, which reads it a second time. A missing wipe
 * in one says nothing about the other.
 *
 * <p>Two shapes here that PostgreSQL has not got, and both are in the seeds:
 * the <b>plugin switch</b>, where the server sends a new scramble and expects
 * a new answer; and the {@code caching_sha2_password} full path, where the
 * server asks for the password under a public key it sends on the spot.
 * That second one is the only place in this driver where a password is
 * encrypted rather than hashed, so it is the place where a scope is most
 * likely to be left open.
 */
@Timeout(600)
class MyLoginFuzzTest {

    private static final String PASSWORD = "ein Testpasswort";

    private String previousTransport;

    @BeforeEach
    void useTheScriptedTransport() {
        previousTransport = System.getProperty("seclume.transport");
        System.setProperty("seclume.transport", ScriptedTransportProvider.NAME);
    }

    @AfterEach
    void putItBack() {
        ScriptedTransportProvider.clear();
        if (previousTransport == null) {
            System.clearProperty("seclume.transport");
        } else {
            System.setProperty("seclume.transport", previousTransport);
        }
    }

    private static SecretProvider secret() {
        byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(256, target -> {
            for (int i = 0; i < bytes.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
            }
            return bytes.length;
        });
    }

    private static MySession.Settings settings() throws SQLException {
        return new MySession.Settings("scripted", 3306, "seclume_test", "seclume_test",
                secret(), "seclume", 2_000, false, HostList.of("scripted", 3306),
                ResultLimit.NONE, TlsMode.OFF);
    }

    // ---- what a MySQL server says during a login ---------------------------

    private static byte[] packet(int sequence, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(payload.length & 0xff);
        out.write((payload.length >> 8) & 0xff);
        out.write((payload.length >> 16) & 0xff);
        out.write(sequence & 0xff);
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

    /** The greeting: protocol 10, a version, a connection id, two scramble halves. */
    private static byte[] greeting(String plugin) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(10);                                   // protocol version
        body.writeBytes("8.4.11".getBytes(StandardCharsets.UTF_8));
        body.write(0);
        body.writeBytes(new byte[] {7, 0, 0, 0});         // connection id
        body.writeBytes("ABCDEFGH".getBytes(StandardCharsets.UTF_8));
        body.write(0);                                    // end of the first half
        int capabilities = 0x0000_0200 | 0x0000_8000 | 0x0008_0000 | 0x0100_0000;
        body.write(capabilities & 0xff);
        body.write((capabilities >> 8) & 0xff);
        body.write(45);                                   // character set
        body.write(0x02);
        body.write(0x00);                                 // status flags
        body.write((capabilities >> 16) & 0xff);
        body.write((capabilities >> 24) & 0xff);
        body.write(21);                                   // scramble length
        body.writeBytes(new byte[10]);                    // reserved
        body.writeBytes("IJKLMNOPQRST".getBytes(StandardCharsets.UTF_8));
        body.write(0);
        body.writeBytes(plugin.getBytes(StandardCharsets.UTF_8));
        body.write(0);
        return packet(0, body.toByteArray());
    }

    private static byte[] ok(int sequence) {
        return packet(sequence, new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00});
    }

    private static byte[] error(int sequence) {
        return packet(sequence, join(
                new byte[] {(byte) 0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'},
                "Access denied for user".getBytes(StandardCharsets.UTF_8)));
    }

    /** AuthSwitchRequest: start again with this plugin and this scramble. */
    private static byte[] switchPlugin(int sequence, String plugin) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0xfe);
        body.writeBytes(plugin.getBytes(StandardCharsets.UTF_8));
        body.write(0);
        body.writeBytes("UVWXYZ0123456789abcd".getBytes(StandardCharsets.UTF_8));
        body.write(0);
        return packet(sequence, body.toByteArray());
    }

    /** AuthMoreData: what caching_sha2_password answers with. */
    private static byte[] moreData(int sequence, int what) {
        return packet(sequence, new byte[] {0x01, (byte) what});
    }

    private static Map<String, byte[]> seeds() {
        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("native password, accepted",
                join(greeting("mysql_native_password"), ok(2)));
        seeds.put("native password, refused",
                join(greeting("mysql_native_password"), error(2)));
        seeds.put("caching sha2, fast path",
                join(greeting("caching_sha2_password"), moreData(2, 3), ok(3)));
        seeds.put("caching sha2, full path asked for",
                join(greeting("caching_sha2_password"), moreData(2, 4), error(4)));
        seeds.put("a plugin switch then ok",
                join(greeting("caching_sha2_password"),
                        switchPlugin(2, "mysql_native_password"), ok(4)));
        seeds.put("a plugin switch then refused",
                join(greeting("caching_sha2_password"),
                        switchPlugin(2, "mysql_native_password"), error(4)));
        seeds.put("refused before the greeting finishes", error(0));
        return seeds;
    }

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
            ScriptedTransportProvider.nextScript(script);
            try (MySession session = MySession.open(settings())) {
                tally.merge(session.isOpen() ? "logged in" : "logged in but closed",
                        1, Integer::sum);
            } catch (SQLException refused) {
                tally.merge(refused.getClass().getSimpleName(), 1, Integer::sum);
            } catch (Throwable thrown) {
                breaches.put(name, "failed with " + thrown.getClass().getName()
                        + ", which is not a failure a caller can act on: " + thrown.getMessage());
                return;
            } finally {
                ScriptedTransportProvider.clear();
            }
            if (SecretScope.open() != open) {
                breaches.put(name, "left " + (SecretScope.open() - open)
                        + " secret scope(s) open - a password still in this process");
            }
        });

        System.err.println("[login fuzz mysql] " + chosen.size() + " cases, " + tally
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

    /** The control: without it, a run that never connected would look identical. */
    @Test
    void theScriptActuallyReachesTheDriver() {
        ScriptedTransportProvider.nextScript(
                join(greeting("mysql_native_password"), ok(2)));
        try (MySession session = MySession.open(settings())) {
            assertTrue(session != null);
        } catch (SQLException refused) {
            // Either way, what is asserted is that the bytes were read.
        }
        assertTrue(ScriptedTransportProvider.last() != null
                        && ScriptedTransportProvider.last().consumed() > 0,
                "the driver never read the script, so every other case would have passed "
                + "without testing anything");
    }
}
