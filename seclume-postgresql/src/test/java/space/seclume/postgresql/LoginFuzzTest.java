package space.seclume.postgresql;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
 * A login that goes wrong in every way a login can, and the password after it.
 *
 * <p>The decoder sweeps reach the driver through {@code resume()}, which skips
 * the handshake entirely. That is most of the surface and it is not the part
 * that matters most: <b>the login is the only place the credential is on the
 * wire</b>. It is read from its provider into locked memory, turned into a
 * hash or a wrapped key, written into a packet, and sent. Every one of those
 * steps can be interrupted by a server that stops talking, and the question
 * afterwards is not what the driver decoded - it is whether the secret is
 * still in this process.
 *
 * <p>There is one existing test per driver asking that, each with a fake
 * server and a handful of cases. This asks it of a corpus: a plausible
 * PostgreSQL authentication exchange, cut at <b>every byte</b>, with every
 * length-shaped field spoilt and every byte replaced in turn.
 *
 * <p><b>The assertion that counts is the last one.</b> A refusal is expected
 * and uninteresting; what is checked is that {@link SecretScope#open()} is
 * back where it started afterwards. A scope still open is a password still in
 * memory, on a path nobody wrote a test for because nobody thought of it.
 *
 * <p>The driver reaches the script through {@link ScriptedTransportProvider},
 * so this is {@code PgSession.open} doing exactly what it does against a real
 * server - the same handshake code, the same secret handling, the same
 * unwinding.
 */
@Timeout(600)
class LoginFuzzTest {

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

    private static PgSession.Settings settings() throws SQLException {
        return new PgSession.Settings("scripted", 5432, "seclume_test", "seclume_test",
                secret(), "seclume", 2_000, HostList.of("scripted", 5432),
                ResultLimit.NONE, TlsMode.OFF,
                space.seclume.internal.jdbc.TlsStack.JSSE);
    }

    // ---- what a server says during a login ---------------------------------

    private static byte[] message(char type, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(type);
        int length = 4 + body.length;
        out.write((length >> 24) & 0xff);
        out.write((length >> 16) & 0xff);
        out.write((length >> 8) & 0xff);
        out.write(length & 0xff);
        out.writeBytes(body);
        return out.toByteArray();
    }

    private static byte[] join(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    private static byte[] int32(int value) {
        return new byte[] {(byte) (value >> 24), (byte) (value >> 16),
            (byte) (value >> 8), (byte) value};
    }

    private static byte[] text(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static Map<String, byte[]> seeds() {
        // AuthenticationSASL, offering SCRAM-SHA-256.
        byte[] sasl = message('R', join(int32(10), text("SCRAM-SHA-256\0"), new byte[] {0}));
        // AuthenticationSASLContinue, with a server-first-message that parses.
        byte[] saslContinue = message('R', join(int32(11),
                text("r=abcdefghijklmnopqrstuvwxyz123456,s=QSXCR+Q6sek8bf92,i=4096")));
        // AuthenticationSASLFinal, with a signature the client will not accept.
        byte[] saslFinal = message('R', join(int32(12), text("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAA")));
        byte[] ok = message('R', int32(0));
        byte[] md5 = message('R', join(int32(5), new byte[] {1, 2, 3, 4}));
        byte[] cleartext = message('R', int32(3));
        byte[] error = message('E', text("SFATAL\0C28P01\0Mpassword authentication failed\0\0"));
        byte[] parameter = message('S', text("client_encoding\0UTF8\0"));
        byte[] backendKey = message('K', join(int32(1234), int32(5678)));
        byte[] ready = message('Z', new byte[] {'I'});

        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("scram, then refused", join(sasl, saslContinue, error));
        seeds.put("scram, then a bad signature", join(sasl, saslContinue, saslFinal, error));
        seeds.put("scram, then accepted", join(sasl, saslContinue, saslFinal, ok,
                parameter, backendKey, ready));
        seeds.put("md5 asked for", join(md5, error));
        seeds.put("cleartext asked for", join(cleartext, error));
        seeds.put("refused before anything", error);
        seeds.put("accepted without asking", join(ok, parameter, backendKey, ready));
        return seeds;
    }

    /**
     * Every case, and after every one of them the same question.
     *
     * <p>Run on this thread rather than through {@code SessionContract}: the
     * scripted transport is per thread, and a contract that moves the attempt
     * onto a worker would leave the script on the wrong one. The deadline that
     * contract provides is replaced here by the connect timeout in the
     * settings, which the driver applies itself.
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
            ScriptedTransportProvider.nextScript(script);
            try (PgSession session = PgSession.open(settings())) {
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
                        + " secret scope(s) open - a password still in this process, on a path "
                        + "nobody wrote a test for");
            }
        });

        System.err.println("[login fuzz postgresql] " + chosen.size() + " cases, " + tally
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
     * The control, and the reason the run above means anything.
     *
     * <p>If no script ever reached the driver - a wrong transport name, a
     * provider not on the class path - every case would "pass" by failing to
     * connect at all, and the report would look identical. So one case is
     * checked for having been read.
     */
    @Test
    void theScriptActuallyReachesTheDriver() throws Exception {
        ScriptedTransportProvider.nextScript(
                join(message('R', int32(0)), message('Z', new byte[] {'I'})));
        try (PgSession session = PgSession.open(settings())) {
            // A login with no password asked for: the driver should get through.
            assertTrue(session != null);
        } catch (SQLException refused) {
            // Also acceptable - what is asserted is that the bytes were read.
        }
        assertTrue(ScriptedTransportProvider.last() != null
                        && ScriptedTransportProvider.last().consumed() > 0,
                "the driver never read the script, so every other case in this class would "
                + "have passed without testing anything");
    }
}
