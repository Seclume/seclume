package space.seclume.oracle.net;

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
 * The Oracle login, interrupted everywhere, and the password afterwards.
 *
 * <p>The other three drivers are reachable from {@code open()} with a script,
 * or nearly so. Oracle is not: before a credential is exchanged there is a
 * CONNECT, an ACCEPT whose fields decide the packet framing, a protocol
 * negotiation and a data-type negotiation, and a script that answered all of
 * that would be half a server. <b>So this starts where the password does.</b>
 * {@link NsChannel#over} builds a channel on any transport,
 * {@link TtcFastAuth#open} sends the combined opening and reads the challenge,
 * and {@link TtcLogin#phaseTwo} is the method the whole library exists for -
 * PBKDF2, AES and hex over native memory, with the secret never becoming an
 * object. Those two calls are the login; what is skipped in front of them
 * holds nothing to protect.
 *
 * <p>The challenge is synthetic and it can be, because nothing in it is
 * checked against a password. {@code AUTH_SESSKEY} is decrypted with a key
 * derived from the password, and with a made-up session key the result is
 * simply the wrong half - which is what a wrong password produces too. The
 * derivation runs in full either way, and that is the code under test. Nothing
 * here is a recording, so nothing here is a verifier for a real account.
 *
 * <p>Both framings, because the NS length field is two bytes below protocol
 * version 315 and four from there on, and the login is the first place either
 * one is read.
 *
 * <p><b>The assertion that counts is the last one.</b> A refused login is
 * expected. What is checked after every case is that {@link SecretScope#open()}
 * is back where it started - the derivation holds the password, the password
 * key and the combo key open at once, and a path that leaves on an exception
 * between two of them is exactly the path nobody wrote a test for.
 */
@Timeout(900)
class OracleLoginFuzzTest {

    private static final String PASSWORD = "ein Testpasswort";
    private static final String USER = "seclume_test";
    private static final String CONNECT_STRING = "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=FREEPDB1)))";

    private static final int HEADER = 8;
    private static final int END_OF_ANSWER = 0x2000;
    /** What AUTH_VFR_DATA's flags say when the server wants the 12c scheme. */
    private static final int VERIFIER_12C = 0x4815;

    private static SecretProvider secret() {
        byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(256, target -> {
            for (int i = 0; i < bytes.length; i++) {
                target.set(ValueLayout.JAVA_BYTE, i, bytes[i]);
            }
            return bytes.length;
        });
    }

    // ---- the wire ---------------------------------------------------------

    private static byte[] packet(int type, byte[] body, boolean fourByteLength) {
        int length = HEADER + body.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (fourByteLength) {
            out.write((length >> 24) & 0xff);
            out.write((length >> 16) & 0xff);
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        } else {
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
            out.write(0x00);
            out.write(0x00);
        }
        out.write(type);
        out.write(0x00);
        out.write(0x00);
        out.write(0x00);
        out.writeBytes(body);
        return out.toByteArray();
    }

    private static byte[] data(byte[] ttc, boolean large) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write((END_OF_ANSWER >> 8) & 0xff);
        body.write(END_OF_ANSWER & 0xff);
        body.writeBytes(ttc);
        return packet(NsPacket.TYPE_DATA, body.toByteArray(), large);
    }

    private static byte[] join(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /** The same length-prefixed number {@link TtcParameters} writes. */
    private static void number(ByteArrayOutputStream out, long value) {
        if (value == 0) {
            out.write(0);
            return;
        }
        int bytes = 8;
        while (bytes > 1 && (value >>> ((bytes - 1) * 8)) == 0) {
            bytes--;
        }
        out.write(bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            out.write((int) (value >>> (i * 8)) & 0xff);
        }
    }

    private static void text(ByteArrayOutputStream out, String value) {
        out.write(value.length() & 0xff);
        out.writeBytes(value.getBytes(StandardCharsets.US_ASCII));
    }

    /** One key-value pair, as the server writes it. */
    private static void pair(ByteArrayOutputStream out, String name, String value, long flags) {
        number(out, name.length());
        text(out, name);
        number(out, value.length());
        if (!value.isEmpty()) {
            text(out, value);
        }
        number(out, flags);
    }

    private static String hex(int bytes, int seed) {
        StringBuilder out = new StringBuilder(bytes * 2);
        for (int i = 0; i < bytes; i++) {
            out.append(String.format("%02X", (seed + i * 37) & 0xff));
        }
        return out.toString();
    }

    /**
     * A parameter message with the challenge in it.
     *
     * <p>The reader finds this by its signature rather than by arithmetic -
     * the protocol and data-type answers in front of it have no written
     * length - so the junk before it is not decoration: it is the thing the
     * search has to walk past.
     */
    private static byte[] challenge(int sessionKeyBytes, int verifierType) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // The protocol and data-type answers, which the reader skips.
        out.writeBytes(new byte[] {0x01, 0x06, 0x00, 'O', 'r', 'a', 'c', 'l', 'e', 0,
            0x00, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00});
        out.write(TtcMessage.TYPE_PARAMETER);
        ByteArrayOutputStream pairs = new ByteArrayOutputStream();
        pair(pairs, "AUTH_SESSKEY", hex(sessionKeyBytes, 0x11), 1);
        pair(pairs, "AUTH_VFR_DATA", hex(16, 0x40), verifierType);
        pair(pairs, "AUTH_PBKDF2_CSK_SALT", hex(16, 0x70), 0);
        pair(pairs, "AUTH_PBKDF2_VGEN_COUNT", "4096", 0);
        pair(pairs, "AUTH_PBKDF2_SDER_COUNT", "3", 0);
        pair(pairs, "AUTH_GLOBALLY_UNIQUE_DBID", hex(16, 0x90), 0);
        number(out, 6);
        out.writeBytes(pairs.toByteArray());
        return out.toByteArray();
    }

    /** The answer to the second stage when the server agreed. */
    private static byte[] sessionParameters() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(TtcMessage.TYPE_PARAMETER);
        ByteArrayOutputStream pairs = new ByteArrayOutputStream();
        pair(pairs, "AUTH_VERSION_NO", "386138880", 0);
        pair(pairs, "AUTH_SESSION_ID", "42", 0);
        pair(pairs, "AUTH_SERIAL_NUM", "7", 0);
        number(out, 3);
        out.writeBytes(pairs.toByteArray());
        return out.toByteArray();
    }

    /** The answer when it did not - a TTC error carrying an ORA number. */
    private static byte[] refusal(String said) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(TtcMessage.TYPE_ERROR);
        out.writeBytes(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x03, (byte) 0xf9});
        out.write(said.length());
        out.writeBytes(said.getBytes(StandardCharsets.US_ASCII));
        return out.toByteArray();
    }

    private static Map<String, byte[]> seeds(boolean large) {
        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("logged in", join(
                data(challenge(32, VERIFIER_12C), large),
                data(sessionParameters(), large)));
        seeds.put("wrong password", join(
                data(challenge(32, VERIFIER_12C), large),
                data(refusal("ORA-01017: invalid username/password; logon denied"), large)));
        seeds.put("the account is locked", join(
                data(challenge(32, VERIFIER_12C), large),
                data(refusal("ORA-28000: the account is locked"), large)));
        seeds.put("refused behind a marker", join(
                data(challenge(32, VERIFIER_12C), large),
                packet(NsPacket.TYPE_MARKER, new byte[] {0x01, 0x00, 0x02}, large),
                packet(NsPacket.TYPE_MARKER, new byte[] {0x01, 0x00, 0x02}, large),
                data(refusal("ORA-01017: invalid username/password; logon denied"), large)));
        seeds.put("an 11g verifier, which this driver does not send",
                data(challenge(32, 0x1128), large));
        seeds.put("a session key of a length nobody established",
                data(challenge(24, VERIFIER_12C), large));
        seeds.put("the challenge and then silence", data(challenge(32, VERIFIER_12C), large));
        seeds.put("no challenge at all", data(sessionParameters(), large));
        return seeds;
    }

    // ---- the sweep --------------------------------------------------------

    @Test
    void noLoginLeavesAPasswordBehind_fourByteLength() {
        sweep(true, "four-byte length");
    }

    @Test
    void noLoginLeavesAPasswordBehind_twoByteLength() {
        sweep(false, "two-byte length");
    }

    private void sweep(boolean large, String label) {
        int version = large ? NsPacket.VERSION_DESIRED : NsPacket.VERSION_MINIMUM;
        ByteCorpus corpus = ByteCorpus.from(seeds(large));
        Map<String, byte[]> chosen = corpus.selected();
        Map<String, String> breaches = new TreeMap<>();
        Map<String, Integer> tally = new TreeMap<>();

        long openBefore = SecretScope.open();
        long readBefore = SecretScope.allocations();

        chosen.forEach((name, script) -> {
            long open = SecretScope.open();
            NsChannel channel = NsChannel.over(HostileTransport.of(script), version);
            try {
                TtcAuth.Challenge answer = TtcFastAuth.open(channel, "seclume", USER);
                TtcLogin.phaseTwo(channel, USER, secret(), answer, CONNECT_STRING);
                tally.merge("logged in", 1, Integer::sum);
            } catch (SQLException | IOException | WireBuffer.Truncated expected) {
                // All three become a SQLException at OracleSession.connectAndLogIn,
                // whose Truncated clause stands before its RuntimeException one
                // for exactly the cases this corpus produces.
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

        System.err.println("[login fuzz oracle, " + label + "] " + chosen.size() + " cases, "
                + tally + ", secrets read " + (SecretScope.allocations() - readBefore));

        assertTrue(SecretScope.allocations() > readBefore,
                "no secret was ever read, so this proves nothing");
        assertTrue(SecretScope.open() == openBefore,
                "scopes were left open across the whole run: "
                + (SecretScope.open() - openBefore));

        if (!breaches.isEmpty()) {
            StringBuilder report = new StringBuilder(breaches.size() + " of " + chosen.size()
                    + " logins broke the contract (" + label + "):\n");
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
     * The control: the unspoilt seeds have to reach the two ends they name.
     *
     * <p>Without it a mistake in the challenge - a pair the reader skips, a
     * length off by one - would make every case above fail identically at the
     * first packet, the password would never be touched, and the report would
     * look exactly the same.
     */
    @Test
    void theHappyPathReallyLogsIn() throws Exception {
        NsChannel channel = NsChannel.over(
                HostileTransport.of(seeds(true).get("logged in")), NsPacket.VERSION_DESIRED);
        try {
            TtcAuth.Challenge answer = TtcFastAuth.open(channel, "seclume", USER);
            assertTrue(answer.is12c(), "the seed does not offer the 12c verifier");
            assertTrue(answer.sessionKey().length() == 64,
                    "the seed's session key is " + answer.sessionKey().length() + " hex digits");
            TtcLogin.phaseTwo(channel, USER, secret(), answer, CONNECT_STRING);
        } finally {
            channel.close();
        }

        NsChannel refused = NsChannel.over(
                HostileTransport.of(seeds(true).get("wrong password")), NsPacket.VERSION_DESIRED);
        try {
            TtcAuth.Challenge answer = TtcFastAuth.open(refused, "seclume", USER);
            TtcLogin.phaseTwo(refused, USER, secret(), answer, CONNECT_STRING);
            throw new AssertionError("a refused login came back as a success");
        } catch (SQLException expected) {
            assertTrue("28000".equals(expected.getSQLState()),
                    "a refusal has to be 28000, not " + expected.getSQLState());
            assertTrue(expected.getMessage().contains("ORA-01017"),
                    "the server's own sentence was lost: " + expected.getMessage());
        } finally {
            refused.close();
        }
    }
}
