package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.tck.HostileTls;
import space.seclume.tck.HostileTls.Behaviour;

/**
 * SQL Server never logs in without TLS, and never to a certificate it was
 * told to check and could not.
 *
 * <p>TDS 7.4 negotiates in the clear: a server whose PRELOGIN answer says
 * {@code ENCRYPT_NOT_SUP} is refused - the LOGIN7 it would get instead
 * carries the password under a XOR. TDS 8.0 ({@code encrypt=strict}) has TLS
 * from the first byte, and there each of the ways {@link HostileTls} breaks
 * TLS is refused, over both stacks, and under {@code trustServerCertificate=false}
 * each certificate it cannot check.
 *
 * <p>For every refusal: an {@link SQLException} of class 08, no LOGIN7 in the
 * clear or inside a TLS whose certificate failed, no second connection, the
 * password never read, no secret left open.
 */
@Isolated
@Timeout(300)
class TlsNeverFallsBackTest {

    @TempDir
    static Path directory;
    private static HostileTls hostile;

    /**
     * What the server saw: connections, bytes in the clear, the first bytes
     * inside TLS, and how many came after its PRELOGIN answer.
     */
    record Seen(int connections, byte[] clear, byte[] insideTls, int afterAnswer) {
    }

    @BeforeAll
    static void certificates() throws Exception {
        hostile = HostileTls.create(directory);
    }

    @Test
    void aServerThatRefusesEncryptionIsRefused() throws Exception {
        List<String> wrong = new ArrayList<>();
        for (int answer : new int[] {Tds.ENCRYPT_NOT_SUP}) {
            for (TlsStack stack : new TlsStack[] {TlsStack.SECLUME, TlsStack.JSSE}) {
                String verdict = oneCase(TdsVersion.TDS_7_4, stack, false, null, answer);
                if (verdict != null) {
                    wrong.add("TDS 7.4 " + stack + " against ENCRYPT_NOT_SUP: " + verdict);
                }
            }
        }
        assertEquals(List.of(), wrong);
    }

    @Test
    void strictEncryptionNeverFallsBackAndChecksWhatItWasToldTo() throws Exception {
        List<String> wrong = new ArrayList<>();
        for (TlsStack stack : new TlsStack[] {TlsStack.SECLUME, TlsStack.JSSE}) {
            for (boolean trust : new boolean[] {true, false}) {
                for (Behaviour behaviour : Behaviour.values()) {
                    String verdict = oneCase(TdsVersion.TDS_8_0, stack, trust, behaviour, -1);
                    if (verdict != null) {
                        wrong.add("TDS 8.0 " + stack + " trustServerCertificate=" + trust
                                + " against " + behaviour + ": " + verdict);
                    }
                }
            }
        }
        assertEquals(List.of(), wrong);
    }

    /** Null if the case went as it must, or what went wrong. */
    private static String oneCase(TdsVersion version, TlsStack stack, boolean trust,
                                  Behaviour behaviour, int preLoginAnswer) throws Exception {
        boolean goesOn = behaviour != null && behaviour.handshakes() && trust;
        int[] asked = new int[1];
        long open = SecretScope.open();
        try (ServerSocket listener = new ServerSocket(0, 4, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Seen> seen = serve(listener, behaviour, preLoginAnswer);
            SQLException failure = null;
            try {
                TdsSession.Settings settings = settings(listener.getLocalPort(), version, stack,
                        trust, asked);
                TdsSession session = behaviour != null && behaviour.fromTrustedCa()
                        ? TrustChoice.using(TrustChoice.of("jdbc:x://h/db?tlsRootCert="
                                + hostile.caPem(), null), () -> TdsSession.open(settings))
                        : TdsSession.open(settings);
                session.close();
            } catch (SQLException e) {
                failure = e;
            }
            Seen what = seen.get(60, TimeUnit.SECONDS);
            if (SecretScope.open() != open) {
                return "a secret was left open";
            }
            if (goesOn) {
                return what.insideTls() != null ? null
                        : "TLS that checks nothing did not go on: " + failure;
            }
            if (failure == null) {
                return "connected";
            }
            if (failure.getSQLState() == null || !failure.getSQLState().startsWith("08")) {
                return "refused with SQLState " + failure.getSQLState() + ": " + failure;
            }
            if (hasLogin7(what.clear())) {
                return "a LOGIN7 went out in the clear";
            }
            if (what.insideTls() != null) {
                return "the client went on to a server whose certificate failed";
            }
            if (behaviour == null && what.afterAnswer() != 0) {
                // Not a LOGIN7 and not a ClientHello either: a server that
                // refuses encryption gets nothing more.
                return what.afterAnswer() + " bytes went to a server that refused encryption";
            }
            if (what.connections() != 1) {
                return what.connections() + " connections - it tried again";
            }
            if (asked[0] != 0) {
                return "the password was read for a connection that was refused";
            }
            return null;
        }
    }

    /** Whether a TDS packet of type LOGIN7 starts anywhere at a packet boundary. */
    private static boolean hasLogin7(byte[] clear) {
        int at = 0;
        while (at + 8 <= clear.length) {
            int type = clear[at] & 0xff;
            int length = ((clear[at + 2] & 0xff) << 8) | (clear[at + 3] & 0xff);
            if (type == Tds.TYPE_LOGIN7) {
                return true;
            }
            if (length < 8) {
                return false;
            }
            at += length;
        }
        return false;
    }

    private static CompletableFuture<Seen> serve(ServerSocket listener, Behaviour behaviour,
                                                 int preLoginAnswer) {
        return CompletableFuture.supplyAsync(() -> {
            int connections = 0;
            int afterAnswer = 0;
            ByteArrayOutputStream clear = new ByteArrayOutputStream();
            byte[] inside = null;
            try {
                listener.setSoTimeout(30_000);
                try (Socket plain = listener.accept()) {
                    connections++;
                    plain.setSoTimeout(10_000);
                    InputStream in = plain.getInputStream();
                    OutputStream out = plain.getOutputStream();
                    if (behaviour != null) {
                        // TDS 8.0: the ClientHello is the first thing on the wire.
                        inside = hostile.misbehave(behaviour, plain, TdsVersion.ALPN);
                    } else {
                        byte[] head = in.readNBytes(8);
                        clear.write(head);
                        int length = head.length < 8 ? 8
                                : ((head[2] & 0xff) << 8) | (head[3] & 0xff);
                        clear.write(in.readNBytes(Math.max(0, length - 8)));
                        out.write(preLoginAnswer(preLoginAnswer));
                        out.flush();
                        plain.setSoTimeout(2_000);
                        byte[] after = HostileTls.readSome(in);
                        afterAnswer = after.length;
                        clear.write(after);
                    }
                }
                listener.setSoTimeout(700);
                while (true) {
                    try (Socket again = listener.accept()) {
                        connections++;
                        again.setSoTimeout(2_000);
                        clear.write(HostileTls.readSome(again.getInputStream()));
                    } catch (SocketTimeoutException none) {
                        break;
                    }
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            return new Seen(connections, clear.toByteArray(), inside, afterAnswer);
        });
    }

    /** A PRELOGIN answer: VERSION 16.0, and ENCRYPTION as {@code encryption}. */
    private static byte[] preLoginAnswer(int encryption) {
        byte[] payload = {
            Tds.PRELOGIN_VERSION, 0, 11, 0, 6,
            Tds.PRELOGIN_ENCRYPTION, 0, 17, 0, 1,
            (byte) Tds.PRELOGIN_TERMINATOR,
            16, 0, 0x10, 0x00, 0, 0,                    // 16.0.4096, subbuild 0
            (byte) encryption,
        };
        byte[] packet = new byte[8 + payload.length];
        packet[0] = Tds.TYPE_TABULAR_RESULT;
        packet[1] = 0x01;                              // end of message
        packet[2] = (byte) (packet.length >>> 8);
        packet[3] = (byte) packet.length;
        packet[6] = 1;
        System.arraycopy(payload, 0, packet, 8, payload.length);
        return packet;
    }

    private static TdsSession.Settings settings(int port, TdsVersion version, TlsStack stack,
                                                boolean trust, int[] asked) {
        SecretProvider password = new CallbackSecretProvider(64, target -> {
            asked[0]++;
            byte[] bytes = "not-the-password".getBytes(StandardCharsets.US_ASCII);
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
        return new TdsSession.Settings("127.0.0.1", port, "app", "app", password, "seclume-test",
                10_000, trust, HostList.of("127.0.0.1", port), ResultLimit.NONE, version, stack,
                null);
    }
}
