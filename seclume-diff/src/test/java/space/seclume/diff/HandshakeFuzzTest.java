package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * The four handshake parsers, fed bytes no server would send.
 *
 * <p>E1 and E2 ask whether the drivers agree with somebody else's when both
 * are talking to a server that behaves. This asks the other question: what
 * happens when the thing on the other end does not. Four protocols written
 * from scratch means four parsers that have only ever met well-behaved
 * servers, and the handshake is the part of each one that runs <b>before any
 * authentication</b> - reachable by anything that can answer on the port or
 * stand in the middle of the connection.
 *
 * <h2>What counts as passing</h2>
 *
 * <p>Not "it works" - none of this input can work. The driver has to fail the
 * way a library fails:
 *
 * <ul>
 *   <li>a {@link SQLException}, which is what a caller is written to catch -
 *       not an {@code ArrayIndexOutOfBoundsException} from four frames down,
 *       and not an {@code Error};
 *   <li><b>promptly</b>, so a garbage length cannot be used to hang a caller;
 *   <li>without an {@code OutOfMemoryError}, which is what happens when a
 *       length taken off the wire is handed to an allocator without a glance.
 * </ul>
 *
 * <p>That last one is the classic mistake in a hand-written protocol, and the
 * reason this test exists at all.
 *
 * <p>No database is needed and no password: the drivers never get far enough
 * to want one.
 */
@Timeout(1800)
class HandshakeFuzzTest {

    /**
     * Long enough that a real failure has happened, short enough that a hang
     * is noticed while there is still time to try the rest.
     *
     * <p>Six seconds, not twenty. Every case that hangs costs this in full,
     * and there are several hundred of them - the first run took the class
     * past its own timeout before it had said anything useful, which is its
     * own small lesson about patience budgets.
     */
    private static final int PATIENCE_SECONDS = 6;

    /** How a driver answered a hostile server. */
    private record Verdict(String what, Throwable thrown, boolean timedOut) {

        boolean acceptable() {
            if (timedOut) {
                return false;
            }
            return thrown instanceof SQLException;
        }

        @Override
        public String toString() {
            if (timedOut) {
                return what + ": did not return within " + PATIENCE_SECONDS + "s";
            }
            if (thrown == null) {
                return what + ": connected, to a server sending nonsense";
            }
            return what + ": " + thrown.getClass().getName() + ": " + thrown.getMessage();
        }
    }

    // ------------------------------------------------------------ the input --

    /**
     * The shapes worth trying, beyond random noise.
     *
     * <p>Random bytes mostly fail at the first field and never reach the
     * interesting code. These are aimed: a length field that claims more than
     * memory, a negative one, a count of elements nobody sent, and a frame
     * that stops in the middle of a header.
     */
    private static List<byte[]> hostileFrames(Random random) {
        List<byte[]> frames = new ArrayList<>();
        frames.add(new byte[0]);
        frames.add(new byte[] {0});
        // A length of 2^31-1, and of -1, in both byte orders, behind every
        // plausible one-byte tag.
        for (int tag : new int[] {0, 'R', 'E', 'N', 'S', 0x04, 0xff}) {
            frames.add(new byte[] {(byte) tag,
                (byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff});
            frames.add(new byte[] {(byte) tag,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
            frames.add(new byte[] {(byte) tag,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x7f});
            frames.add(new byte[] {(byte) tag, 0, 0, 0, 0});
            frames.add(new byte[] {(byte) tag, 0, 0, 0, 3});
        }
        // Truncations of something that starts out plausible.
        byte[] plausible = {(byte) 'R', 0, 0, 0, 8, 0, 0, 0, 3};
        for (int length = 1; length < plausible.length; length++) {
            byte[] cut = new byte[length];
            System.arraycopy(plausible, 0, cut, 0, length);
            frames.add(cut);
        }
        // And noise, which is cheap and occasionally lands somewhere the
        // aimed cases do not.
        for (int i = 0; i < 40; i++) {
            byte[] noise = new byte[1 + random.nextInt(64)];
            random.nextBytes(noise);
            frames.add(noise);
        }
        return frames;
    }

    // ------------------------------------------------------------- the runs --

    @Test
    void postgresSurvivesAHostileServer(@TempDir Path dir) throws Exception {
        fuzz("postgresql", dir, port -> "jdbc:seclume:postgresql://127.0.0.1:" + port
                + "/db?user=u&tls=off&connectTimeout=2000&provider=file&path=");
    }

    @Test
    void mysqlSurvivesAHostileServer(@TempDir Path dir) throws Exception {
        fuzz("mysql", dir, port -> "jdbc:seclume:mysql://127.0.0.1:" + port
                + "/db?user=u&tls=off&connectTimeout=2000&provider=file&path=");
    }

    @Test
    void sqlServerSurvivesAHostileServer(@TempDir Path dir) throws Exception {
        fuzz("sqlserver", dir, port -> "jdbc:seclume:sqlserver://127.0.0.1:" + port
                + "/db?user=u&trustServerCertificate=true&connectTimeout=2000"
                + "&provider=file&path=");
    }

    @Test
    void oracleSurvivesAHostileServer(@TempDir Path dir) throws Exception {
        fuzz("oracle", dir, port -> "jdbc:seclume:oracle://127.0.0.1:" + port
                + "/svc?user=u&connectTimeout=2000&provider=file&path=");
    }

    // ---------------------------------------------------------------- engine --

    @FunctionalInterface
    private interface UrlFor {
        String url(int port);
    }

    private void fuzz(String driver, Path dir, UrlFor urls) throws Exception {
        Path password = dir.resolve("password");
        Files.writeString(password, "irrelevant");
        String suffix = password.toString().replace('\\', '/');

        Random random = new Random(Long.getLong("seclume.fuzz.seed", 20260921L));
        List<Verdict> bad = new ArrayList<>();

        for (byte[] frame : hostileFrames(random)) {
            for (boolean readFirst : new boolean[] {true, false}) {
                try (HostileServer server = new HostileServer(readFirst
                        ? HostileServer.readingThenWriting(frame)
                        : HostileServer.writing(frame))) {

                    Verdict verdict = attempt(driver + " " + describe(frame)
                            + (readFirst ? " after reading" : " unprompted"),
                            urls.url(server.port()) + suffix);
                    if (!verdict.acceptable()) {
                        System.out.println("  FUZZ " + verdict);
                        bad.add(verdict);
                    }
                }
            }
        }

        assertTrue(bad.isEmpty(), () -> "the " + driver + " handshake answered "
                + bad.size() + " hostile server(s) with something other than a SQLException:\n  "
                + String.join("\n  ", bad.stream().map(Object::toString).toList()));
    }

    /**
     * One connection attempt, on a thread of its own so a hang is a result
     * rather than the end of the test run.
     */
    private Verdict attempt(String what, String url) throws InterruptedException {
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);

        Thread worker = new Thread(() -> {
            try {
                DriverManager.getConnection(url).close();
            } catch (Throwable t) {
                thrown.set(t);
            } finally {
                done.countDown();
            }
        }, "fuzz-" + what);
        worker.setDaemon(true);
        worker.start();

        boolean finished = done.await(PATIENCE_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            worker.interrupt();
            return new Verdict(what, null, true);
        }
        return new Verdict(what, thrown.get(), false);
    }

    private static String describe(byte[] frame) {
        if (frame.length == 0) {
            return "<nothing>";
        }
        StringBuilder text = new StringBuilder(frame.length * 2 + 2);
        for (int i = 0; i < Math.min(frame.length, 12); i++) {
            text.append(String.format("%02x", frame[i]));
        }
        if (frame.length > 12) {
            text.append("...(").append(frame.length).append(")");
        }
        return text.toString();
    }

    /** Guards the guard: a driver pointed at nothing at all must also fail cleanly. */
    @Test
    void nothingListeningIsAlsoASqlException(@TempDir Path dir) throws Exception {
        Path password = dir.resolve("password");
        Files.writeString(password, "irrelevant");
        int port;
        try (java.net.ServerSocket probe = new java.net.ServerSocket(0, 1,
                java.net.InetAddress.getLoopbackAddress())) {
            port = probe.getLocalPort();
        }
        Verdict verdict = attempt("nothing listening",
                "jdbc:seclume:postgresql://127.0.0.1:" + port + "/db?user=u&tls=off"
                + "&connectTimeout=2000&provider=file&path="
                + password.toString().replace('\\', '/'));
        if (!verdict.acceptable()) {
            fail(verdict.toString());
        }
    }
}
