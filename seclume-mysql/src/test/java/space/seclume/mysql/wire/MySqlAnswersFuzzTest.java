package space.seclume.mysql.wire;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.fuzz.FuzzRun;

/**
 * The MySQL answer boundary, attacked.
 *
 * <p>The hardest of the four to reason about and therefore the most worth
 * fuzzing. PostgreSQL, TDS and TTC each find the end of an answer from a flag
 * or a tag in a header; MySQL has neither, so this walker carries a
 * <b>phase</b> - first packet, column definitions, rows - counts columns, and
 * has to tell a terminating packet from a row that happens to begin with the
 * same byte. Three pieces of state that a split read can catch mid-change.
 *
 * <p>Two shapes exist here that the other three do not have, and both are in
 * the seeds:
 *
 * <ul>
 *   <li>a packet of exactly {@code 0xffffff} bytes means <b>more follows</b>,
 *       so a 16 MB value arrives as several packets and the first byte of the
 *       continuation is data rather than a tag - a walker that forgets this
 *       reads a row's contents as a terminator;
 *   <li>an {@code EOF} packet and a row can both start with {@code 0xfe},
 *       and only the length tells them apart.
 * </ul>
 */
@Timeout(180)
class MySqlAnswersFuzzTest {

    /** {@code CLIENT_DEPRECATE_EOF}, as the handshake negotiates it. */
    private static final int DEPRECATE_EOF = 1 << 24;

    /** One packet: three-byte little-endian length, sequence, payload. */
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

    private static Map<String, byte[]> seeds() {
        byte[] ok = packet(1, new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00});
        byte[] err = packet(1, join(new byte[] {(byte) 0xff, 0x15, 0x04, '#', '2', '8', '0',
            '0', '0'}, "Access denied".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        byte[] eof = packet(5, new byte[] {(byte) 0xfe, 0x00, 0x00, 0x02, 0x00});
        byte[] columnCount = packet(1, new byte[] {0x01});
        byte[] columnDefinition = packet(2, new byte[] {
            0x03, 'd', 'e', 'f', 0x00, 0x00, 0x00, 0x01, 'n', 0x00, 0x0c, 0x3f, 0x00,
            0x0b, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00});
        byte[] row = packet(4, new byte[] {0x01, '7'});

        // A value that needs more than one packet: the first announces the
        // maximum and the second carries the tail. Its first byte is data and
        // must not be read as a tag.
        // The header announces the maximum; the body deliberately does not
        // arrive. Sixteen megabytes of 'x' would say nothing more than this
        // does - what the walker has to get right is the state the announcement
        // puts it in, not the bytes it then counts past - and the corpus makes
        // a case per byte, so the honest version of this seed once exhausted
        // the heap.
        byte[] announcesTheMaximum = {(byte) 0xff, (byte) 0xff, (byte) 0xff, 0x04,
            'x', 'x', 'x', 'x'};
        byte[] continued = join(announcesTheMaximum,
                packet(5, new byte[] {(byte) 0xfe, 'y'}));

        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("ok", ok);
        seeds.put("error", err);
        seeds.put("one column one row", join(columnCount, columnDefinition, eof, row, eof));
        seeds.put("empty result", join(columnCount, columnDefinition, eof, eof));
        seeds.put("zero-length packet then ok", join(packet(1, new byte[0]), ok));
        seeds.put("a value across two packets", continued);
        return seeds;
    }

    /**
     * And both halves of the one negotiated fact this walker depends on.
     *
     * <p>{@code CLIENT_DEPRECATE_EOF} decides whether a result set ends with
     * an EOF packet or with an OK packet wearing the EOF tag. The walker is
     * constructed with the capabilities for exactly that reason, so fuzzing
     * only one of the two would leave half the state machine unvisited - and
     * it is the half a modern server actually uses.
     */
    @Test
    void theBoundarySurvivesAHostileServerWithEofPackets() {
        FuzzRun.against("MySqlAnswers(eof)", () -> new MySqlAnswers(0), seeds());
    }

    @Test
    void theBoundarySurvivesAHostileServerWithoutEofPackets() {
        FuzzRun.against("MySqlAnswers(deprecate eof)",
                () -> new MySqlAnswers(DEPRECATE_EOF), seeds());
    }
}
