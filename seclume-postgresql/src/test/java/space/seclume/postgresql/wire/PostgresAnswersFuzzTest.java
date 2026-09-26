package space.seclume.postgresql.wire;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.fuzz.BoundaryContract;
import space.seclume.tck.fuzz.FuzzRun;

/**
 * The PostgreSQL answer boundary, attacked.
 *
 * <p>Everything this walker does rests on one number it reads off the wire and
 * then believes: the four-byte length that counts itself. The existing tests
 * feed it answers a server would send. This one feeds it answers a server
 * would not, and asks the five questions in {@link BoundaryContract} about
 * each.
 *
 * <p>The corpus starts from messages this protocol would accept, because a
 * stream of noise is rejected by the first length check and never reaches the
 * state behind it. From there: cut at every byte, every length-shaped window
 * spoilt, every byte replaced, answers spliced and repeated, and noise on top.
 */
@Timeout(120)
class PostgresAnswersFuzzTest {

    /** One message: type byte, four-byte length counting itself, body. */
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

    private static byte[] text(String value) {
        return value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static Map<String, byte[]> seeds() {
        byte[] ready = message('Z', new byte[] {'I'});
        byte[] inTransaction = message('Z', new byte[] {'T'});
        byte[] complete = message('C', text("SELECT 1\0"));
        byte[] description = message('T', new byte[] {0, 1, 'n', 0, 0, 0, 0, 0, 0, 0, 0,
            0, 23, 0, 4, 0, 0, 0, (byte) 0xff, 0, 0});
        byte[] row = message('D', new byte[] {0, 1, 0, 0, 0, 1, '7'});
        byte[] error = message('E', text("SERROR\0C42601\0Msyntax\0\0"));
        byte[] empty = message('n', new byte[0]);

        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("ready", ready);
        seeds.put("complete then ready", join(complete, ready));
        seeds.put("rows", join(description, row, row, complete, ready));
        seeds.put("error then ready", join(error, ready));
        seeds.put("no-body message then ready", join(empty, ready));
        seeds.put("ready in a transaction", inTransaction);
        return seeds;
    }

    @Test
    void theBoundarySurvivesAHostileServer() {
        FuzzRun.against("PostgresAnswers", PostgresAnswers::new, seeds());
    }
}
