package space.seclume.sqlserver.tds;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.fuzz.FuzzRun;

/**
 * The SQL Server answer boundary, attacked.
 *
 * <p>TDS is the friendliest of the four to walk - every packet carries its own
 * length and a bit that says whether it is the last - and that is exactly why
 * it is worth attacking. A walker with little to decide has little code, and
 * the little it has is the arithmetic around a length that <b>counts its own
 * header</b>: two bytes big-endian, so a packet claiming fewer than eight
 * bytes claims a negative body.
 *
 * <p>The seeds therefore include the shapes on both sides of that boundary: a
 * packet of exactly the header and nothing else, one marked last and one not,
 * and a message spread over several packets where only the final one carries
 * the bit.
 */
@Timeout(180)
class SqlServerAnswersFuzzTest {

    private static final int HEADER = 8;
    private static final int TYPE_TABULAR_RESULT = 0x04;
    private static final int END_OF_MESSAGE = 0x01;

    /** One packet: type, status, big-endian length counting the header, spid, id, window. */
    private static byte[] packet(int status, byte[] payload) {
        int length = HEADER + payload.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(TYPE_TABULAR_RESULT);
        out.write(status);
        out.write((length >> 8) & 0xff);
        out.write(length & 0xff);
        out.write(0x00);
        out.write(0x33);            // spid
        out.write(0x01);            // packet id
        out.write(0x00);            // window
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
        // DONE: token 0xfd, status, curcmd, rowcount as eight bytes.
        byte[] done = {(byte) 0xfd, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] doneInProc = {(byte) 0xff, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] row = {(byte) 0xd1, 0x07, 0x00, 0x00, 0x00};

        Map<String, byte[]> seeds = new LinkedHashMap<>();
        seeds.put("one last packet", packet(END_OF_MESSAGE, done));
        seeds.put("header only, last", packet(END_OF_MESSAGE, new byte[0]));
        seeds.put("header only, not last", packet(0, new byte[0]));
        seeds.put("two packets, the second last",
                join(packet(0, row), packet(END_OF_MESSAGE, done)));
        seeds.put("done in proc then done",
                packet(END_OF_MESSAGE, join(doneInProc, doneInProc, done)));
        seeds.put("three continuations then the end",
                join(packet(0, row), packet(0, row), packet(0, row),
                        packet(END_OF_MESSAGE, done)));
        return seeds;
    }

    @Test
    void theBoundarySurvivesAHostileServer() {
        FuzzRun.against("SqlServerAnswers", SqlServerAnswers::new, seeds());
    }
}
