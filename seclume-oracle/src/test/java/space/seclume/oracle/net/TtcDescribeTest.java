package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * The column description, against a known answer.
 *
 * <p>The bytes come from a {@code python-oracledb} exchange with Oracle Free
 * 23ai for {@code select 42 as answer, 'abc' as text from dual}. Two things in
 * them are worth knowing and are asserted here because they are easy to get
 * wrong:
 *
 * <ul>
 *   <li>A {@code NUMBER} without a declared scale reports <b>-127</b>, not 0.
 *       A driver that treats that as "no decimals" turns 1.5 into 2.</li>
 *   <li>A text literal in a query is a <b>CHAR</b> (type 96), not a
 *       VARCHAR.</li>
 * </ul>
 */
class TtcDescribeTest {

    /** The answer, without the packet header and data flags. */
    private static final String EXPECTED =
            "10179778C2F43A22195C26D0F8A724BB1E90787E090708072D010501028202"
            + "000081010200000000000000000106010606414E5357455200000000000000"
            + "00000060800000010300000000020369010103023FFE010401040454455854"
            + "0000010100000000000000010707787E090708072D00021FE8010201020006";

    @Test
    void readsTheColumnsOfTheAnswer() {
        byte[] bytes = new byte[EXPECTED.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(EXPECTED.substring(i * 2, i * 2 + 2), 16);
        }
        try (WireBuffer in = new WireBuffer(bytes.length + 16)) {
            for (byte b : bytes) {
                in.putByte(b);
            }
            in.position(0);
            in.limit(bytes.length);

            // Position 1: the message-type byte has been read by the caller.
            TtcDescribe.Parsed parsed = TtcDescribe.read(in, 1);
            List<OracleColumn> columns = parsed.columns();

            assertEquals(2, columns.size());

            OracleColumn answer = columns.get(0);
            assertEquals("ANSWER", answer.name());
            assertEquals(OracleColumn.TYPE_NUMBER, answer.type());
            assertEquals(OracleColumn.SCALE_UNDECLARED, answer.scale(),
                    "a NUMBER without a declared scale reports -127, not 0");
            // Zero, not six: six was the length of the name, which the first
            // version of the parser read into this field. A computed NUMBER
            // has no declared maximum size.
            assertEquals(0, answer.maxSize());
            assertTrue(answer.nullable());

            OracleColumn text = columns.get(1);
            assertEquals("TEXT", text.name());
            assertEquals(OracleColumn.TYPE_CHAR, text.type(),
                    "a literal in a query is a CHAR, not a VARCHAR");
            assertEquals(873, text.charset(), "AL32UTF8");
            assertEquals(3, text.bufferSize());
            assertTrue(text.isText());

            // The message ends with a trailer; right after it comes the row
            // header. If the trailer were miscounted, this would be some other
            // byte - and every row after it would be read shifted.
            assertEquals(6, in.getByte(parsed.end()) & 0xff,
                    "the row header does not follow the description");
        }
    }
}
