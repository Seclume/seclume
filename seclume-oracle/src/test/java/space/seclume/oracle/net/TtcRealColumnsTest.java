package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * Answers over real table columns - the shapes that a query over {@code dual}
 * never produces.
 *
 * <p>Three findings are nailed down here, and each of them cost rows rather
 * than raising an error:
 *
 * <ul>
 *   <li>The <b>bit vector</b> that arrives as a message of its own carries no
 *       length. It is one bit per column, rounded up to whole bytes. Reading a
 *       length in front of it swallows the first byte of the next row.</li>
 *   <li>A <b>LONG</b> is described with a buffer size of zero, like an untyped
 *       {@code null} in the select list - but it does send bytes, and behind
 *       them two more fields: whether it was null, as a signed number, and a
 *       return code that is 1405 for a null one.</li>
 *   <li>{@code ORA-01403} at the end is not an error but the end of the
 *       result. Only that number means finished; a zero means the server has
 *       more and is waiting to be asked.</li>
 * </ul>
 *
 * <p>Both are exchanges with Oracle Free 23ai, produced
 * and not retyped: a hand-copied hexdump once lost three bytes and the test
 * that compared against it stayed green.
 */
class TtcRealColumnsTest {

    /** {@code select username, user_id from all_users} - 30 rows in one answer. */
    private static final String USERS =
            "10175E0E1FCBEA098F53BCFE984D28B252CD787E0908102A2C019601028201800000"
                    + "018000000000020369010180023FFE0008010808555345524E414D45000000000000"
                    + "0000000002000081011600000000000000000007010707555345525F494400000101"
                    + "00000000000000010707787E090810372B00021FE8010A010A000622010200016400"
                    + "000007035359530180070641554453595302C10915010203070653595354454D02C1"
                    + "0A1501020307095359534241434B555006C516303125121501020307055359534447"
                    + "06C516303125131501020307055359534B4D06C51630312514150102030706535953"
                    + "52414306C516303125151501020307054F55544C4E02C10E15010203070656454353"
                    + "595302C1121501020307074241415353595302C11315010203071147534D41444D49"
                    + "4E5F494E5445524E414C02C11B15010203070747534D5553455202C11C1501020307"
                    + "0B474753484152454443415002C11D15010203070344495002C11E15010203070758"
                    + "53244E554C4C06C5163031252715010203071652454D4F54455F5343484544554C45"
                    + "525F4147454E5402C12E15010203070944425346575553455202C12F150102030707"
                    + "53595324554D4602C13C15010203070944475044425F494E5402C143150102030706"
                    + "4442534E4D5002C150150102030709415050514F5353595302C15115010203070A47"
                    + "534D4341545553455202C157150102030705474753595302C1581501020307035844"
                    + "4203C20205150102030709414E4F4E594D4F555303C2020615010203070544565359"
                    + "5305C4021C645B15010203070850444241444D494E03C202241501020307074C4241"
                    + "4353595303C2022115010203070344564603C2022315010203070D5A45524F4C4541"
                    + "4B5F5445535403C202250801060323CF1A0001010000000000000401010194011E02"
                    + "057B000001010003002000000000000000000000030001010000000002057B011E01"
                    + "0300194F52412D30313430333A206E6F206461746120666F756E640A1D";

    /** The description of {@code select 7 as a, data_default, 8 as b ...}. */
    private static final String LONG_DESCRIPTION =
            "101705A01DB7555E1C76025BF8512240F66D787E090810372B000103820200008101"
                    + "02000000000000000001010101014100000000000000000000088000000000000000"
                    + "0203690100023FFE010C010C0C444154415F44454641554C54000001010000000000"
                    + "00000200008101020000000000000000010101010142000001020000000000000001"
                    + "0707787E090810372B00021FE80000000801060323CF170001010000000000000401"
                    + "01018F00000000010101290300000000000000000000000003000101000000000000"
                    + "0103001D";

    /** The rows of that query - two of them, with a null LONG in the middle. */
    private static final String LONG_ROWS =
            "062201030001640000000702C10800810102057D02C1090702C10800810102057D02"
                    + "C1090401010190010202057B00000101000300000000000000000000000004000000"
                    + "00000002057B0102010300194F52412D30313430333A206E6F206461746120666F75"
                    + "6E640A1D";

    private static byte[] bytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    private static WireBuffer buffer(byte[] bytes) {
        WireBuffer in = new WireBuffer(bytes.length + 16);
        for (byte b : bytes) {
            in.putByte(b);
        }
        in.position(0);
        in.limit(bytes.length);
        return in;
    }

    @Test
    void readsEveryRowOfAnAnswerWithBitVectors() throws Exception {
        byte[] bytes = bytes(USERS);
        try (WireBuffer in = buffer(bytes)) {
            List<String> names = new ArrayList<>();
            TtcResult result = new TtcResult();
            result.read(in, 0, bytes.length, row -> names.add(row.text(0)));

            assertEquals(List.of("USERNAME", "USER_ID"),
                    result.columns().stream().map(OracleColumn::name).toList());
            assertEquals(30, result.rowCount(), "one row lost means the bit vector was misread");
            assertEquals(30, names.size());
            assertEquals("SYS", names.get(0));
            // A name every Oracle has, so the assertion says "these are real
            // rows off a real server" without pinning the test to one account.
            assertTrue(names.contains("SYSTEM"));
            assertEquals(TtcResult.ORA_NO_DATA_FOUND, result.errorNumber());
            assertTrue(result.isExhausted());
            assertTrue(!result.isFailure(), "1403 is the end of the result, not a failure");
        }
    }

    /**
     * The description comes with the execute call and the rows with the fetch
     * that follows - so the second answer has to be told what the columns are.
     */
    @Test
    void readsARowWithANullLong() throws Exception {
        byte[] description = bytes(LONG_DESCRIPTION);
        byte[] rows = bytes(LONG_ROWS);
        try (WireBuffer first = buffer(description);
             WireBuffer second = buffer(rows)) {
            TtcResult described = new TtcResult();
            described.read(first, 0, description.length, null);
            List<OracleColumn> columns = described.columns();
            assertEquals(3, columns.size());
            assertEquals(OracleColumn.TYPE_LONG, columns.get(1).type());
            assertEquals(0, columns.get(1).bufferSize(),
                    "a LONG is described like an untyped null - and is not one");
            assertEquals(0, described.rowCount(), "the rows come with the fetch");

            List<String> values = new ArrayList<>();
            TtcResult result = new TtcResult(columns);
            result.read(second, 0, rows.length, row -> {
                values.add(Long.toString(row.number(0)));
                values.add(row.isNull(1) ? "null" : row.text(1));
                values.add(Long.toString(row.number(2)));
            });

            assertEquals(2, result.rowCount());
            assertEquals(List.of("7", "null", "8", "7", "null", "8"), values);
        }
    }
}
