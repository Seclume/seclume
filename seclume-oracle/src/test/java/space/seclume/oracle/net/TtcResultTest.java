package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * The whole answer to a query, against the <b>recording</b>.
 *
 * <p>The bytes are a {@code python-oracledb} exchange with Oracle Free 23ai for
 * {@code select 42 as answer, 'abc' as text from dual}. Everything has to fall
 * into place at once here: the column description, the row header with its bit
 * vector, the row itself, and Oracle's number format. One field miscounted
 * anywhere and the values come out as plausible nonsense - which is why the
 * expected values are spelled out rather than merely counted.
 */
class TtcResultTest {

    private static final String RECORDED =
            "10179778C2F43A22195C26D0F8A724BB1E90787E090708072D01050102820200008101"
            + "0200000000000000000106010606414E5357455200000000000000000000608000000103"
            + "00000000020369010103023FFE01040104045445585400000101000000000000000107"
            + "07787E090708072D00021FE801020102000622010200010200000007"
            + "02C12B03616263";

    @Test
    void readsTheColumnsAndTheRowOfTheRecordedAnswer() throws Exception {
        byte[] bytes = new byte[RECORDED.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(RECORDED.substring(i * 2, i * 2 + 2), 16);
        }
        try (WireBuffer in = new WireBuffer(bytes.length + 16)) {
            for (byte b : bytes) {
                in.putByte(b);
            }
            in.position(0);
            in.limit(bytes.length);

            List<String> values = new ArrayList<>();
            TtcResult result = new TtcResult();
            result.read(in, 0, bytes.length, row -> {
                for (int i = 0; i < row.columnCount(); i++) {
                    values.add(row.text(i));
                }
                // The number also has to come out without a detour through text.
                values.add(Long.toString(row.number(0)));
            });

            assertEquals(List.of("ANSWER", "TEXT"),
                    result.columns().stream().map(OracleColumn::name).toList());
            assertEquals(1, result.rowCount());
            assertEquals(List.of("42", "abc", "42"), values);
        }
    }
}
