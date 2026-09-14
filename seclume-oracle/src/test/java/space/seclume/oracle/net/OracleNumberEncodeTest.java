package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.internal.WireBuffer;

/**
 * Writing Oracle's {@code NUMBER} - against the same vectors that the reader
 * is checked with.
 *
 * <p>The expected bytes are not invented here: they come from
 * {@code select dump(x) from dual} on a real server, the same list
 * {@code OracleNumberTest} reads. A writer checked against its own reader
 * proves only that the two agree; checked against the server's own dump it
 * proves the format.
 */
class OracleNumberEncodeTest {

    @ParameterizedTest(name = "{1} -> {0}")
    @CsvSource({
        "128,                          0",
        "193;2,                        1",
        "62;100;102,                   -1",
        "193;43,                       42",
        "62;59;102,                    -42",
        "194;2,                        100",
        "195;2;24;46,                  12345",
        "60;100;78;56;102,             -12345",
        "202;2;24;46;68;90;2;24;46;68;90, 1234567890123456789",
        "195;100;100;100,              999999",
        "193;8,                        7",
    })
    void writesWholeNumbers(String expected, long value) {
        try (WireBuffer out = new WireBuffer(32)) {
            OracleNumber.encode(out, value);
            assertEquals(expected, dump(out));
        }
    }

    @ParameterizedTest(name = "{1} -> {0}")
    @CsvSource({
        "128,                          0",
        "128,                          0.000",
        "193;2;51,                     1.5",
        "62;100;51;102,                -1.5",
        "192;26,                       0.25",
        "191;2,                        0.0001",
        "193;4;15;16;91,               3.14159",
        "195;2;24;46,                  12345",
        "62;100;102,                   -1",
    })
    void writesDecimals(String expected, String value) {
        try (WireBuffer out = new WireBuffer(32)) {
            OracleNumber.encodeText(out, value);
            assertEquals(expected, dump(out));
        }
    }

    /**
     * What is written has to read back as the same number - the two directions
     * are independent implementations of the same rules.
     */
    @ParameterizedTest
    @CsvSource({"0", "1", "-1", "42", "-42", "100", "12345", "-12345",
                "999999", "1234567890123456789", "-9223372036854775808",
                "9223372036854775807"})
    void readsBackWhatItWrote(long value) {
        try (WireBuffer out = new WireBuffer(32)) {
            OracleNumber.encode(out, value);
            int length = out.getByte(0) & 0xff;
            assertEquals(value, OracleNumber.toLong(out.segment(), 1, length));
        }
    }

    /** The bytes as the test vectors spell them: unsigned, separated by ";". */
    private static String dump(WireBuffer out) {
        StringBuilder text = new StringBuilder();
        int length = out.getByte(0) & 0xff;
        for (int i = 0; i < length; i++) {
            if (i > 0) {
                text.append(';');
            }
            text.append(out.getByte(1 + i) & 0xff);
        }
        return text.toString();
    }
}
