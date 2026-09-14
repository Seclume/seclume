package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Oracle's number format, against <b>real</b> encodings.
 *
 * <p>The byte sequences below are not derived from a description, they are what
 * the server itself says: {@code select dump(42) from dual} answers
 * {@code Typ=2 Len=2: 193,43}. That makes these vectors ground truth rather
 * than a repetition of my own assumption - which for a format this odd is the
 * difference between a test and a mirror.
 */
class OracleNumberTest {

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
        "193;2;51,                     1.5",
        "62;100;51;102,                -1.5",
        "192;26,                       0.25",
        "202;2;24;46;68;90;2;24;46;68;90, 1234567890123456789",
        "191;2,                        0.0001",
        "195;100;100;100,              999999",
        "193;4;15;16;91,               3.14159",
    })
    void decodesWhatTheServerEncodes(String bytes, String expected) {
        try (Arena arena = Arena.ofConfined()) {
            String[] parts = bytes.split(";");
            MemorySegment value = arena.allocate(parts.length);
            for (int i = 0; i < parts.length; i++) {
                value.set(ValueLayout.JAVA_BYTE, i, (byte) Integer.parseInt(parts[i].trim()));
            }
            assertEquals(expected, OracleNumber.toText(value, 0, parts.length));
        }
    }

    /** getLong cuts the decimals off, as JDBC prescribes - it does not round. */
    @ParameterizedTest(name = "{1} -> {0}")
    @CsvSource({
        "128,               0",
        "193;2,             1",
        "62;100;102,        -1",
        "193;43,            42",
        "194;2,             100",
        "195;2;24;46,       12345",
        "60;100;78;56;102,  -12345",
        "193;2;51,          1",
        "62;100;51;102,     -1",
        "192;26,            0",
        "195;100;100;100,   999999",
        "202;2;24;46;68;90;2;24;46;68;90, 1234567890123456789",
    })
    void readsIntegersWithoutADetour(String bytes, long expected) {
        try (Arena arena = Arena.ofConfined()) {
            String[] parts = bytes.split(";");
            MemorySegment value = arena.allocate(parts.length);
            for (int i = 0; i < parts.length; i++) {
                value.set(ValueLayout.JAVA_BYTE, i, (byte) Integer.parseInt(parts[i].trim()));
            }
            assertEquals(expected, OracleNumber.toLong(value, 0, parts.length));
        }
    }
}
