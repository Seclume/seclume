package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Context.ROW_ID was String.valueOf(id): a byte[] id became its identity in
 * memory, "[B@1a2b...", and no value opened; a BigDecimal was 17 or 17.0
 * depending on the driver. Binary ids are their bytes, decimals have no
 * trailing zeros, and text and integer ids are as they were.
 */
class RowIdContextTest {

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void binaryIdsAreTheirBytes() {
        byte[] id = {1, 2, 3, (byte) 0xff};
        assertArrayEquals(id, ColumnRotation.rowIdContext(id));
        assertArrayEquals(ColumnRotation.rowIdContext(new byte[] {1, 2, 3, (byte) 0xff}),
                ColumnRotation.rowIdContext(id.clone()), "two copies of one id differed");
    }

    @Test
    void decimalsDoNotDependOnTheDriversScale() {
        assertArrayEquals(utf8("17"), ColumnRotation.rowIdContext(new BigDecimal("17.0")));
        assertArrayEquals(utf8("17"), ColumnRotation.rowIdContext(new BigDecimal("17")));
        assertArrayEquals(utf8("1700"), ColumnRotation.rowIdContext(new BigDecimal("1.7E+3")));
        assertArrayEquals(utf8("0"), ColumnRotation.rowIdContext(new BigDecimal("0.00")));
    }

    @Test
    void textAndIntegersAreAsBefore() {
        assertArrayEquals(utf8("42"), ColumnRotation.rowIdContext(42L));
        assertArrayEquals(utf8("a-b"), ColumnRotation.rowIdContext("a-b"));
    }
}
