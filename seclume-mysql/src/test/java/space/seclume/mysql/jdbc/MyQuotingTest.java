package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * Literals and identifiers as MySQL reads them. The literals are checked by
 * reading them back the way the server does - a small model of its string
 * syntax - so that the test says what the quoting is for: the value comes
 * back whole, and nothing after it is SQL.
 */
class MyQuotingTest {

    /**
     * Reads a string literal at the start of {@code sql} as MySQL does and
     * returns its value, then a NUL, then whatever follows the literal.
     */
    private static String read(String sql, boolean noBackslashEscapes) {
        assertEquals('\'', sql.charAt(0));
        StringBuilder value = new StringBuilder();
        int i = 1;
        while (true) {
            char c = sql.charAt(i);
            if (c == '\\' && !noBackslashEscapes) {
                value.append(sql.charAt(i + 1));        // the escapes used here stand for themselves
                i += 2;
            } else if (c == '\'' && i + 1 < sql.length() && sql.charAt(i + 1) == '\'') {
                value.append('\'');
                i += 2;
            } else if (c == '\'') {
                return value + "\0" + sql.substring(i + 1);
            } else {
                value.append(c);
                i++;
            }
        }
    }

    private static final String[] VALUES = {
        "plain", "", "it's", "''", "\\", "\\\\", "\\' or 1=1 -- ", "a\\'b", "ends with \\",
        "'; drop table t; -- ", "\\\\' or ''='", "tab\there", "ümlaut \\ and ' both"};

    @Test
    void aLiteralIsReadBackWholeWithNothingAfterItInEitherMode() {
        for (boolean noBackslashEscapes : new boolean[] {false, true}) {
            for (String value : VALUES) {
                String literal = MyQuoting.literal(value, noBackslashEscapes);
                assertEquals(value + "\0", read(literal, noBackslashEscapes),
                        literal + (noBackslashEscapes ? " (NO_BACKSLASH_ESCAPES)" : ""));
            }
        }
    }

    /** What JDBC's default makes of a backslash before a quote: the rest is SQL. */
    @Test
    void doublingQuotesAloneLetsABackslashEndTheString() {
        String value = "\\' or 1=1 -- ";
        String standard = "'" + value.replace("'", "''") + "'";
        String read = read(standard, false);
        assertEquals("'", read.substring(0, read.indexOf('\0')));
        assertEquals(" or 1=1 -- '", read.substring(read.indexOf('\0') + 1),
                "the control: this is the injection the driver's own quoting prevents");
        assertEquals("'\\\\'' or 1=1 -- '", MyQuoting.literal(value, false));
        assertEquals("'\\'' or 1=1 -- '", MyQuoting.literal(value, true));
    }

    @Test
    void anIdentifierGoesInBackticks() throws Exception {
        assertEquals("name", MyQuoting.identifier("name", false));
        assertEquals("`name`", MyQuoting.identifier("name", true));
        assertEquals("`my col`", MyQuoting.identifier("my col", false));
        assertEquals("`a``b`", MyQuoting.identifier("a`b", false));
        assertEquals("`select`", MyQuoting.identifier("select", true));
        assertEquals("`1st`", MyQuoting.identifier("1st", false));
        assertEquals("`a\"b`", MyQuoting.identifier("a\"b", false));
        assertEquals("`quoted``already`", MyQuoting.identifier("`quoted``already`", true));
        assertThrows(SQLException.class, () -> MyQuoting.identifier("", true));
        assertThrows(SQLException.class, () -> MyQuoting.identifier("a\0b", true));
        assertThrows(SQLException.class, () -> MyQuoting.identifier("`a`b`", true));
        assertThrows(SQLException.class, () -> MyQuoting.identifier("``", true));
        assertThrows(NullPointerException.class, () -> MyQuoting.identifier(null, true));
    }

    @Test
    void whatNeedsNoQuotes() {
        assertTrue(MyQuoting.simple("name"));
        assertTrue(MyQuoting.simple("Name_2"));
        assertFalse(MyQuoting.simple("_name"));
        assertFalse(MyQuoting.simple("2name"));
        assertFalse(MyQuoting.simple("my col"));
        assertFalse(MyQuoting.simple("näme"));
        assertFalse(MyQuoting.simple(""));
        assertTrue(MyQuoting.simple("a".repeat(64)));
        assertFalse(MyQuoting.simple("a".repeat(65)));
    }
}
