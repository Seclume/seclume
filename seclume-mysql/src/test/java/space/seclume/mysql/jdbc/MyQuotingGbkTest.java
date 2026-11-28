package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * In GBK, Big5 or SJIS a lead byte takes the byte after it: the escaping
 * backslash in front of a quote became part of a character, and the quote
 * ended the literal. A value beyond ASCII goes as {@code _utf8mb4 X'...'} -
 * hex digits are ASCII in every client character set, and nothing can join.
 */
class MyQuotingGbkTest {

    private static final String ATTACK = "中\\' or 1=1 -- ";

    @Test
    void noMultiByteClientCharsetJoinsAByteWithTheEscape() {
        String literal = MyQuoting.literal(ATTACK, false);
        assertTrue(literal.startsWith("_utf8mb4 X'"), literal);
        String digits = literal.substring("_utf8mb4 X'".length(), literal.length() - 1);
        assertTrue(digits.matches("[0-9a-f]+"), literal);
        for (String charset : new String[] {"GBK", "Big5", "Shift_JIS"}) {
            // What the server reads in that charset is the hex text itself.
            String read = new String(literal.getBytes(StandardCharsets.US_ASCII),
                    Charset.forName(charset));
            assertEquals(literal, read, charset);
        }
        assertEquals(ATTACK, new String(java.util.HexFormat.of().parseHex(digits),
                StandardCharsets.UTF_8), "the value itself, unchanged");
    }

    @Test
    void anNCharLiteralBeyondAsciiIsHexWithoutN() {
        String literal = MyQuoting.literal("été", false);
        assertTrue(literal.startsWith("_utf8mb4 X'"), literal);
        assertFalse(literal.startsWith("N"), literal);
    }

    @Test
    void asciiStaysAQuotedLiteral() {
        assertEquals("'it''s \\\\ fine'", MyQuoting.literal("it's \\ fine", false));
        assertEquals("'it''s \\ fine'", MyQuoting.literal("it's \\ fine", true));
    }
}
