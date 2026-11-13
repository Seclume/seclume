package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The literals {@link PgDatabaseMetaData} puts the application's names and
 * patterns into, read the way PostgreSQL's lexer reads a string constant -
 * with {@code standard_conforming_strings} on, and off.
 *
 * <p>Review round 4: the literal was {@code '...'} with the quotes doubled.
 * With the setting off - a role's, a database's, a session's choice - a
 * backslash in it escapes the quote after it, so {@code \' or true --} ended
 * the literal early and the rest was SQL: {@code getTables} with that pattern
 * listed every table of every schema. The control below shows the old
 * quoting doing exactly that against the same model.
 */
class MetaDataLiteralTest {

    private static final List<String> VALUES = List.of(
            "seclume_meta", "", "'", "''", "\\", "\\\\", "\\'", "\\'' or true --",
            "\\' or true --", "a'b\\c", "x\\nE'y", "%\\_%", "o'neil\\", "été ☃",
            "$seclume$", "'; drop table t; --");

    /** A string constant at the start of {@code sql}: its value, and what follows it. */
    private record Read(String value, String rest) {
    }

    /**
     * PostgreSQL's lexer for one string constant (the parts that matter for
     * where it ends): {@code E'...'} reads backslash escapes always,
     * {@code '...'} only when {@code standard_conforming_strings} is off; a
     * doubled quote is a quote either way.
     */
    private static Read read(String sql, boolean conforming) {
        boolean escapes;
        int at;
        if (sql.startsWith("E'") || sql.startsWith("e'")) {
            escapes = true;
            at = 2;
        } else if (sql.startsWith("'")) {
            escapes = !conforming;
            at = 1;
        } else {
            throw new AssertionError("not a string constant: " + sql);
        }
        StringBuilder value = new StringBuilder();
        while (at < sql.length()) {
            char c = sql.charAt(at);
            if (c == '\\' && escapes && at + 1 < sql.length()) {
                // \\ and \' are what matter; any other escape is not made by literal().
                value.append(sql.charAt(at + 1));
                at += 2;
            } else if (c == '\'') {
                if (at + 1 < sql.length() && sql.charAt(at + 1) == '\'') {
                    value.append('\'');
                    at += 2;
                } else {
                    return new Read(value.toString(), sql.substring(at + 1));
                }
            } else {
                value.append(c);
                at++;
            }
        }
        throw new AssertionError("the literal never ends: " + sql);
    }

    @Test
    void aLiteralMeansItsValueWhateverTheServersSetting() {
        for (String value : VALUES) {
            String literal = PgDatabaseMetaData.literal(value);
            for (boolean conforming : new boolean[] {true, false}) {
                Read read = read(literal, conforming);
                assertEquals(value, read.value(), literal + " with standard_conforming_strings "
                        + (conforming ? "on" : "off"));
                assertEquals("", read.rest(), literal + " ends where it was made to end");
            }
        }
    }

    @Test
    void theOldQuotingLeftItsLiteralWithTheSettingOff() {
        // The negative control: the model finds what the old code did.
        String old = "'" + "\\' or true --".replace("'", "''") + "'";
        Read read = read(old, false);
        assertEquals("'", read.value());
        assertTrue(read.rest().startsWith(" or true --"), read.rest());
        // ... and nothing with the setting on, which is why it went unseen.
        assertEquals("", read(old, true).rest());
    }
}
