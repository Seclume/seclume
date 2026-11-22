package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Locale;
import java.util.Random;

import org.junit.jupiter.api.Test;

import space.seclume.QueryFingerprint.Dialect;

/**
 * A backslash before a quote means one thing in one dialect and another in
 * the next - and in MySQL and PostgreSQL it depends on a setting as well. It
 * used to be taken for an escape everywhere: {@code 'C:\dir\'} then ran on to
 * the quote that opens the next literal, whose contents came out as words,
 * and an identifier {@code "col\"} copied the rest of the statement - its
 * literals with it - verbatim.
 */
class QueryFingerprintBackslashTest {

    private static final String SECRET = "zqxdecoysecret";

    private static void hidden(String sql, Dialect dialect) {
        String fingerprint = QueryFingerprint.of(sql, dialect);
        assertFalse(fingerprint.toLowerCase(Locale.ROOT).contains(SECRET),
                dialect + ": " + sql + " -> " + fingerprint);
    }

    @Test
    void aLiteralEndingInABackslashDoesNotUncoverTheNextOne() {
        for (Dialect dialect : Dialect.values()) {
            hidden("INSERT INTO creds(path, pw) VALUES ('C:\\data\\', '" + SECRET + "')", dialect);
            hidden("BACKUP DATABASE app TO DISK = 'D:\\backup\\' WITH PASSWORD = '" + SECRET + "'",
                    dialect);
            // MySQL with NO_BACKSLASH_ESCAPES, PostgreSQL with standard_conforming_strings
            hidden("SELECT 'a\\' , '" + SECRET + "'", dialect);
            // and the other reading: the backslash escapes, the literal goes on
            hidden("SELECT 'a\\' , ' || '" + SECRET + "'", dialect);
        }
    }

    @Test
    void aQuotedIdentifierEndingInABackslashCopiesNothingAfterIt() {
        for (Dialect dialect : new Dialect[] {Dialect.POSTGRESQL, Dialect.SQLSERVER, Dialect.ORACLE}) {
            String fingerprint = QueryFingerprint.of("SELECT \"col\\\" , '" + SECRET + "' FROM t", dialect);
            assertEquals("select \"col\\\" , ? from t", fingerprint);
        }
        assertEquals("select `col\\` , ? from t",
                QueryFingerprint.of("SELECT `col\\` , '" + SECRET + "' FROM t", Dialect.MYSQL));
    }

    @Test
    void escapesThatAreCertainStillReadAsSuch() {
        // E'...' escapes for certain: the statement goes on after it (values collapse to one ?).
        assertEquals("select ? from t",
                QueryFingerprint.of("SELECT E'it\\'s', 'two' FROM t", Dialect.POSTGRESQL));
        assertEquals("select ? from t where a = ?",
                QueryFingerprint.of("SELECT 'C:\\\\dir\\\\' FROM t WHERE a = 'b'", Dialect.MYSQL));
    }

    // ---- random statements, each written by the rules of a real dialect --------------

    private static String content(Random random) {
        String alphabet = "ab \\'\"`/*-#$";
        StringBuilder text = new StringBuilder();
        for (int i = random.nextInt(6); i > 0; i--) {
            text.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return text.toString();
    }

    /** A literal holding {@code value} as grammar {@code g} writes one. */
    private static String literal(String value, int g) {
        return switch (g) {
            case 0 -> "'" + value.replace("'", "''") + "'";                         // no backslash escape
            case 1 -> "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'";  // MySQL, PostgreSQL legacy
            case 2 -> "E'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"; // PostgreSQL E''
            default -> "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; // MySQL "..."
        };
    }

    private static String identifier(Random random, int g) {
        String name = "c" + (char) ('a' + random.nextInt(26)) + (random.nextBoolean() ? "\\" : "");
        return g == 3 ? "`" + name + "`" : "\"" + name + "\"";
    }

    @Test
    void noLiteralOfARandomStatementIsInItsFingerprint() {
        Random random = new Random(20261122L);
        for (int n = 0; n < 20_000; n++) {
            int g = random.nextInt(4);
            StringBuilder sql = new StringBuilder("select ");
            int parts = 1 + random.nextInt(4);
            int secretAt = random.nextInt(parts);
            for (int p = 0; p < parts; p++) {
                sql.append(p > 0 ? ", " : "");
                if (p == secretAt) {
                    sql.append(literal(content(random) + SECRET + content(random), g));
                } else if (random.nextInt(3) == 0) {
                    sql.append(identifier(random, g));
                } else {
                    sql.append(literal(content(random), g));
                }
            }
            sql.append(" from t");
            for (Dialect dialect : Dialect.values()) {
                // "..." is a string only where the dialect says so.
                if (g == 3 && dialect != Dialect.MYSQL && dialect != Dialect.GENERIC) {
                    continue;
                }
                hidden(sql.toString(), dialect);
            }
        }
    }
}
