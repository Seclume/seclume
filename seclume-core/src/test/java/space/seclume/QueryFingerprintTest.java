package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.Test;

import space.seclume.QueryFingerprint.Dialect;

/**
 * A fingerprint has two jobs, and only one of them is allowed to fail.
 *
 * <p>It should group executions of one statement under one readable name.
 * That is useful, and getting it slightly wrong costs a worse report.
 *
 * <p>It must never carry a value. That is the property the whole thing exists
 * for, and getting it wrong once puts a password in a log - a place secrets
 * are kept far longer and read far more widely than any heap dump. So the
 * first half of this class is a single test repeated over every quoting form
 * of every dialect, asserting that a marker planted in a literal does not
 * come out the other end.
 */
class QueryFingerprintTest {

    /** Unmistakable, and unlike anything that could legitimately survive. */
    private static final String SECRET = "hunter2swordfishXY";

    /**
     * Every shape a value can take, in every dialect that has it.
     *
     * <p>The list is the test. Adding a quoting form to the fingerprinter
     * without adding it here is how the property quietly stops holding, so
     * these are written as statements rather than as fragments - the way they
     * would actually arrive.
     */
    private static List<String[]> literalForms() {
        List<String[]> forms = new ArrayList<>();
        for (Dialect dialect : Dialect.values()) {
            String name = dialect.name();
            forms.add(new String[] {name, "select * from t where a = '" + SECRET + "'"});
            forms.add(new String[] {name, "insert into t values ('" + SECRET + "', 1)"});
            forms.add(new String[] {name, "select '" + SECRET + "' || x from t"});
            forms.add(new String[] {name, "select * from t where a = 'it''s " + SECRET + "'"});
            forms.add(new String[] {name, "select * from t /* " + SECRET + " */ where a = 1"});
            forms.add(new String[] {name, "select * from t -- " + SECRET + "\n where a = 1"});
            forms.add(new String[] {name, "select * from t where a = N'" + SECRET + "'"});
            forms.add(new String[] {name, "select * from t where a = X'" + SECRET + "'"});
            // An unterminated literal: a statement the database would refuse,
            // which is no reason to print what is inside it.
            forms.add(new String[] {name, "select * from t where a = '" + SECRET});
        }
        forms.add(new String[] {"POSTGRESQL",
                "select * from t where a = $tag$" + SECRET + "$tag$"});
        forms.add(new String[] {"POSTGRESQL",
                "select * from t where a = $$" + SECRET + "$$"});
        forms.add(new String[] {"POSTGRESQL",
                "select * from t where a = E'x\\'" + SECRET + "'"});
        forms.add(new String[] {"ORACLE", "select * from t where a = q'[" + SECRET + "]'"});
        forms.add(new String[] {"ORACLE", "select * from t where a = q'{" + SECRET + "}'"});
        forms.add(new String[] {"MYSQL", "select * from t where a = \"" + SECRET + "\""});
        forms.add(new String[] {"MYSQL", "select * from t where a = '" + SECRET + "\\''"});
        forms.add(new String[] {"MYSQL", "select * from t # " + SECRET + "\n where a = 1"});
        forms.add(new String[] {"GENERIC", "select * from t where a = \"" + SECRET + "\""});
        forms.add(new String[] {"GENERIC", "select * from t where a = `" + SECRET + "`"});
        forms.add(new String[] {"GENERIC", "select * from t where a = [" + SECRET + "]"});
        return forms;
    }

    @Test
    void noLiteralEverSurvives() {
        List<String> leaked = new ArrayList<>();
        for (String[] form : literalForms()) {
            Dialect dialect = Dialect.valueOf(form[0]);
            String fingerprint = QueryFingerprint.of(form[1], dialect);
            if (fingerprint.toLowerCase(Locale.ROOT).contains(SECRET.toLowerCase(Locale.ROOT))) {
                leaked.add(dialect + ": " + form[1] + "\n      -> " + fingerprint);
            }
        }
        assertTrue(leaked.isEmpty(), () -> "a value came through the fingerprint:\n    "
                + String.join("\n    ", leaked));
    }

    /**
     * And numbers too, which are easy to think of as harmless.
     *
     * <p>They are not: an account number, a national identifier and a
     * transaction amount are all numbers, and the last one is the reason a
     * fingerprint with literals in it cannot be shared with a support team.
     */
    @Test
    void noNumberEverSurvives() {
        for (String sql : List.of(
                "select * from t where id = 4711",
                "select * from t where amount = 1234.56",
                "select * from t where amount = -1234.56e-7",
                "select * from t where id = 0x4711",
                "select * from t limit 100 offset 900")) {
            String fingerprint = QueryFingerprint.of(sql, Dialect.POSTGRESQL);
            assertFalse(fingerprint.matches(".*\\d.*"),
                    sql + "\n      -> " + fingerprint);
        }
    }

    // ---------------------------------------------------------- the readable half --

    @Test
    void keepsTheShapeAndDropsTheValues() {
        assertEquals("select * from customer where id = ? and name = ?",
                QueryFingerprint.of("select * from customer where id = 42 and name = 'alice'",
                        Dialect.POSTGRESQL));
    }

    /** Two executions of one statement are one fingerprint. */
    @Test
    void groupsExecutionsOfOneStatement() {
        String one = QueryFingerprint.of("select * from t where a = 1", Dialect.POSTGRESQL);
        String other = QueryFingerprint.of("select * from t where a = 999", Dialect.POSTGRESQL);
        assertEquals(one, other);
        assertEquals(QueryFingerprint.idOf("select * from t where a = 1", Dialect.POSTGRESQL),
                QueryFingerprint.idOf("select * from t where a = 999", Dialect.POSTGRESQL));
    }

    /** And two different statements are not. */
    @Test
    void doesNotGroupDifferentStatements() {
        assertNotEquals(
                QueryFingerprint.idOf("select * from t where a = 1", Dialect.POSTGRESQL),
                QueryFingerprint.idOf("select * from u where a = 1", Dialect.POSTGRESQL));
    }

    /**
     * A list of values is one hole, however long.
     *
     * <p>The shape that otherwise fills a slow-query report with thousands of
     * single-execution entries that are all the same query.
     */
    @Test
    void collapsesListsOfValues() {
        String three = QueryFingerprint.of("select * from t where id in (1, 2, 3)",
                Dialect.POSTGRESQL);
        String many = QueryFingerprint.of(
                "select * from t where id in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)",
                Dialect.POSTGRESQL);
        assertEquals("select * from t where id in (?)", three);
        assertEquals(three, many);
    }

    /** Whitespace and case are not part of what a statement is. */
    @Test
    void normalisesLayoutAndCase() {
        assertEquals(
                QueryFingerprint.of("SELECT  *\n  FROM   t\n WHERE a = 1", Dialect.POSTGRESQL),
                QueryFingerprint.of("select * from t where a = 1", Dialect.POSTGRESQL));
    }

    /** Placeholders are already holes - in every spelling a server uses. */
    @Test
    void everyPlaceholderSpellingIsAHole() {
        assertEquals("select * from t where a = ?",
                QueryFingerprint.of("select * from t where a = ?", Dialect.POSTGRESQL));
        assertEquals("select * from t where a = ?",
                QueryFingerprint.of("select * from t where a = $1", Dialect.POSTGRESQL));
        assertEquals("select * from t where a = ?",
                QueryFingerprint.of("select * from t where a = :name", Dialect.ORACLE));
        assertEquals("select * from t where a = ?",
                QueryFingerprint.of("select * from t where a = @p1", Dialect.SQLSERVER));
    }

    /**
     * An identifier is structure and stays - where the dialect makes it
     * unambiguous.
     */
    @Test
    void keepsQuotedIdentifiersWhereTheyAreIdentifiers() {
        assertEquals("select \"Order\" from t where a = ?",
                QueryFingerprint.of("select \"Order\" from t where a = 1", Dialect.POSTGRESQL));
        assertEquals("select `Order` from t where a = ?",
                QueryFingerprint.of("select `Order` from t where a = 1", Dialect.MYSQL));
        assertEquals("select [Order] from t where a = ?",
                QueryFingerprint.of("select [Order] from t where a = 1", Dialect.SQLSERVER));
    }

    /**
     * And is given up where it is not.
     *
     * <p>In MySQL {@code "Order"} is a string unless the server was started
     * with {@code ANSI_QUOTES}, which nothing here can know. Losing a column
     * name is the price of not printing a value; the trade only goes this
     * way.
     */
    @Test
    void givesUpTheIdentifierWhenTheDialectIsAmbiguous() {
        assertEquals("select ? from t", QueryFingerprint.of("select \"Order\" from t",
                Dialect.MYSQL));
        assertEquals("select ? from t", QueryFingerprint.of("select \"Order\" from t",
                Dialect.GENERIC));
    }

    /** Logging code does not get to throw. */
    @Test
    void neverRefuses() {
        for (String sql : List.of("", "   ", "'", "\"", "/*", "$$", "q'[", "select", "((((",
                "-- only a comment", "\0")) {
            assertTrue(QueryFingerprint.of(sql, Dialect.POSTGRESQL) != null, sql);
            assertTrue(QueryFingerprint.of(sql, Dialect.MYSQL) != null, sql);
            assertTrue(QueryFingerprint.of(sql, Dialect.ORACLE) != null, sql);
            assertTrue(QueryFingerprint.of(sql, Dialect.SQLSERVER) != null, sql);
            assertTrue(QueryFingerprint.of(sql) != null, sql);
        }
    }

    /** A statement nobody meant to write does not become a statement nobody can read. */
    @Test
    void truncatesSomethingEnormous() {
        StringBuilder huge = new StringBuilder("select * from t where a in (");
        for (int i = 0; i < 200_000; i++) {
            huge.append("'x'").append(i < 199_999 ? "," : "");
        }
        huge.append(')');
        String fingerprint = QueryFingerprint.of(huge.toString(), Dialect.POSTGRESQL);
        assertTrue(fingerprint.length() <= 4100, "length " + fingerprint.length());
    }
}
