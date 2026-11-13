package space.seclume.postgresql.jdbc;

/**
 * A value as a string literal that PostgreSQL reads the same way whatever
 * {@code standard_conforming_strings} is.
 *
 * <p>Doubling the single quotes is all standard SQL asks, and all JDBC's own
 * {@code enquoteLiteral} does. With {@code standard_conforming_strings = off}
 * - the default before 9.1, and still a setting of a session, a role or a
 * database - PostgreSQL reads a backslash in such a literal as an escape, so
 * {@code \' or 1=1 -- } became {@code '\'' or 1=1 -- '}: a string of one
 * quote, and the rest SQL. A value with a backslash is therefore written as
 * an escape string, {@code E'...'}, with the backslash doubled - which means
 * the same in both settings, and is what libpq's {@code PQescapeLiteral}
 * writes. The blank before the {@code E} keeps it from joining a word that
 * stands before the literal.
 */
final class PgQuoting {

    private PgQuoting() {
    }

    static String literal(String value) {
        if (value.indexOf('\\') < 0) {
            return "'" + value.replace("'", "''") + "'";
        }
        return " E'" + value.replace("\\", "\\\\").replace("'", "''") + "'";
    }
}
