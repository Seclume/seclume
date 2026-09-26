package space.seclume.internal.jdbc;

import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.regex.Pattern;

/** The checks and the quoting behind {@link space.seclume.SessionContext}. */
public final class ContextValues {

    private static final Pattern NAME = Pattern.compile("[A-Za-z][A-Za-z0-9_.]{0,127}");

    private ContextValues() {
    }

    /** Refuses a name that could be anything but a name, and a null value. */
    public static void check(String name, String value) throws SQLException {
        if (name == null || !NAME.matcher(name).matches()) {
            throw new SQLException("a session context name is letters, digits, underscores and "
                    + "dots, starting with a letter: " + name, "22023");
        }
        if (value == null) {
            throw new SQLException("a session context value of null is refused - leave the "
                    + "context out instead", "22004");
        }
    }

    /**
     * PostgreSQL: the value dollar-quoted, which no setting of the server can
     * make mean anything else - unlike a quoted string, whose backslashes
     * depend on {@code standard_conforming_strings}.
     */
    public static String dollarQuoted(String value) {
        String tag = "$seclume$";
        int n = 0;
        while (value.contains(tag)) {
            tag = "$seclume" + (++n) + "$";
        }
        return tag + value + tag;
    }

    /** MySQL: the value as a hex literal read as UTF-8 - no quoting mode matters. */
    public static String hexUtf8(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);  // seclume-allow: a context value, not a secret
        StringBuilder out = new StringBuilder(bytes.length * 2 + 30); // seclume-allow: a context value, not a secret
        out.append("convert(0x");
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        if (bytes.length == 0) {
            return "''";
        }
        return out.append(" using utf8mb4)").toString();
    }

    /** SQL Server: an N'' literal - T-SQL has no escape character, only the doubled quote. */
    public static String nString(String value) {
        return "N'" + value.replace("'", "''") + "'";
    }
}
