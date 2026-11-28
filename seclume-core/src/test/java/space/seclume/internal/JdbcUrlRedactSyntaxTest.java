package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * Where a value ends depends on the syntax it is in: SQL Server's settings end
 * at {@code ;} alone, MySQL's key-value hosts and Oracle's descriptors at
 * {@code ,} and {@code )}. One set of ends for both cut a SQL Server password
 * at its {@code (} or {@code ,} and a MySQL one at its {@code ;}, and showed
 * the rest; an Oracle password in quotes with a {@code //} in it was taken for
 * an authority and shown whole.
 */
class JdbcUrlRedactSyntaxTest {

    private static void hidden(String url, String... parts) {
        String redacted = JdbcUrl.redact(url);
        for (String part : parts) {
            assertFalse(redacted.contains(part), url + " -> " + redacted);
        }
    }

    @Test
    void theShapesThatLeaked() {
        hidden("jdbc:sqlserver://db:1433;user=u;password=Qfirst(Qsecond;encrypt=true", "Qsecond");
        hidden("jdbc:sqlserver://db:1433;user=u;password=Qfirst,Qsecond;encrypt=true", "Qsecond");
        hidden("jdbc:sqlserver://db:1433;user=u;password=Qfirst\"Qsecond;encrypt=true", "Qsecond");
        hidden("jdbc:mysql://(host=db,port=3306,user=u,password=Qfirst;Qsecond)/app", "Qsecond");
        hidden("jdbc:oracle:thin:scott/\"Qfirst//Qsecond\"@db:1521/svc", "Qfirst", "Qsecond");
    }

    @Test
    void structureStaysReadable() {
        assertEquals("jdbc:sqlserver://db:1433;user=?;password=?;encrypt=?",
                JdbcUrl.redact("jdbc:sqlserver://db:1433;user=u;password=a(b,c;encrypt=true"));
        assertEquals("jdbc:mysql://address=(host=?)(password=?)/x",
                JdbcUrl.redact("jdbc:mysql://address=(host=db)(password=pw)/x"));
        assertEquals("jdbc:mysql://(host=?,port=?,password=?)/app",
                JdbcUrl.redact("jdbc:mysql://(host=db,port=3306,password=a;b)/app"));
    }

    private static String token(Random random) {
        StringBuilder text = new StringBuilder("Q");
        for (int i = 0; i < 6; i++) {
            text.append((char) ('a' + random.nextInt(26)));
        }
        return text.toString();
    }

    private static String separators(Random random, String forbidden) {
        String all = "!$%()*+,-.:;=@[]^_{|}~/?#&'\" ";
        StringBuilder text = new StringBuilder();
        for (int i = 1 + random.nextInt(3); i > 0; i--) {
            char c;
            do {
                c = all.charAt(random.nextInt(all.length()));
            } while (forbidden.indexOf(c) >= 0);
            text.append(c);
        }
        return text.toString();
    }

    /** Passwords as each driver's syntax lets them be written, halves on both sides of the odd characters. */
    @Test
    void noHalfOfARandomPasswordIsShown() {
        Random random = new Random(20261122L);
        for (int n = 0; n < 30_000; n++) {
            String a = token(random);
            String b = token(random);
            String url = switch (random.nextInt(6)) {
                case 0 -> "jdbc:postgresql://db:5432/app?user=u&password=" + a
                        + separators(random, "&#") + b + "&ssl=true";
                case 1 -> "jdbc:mysql://u:" + a + separators(random, "/?#@") + b + "@db:3306/app";
                case 2 -> "jdbc:sqlserver://db:1433;user=u;password=" + a
                        + separators(random, ";{}") + b + ";encrypt=true";
                case 3 -> "jdbc:sqlserver://db:1433;user=u;password={" + a
                        + separators(random, "}") + b + "};encrypt=true";
                case 4 -> "jdbc:mysql://(host=db,port=3306,user=u,password=" + a
                        + separators(random, ",)(=") + b + ")/app";
                default -> "jdbc:oracle:thin:scott/\"" + a + separators(random, "\"") + b
                        + "\"@db:1521/svc";
            };
            hidden(url, a, b);
        }
    }
}
