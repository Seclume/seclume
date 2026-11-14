package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

/**
 * {@link JdbcUrl#redact} at the edges of each of its rules, to the character.
 *
 * <p>{@code JdbcUrlPropertyTest} checks over random URLs that no password
 * survives. What it cannot check is that the boundaries of each rule sit
 * where the documentation says: that a URL may start with the {@code //}
 * or the {@code /} a rule looks for, that the authority ends at the first
 * {@code / ? #} and not one character later, that a brace-quoted SQL Server
 * value ends at its own closing brace even at the very end of the URL. A
 * comparison one off at any of these hides a little more or a little less,
 * and only an exact expected string notices the difference (run
 * 43416680859, {@code JdbcUrl}: 30 survivors).
 */
class JdbcUrlRedactEdgeTest {

    private static void redacts(String url, String expected) {
        assertEquals(expected, JdbcUrl.redact(url), url);
    }

    /** A rule's marker at the very first character still starts the rule. */
    @Test
    void aLoginAtTheVeryStartOfTheTextIsHidden() {
        redacts("//app:zlStart1@db", "//app:?@db");
        redacts("/scott/zlStart2@db", "/?@db");
        assertFalse(JdbcUrl.redact("//app:zlStart1@db").contains("zlStart1"));
        assertFalse(JdbcUrl.redact("/scott/zlStart2@db").contains("zlStart2"));
    }

    /**
     * Oracle's EZConnect form, {@code thin:@//host}, with a {@code user:password@}
     * typed into its authority. The {@code @} before the {@code //} took the
     * URL for Oracle's {@code user/password@}, found no {@code /} before it
     * and hid nothing: the password stood in the message that named the URL.
     * Found with this test; it fails on the code before the fix.
     */
    @Test
    void aLoginAfterOraclesAtSlashSlashIsHidden() {
        redacts("jdbc:oracle:thin:@//app:zlEz1@db:1521/svc", "jdbc:oracle:thin:@//app:?@db:1521/svc");
        redacts("jdbc:mysql:@//app:zlEz2@db/x", "jdbc:mysql:@//app:?@db/x");
        redacts("@x//app:zlEz3@h", "@x//app:?@h");
        redacts("jdbc:oracle:thin:@//db:1521/svc", "jdbc:oracle:thin:@//db:1521/svc");
        redacts("jdbc:oracle:thin:scott/zlEz4@//db:1521/svc", "jdbc:oracle:thin:scott/?@//db:1521/svc");
    }

    /** RFC 3986: the authority ends at the first / ? or # - an @ after it is not a login's. */
    @Test
    void anAtSignAfterTheAuthorityEndsNoLogin() {
        redacts("jdbc:x://db/path:a@b", "jdbc:x://db/path:a@b");
        redacts("jdbc:x://u:5432/@x", "jdbc:x://u:5432/@x");
        redacts("jdbc:mysql://u:p@db#frag:z@w", "jdbc:mysql://u:?@db#frag:z@w");
    }

    @Test
    void theLastAtSignOfTheAuthorityEndsTheLogin() {
        redacts("jdbc:mysql://app:zlAt@Twice@db/x?useSSL=true", "jdbc:mysql://app:?@db/x?useSSL=?");
    }

    /** Oracle's user/password@: the first @ outside quotes ends it, and a quoted password may hold one. */
    @Test
    void anOraclePasswordInQuotesIsHiddenWholeWithItsAtSign() {
        redacts("jdbc:oracle:thin:scott/\"zl@Quoted\"@db:1521/svc", "jdbc:oracle:thin:scott/?@db:1521/svc");
        redacts("jdbc:oracle:thin:@db:1521/svc?password=zlQ", "jdbc:oracle:thin:@db:1521/svc?password=?");
    }

    /** SQL Server's {...}: }} is a brace inside, and the value runs to its own closing brace. */
    @Test
    void aBraceQuotedValueEndsAtItsOwnClosingBrace() {
        redacts("jdbc:sqlserver://db;password={zl}}B;c};user=sa", "jdbc:sqlserver://db;password=?;user=?");
        redacts("jdbc:sqlserver://db;password={zlEnd}", "jdbc:sqlserver://db;password=?");
        redacts("jdbc:sqlserver://db;password={zlOpen", "jdbc:sqlserver://db;password=?");
        redacts("jdbc:sqlserver://db;password={zl}};user=sa", "jdbc:sqlserver://db;password=?");
        redacts("jdbc:sqlserver://db;password={zl};user=sa", "jdbc:sqlserver://db;password=?;user=?");
    }

    /** Before the query a ? belongs to the value - SQL Server's values may have one. */
    @Test
    void aQuestionMarkInsideAValueBeforeTheQueryIsTheValues() {
        redacts("jdbc:sqlserver://db;password=zl?Q;user=sa", "jdbc:sqlserver://db;password=?;user=?");
    }

    @Test
    void everyQueryValueIsHiddenAndAnOptionWithoutOneIsKept() {
        redacts("jdbc:postgresql://db/app?user=a&password=zlQ&ssl", "jdbc:postgresql://db/app?user=?&password=?&ssl");
        redacts("jdbc:postgresql://db/app?user=a&&password=zl=Q&x=", "jdbc:postgresql://db/app?user=?&&password=?&x=");
        redacts("jdbc:x://db?a=\"q?w\"&b=c", "jdbc:x://db?a=?&b=?");
    }

    /** A ? inside quotes does not start the query; the one after them does. */
    @Test
    void aQuotedDescriptorIsNotTheQuery() {
        redacts("jdbc:oracle:thin:@\"(DESCRIPTION=(HOST=db)(PORT=1)\"?password=zlQ",
                "jdbc:oracle:thin:@\"(DESCRIPTION=(HOST=db)(PORT=1)\"?password=?");
        redacts("jdbc:mysql://address=(host=db)(password=zlKv)/x", "jdbc:mysql://address=(host=?)(password=?)/x");
        redacts("jdbc:x:\"//u:zlQ@h\"", "jdbc:x:\"//u:?@h\"");
    }

    @Test
    void nothingToHideIsReturnedAsItIs() {
        redacts("jdbc:seclume:postgresql://db:5432/app", "jdbc:seclume:postgresql://db:5432/app");
        redacts("", "");
        redacts("null", "null");
        assertEquals("null", JdbcUrl.redact(null));
    }
}
