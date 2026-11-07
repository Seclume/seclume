package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.verify.Migrate.Level;
import space.seclume.verify.Migrate.Result;

/**
 * {@code --migrate} prints a translated configuration - to a terminal, into a
 * CI log, into a ticket. Whatever form a URL writes its password in, the
 * password is not in what is printed, and the finding says it stood there.
 */
class MigrateNeverPrintsAPasswordTest {

    private static void assertNotPrinted(Result result, String... pieces) {
        String text = result.render();
        for (String piece : pieces) {
            assertFalse(text.contains(piece), "'" + piece + "' reached the output:\n" + text);
        }
    }

    private static boolean has(Result result, Level level, String text) {
        return result.findings().stream()
                .anyMatch(finding -> finding.level() == level && finding.text().contains(text));
    }

    @Test
    void aMysqlUserAndPasswordBeforeTheHost() {
        Result result = Migrate.translateUrl(
                "jdbc:mysql://app:S3cr3t-Pw@db1:3307,db2/shop?sslMode=VERIFY_IDENTITY");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:mysql://db1:3307,db2:3306/shop"
                + "?tls=verify-full", result.properties().get(0));
        assertEquals("seclume.datasources.main.username=app", result.properties().get(1));
        assertTrue(has(result, Level.UNSAFE, "password stood in the configuration"),
                result.render());
        assertNotPrinted(result, "S3cr3t-Pw");
    }

    @Test
    void aUserBeforeTheHostWithoutAPasswordIsJustTheUser() {
        Result result = Migrate.translateUrl("jdbc:mariadb://reader@db/stats?sslMode=VERIFY_IDENTITY");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:mysql://db:3306/stats"
                + "?tls=verify-full", result.properties().get(0));
        assertEquals("seclume.datasources.main.username=reader", result.properties().get(1));
        assertFalse(result.unsafe(), result.render());
    }

    @Test
    void connectorJsKeyValueHostsAreNotCarriedOver() {
        for (String url : List.of(
                "jdbc:mysql://(host=db,port=3306,user=app,password=Kv-Secret-1)/shop",
                "jdbc:mysql://address=(host=db)(port=3306)(password=Kv-Secret-1)/shop",
                "jdbc:mysql://db:3306,(host=db2,password=Kv-Secret-1)/shop")) {
            Result result = Migrate.translateUrl(url);
            assertEquals(List.of(), result.properties(), url);
            assertTrue(has(result, Level.NOT_TRANSLATED, "key-value form"), url);
            assertTrue(has(result, Level.UNSAFE, "password stood in the URL"), url);
            assertNotPrinted(result, "Kv-Secret-1", "password=");
        }
        Result noPassword = Migrate.translateUrl("jdbc:mysql://(host=db,port=3306)/shop");
        assertTrue(noPassword.properties().isEmpty());
        assertFalse(has(noPassword, Level.UNSAFE, "password"), noPassword.render());
    }

    @Test
    void connectorJsFurtherFactorsAreFoundAndDropped() {
        Result result = Migrate.translateUrl("jdbc:mysql://db/shop?sslMode=VERIFY_IDENTITY"
                + "&user=app&password2=Second-Factor&password3=Third-Factor");
        assertTrue(has(result, Level.UNSAFE, "password stood in the configuration"),
                result.render());
        assertFalse(has(result, Level.NOT_TRANSLATED, "password2"), result.render());
        assertNotPrinted(result, "Second-Factor", "Third-Factor");
    }

    @Test
    void aBracedSqlServerPasswordIsOneValue() {
        Result result = Migrate.translateUrl("jdbc:sqlserver://db;databaseName=app;"
                + "password={Xq7;Zr9=Kp2};encrypt=strict;user=svc");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:sqlserver://db:1433/app?tds=8.0",
                result.properties().get(0));
        assertEquals("seclume.datasources.main.username=svc", result.properties().get(1));
        assertTrue(has(result, Level.UNSAFE, "password stood in the configuration"),
                result.render());
        assertFalse(result.findings().stream().anyMatch(f -> f.level() == Level.NOT_TRANSLATED),
                result.render());
        assertNotPrinted(result, "Xq7", "Zr9", "Kp2");
    }

    @Test
    void bracesKeepSemicolonsAndDoubledClosingBraces() {
        assertEquals(List.of("//db", "password={a}}b;c=d}", "encrypt=strict"),
                Migrate.sqlServerParts("//db;password={a}}b;c=d};encrypt=strict"));
        assertEquals(List.of("//db", "applicationName=a{b", "encrypt=strict"),
                Migrate.sqlServerParts("//db;applicationName=a{b;encrypt=strict"),
                "a brace inside a value opens nothing");
    }

    @Test
    void sqlServerPropertyNamesInAnyCase() {
        Result result = Migrate.translateUrl("jdbc:sqlserver://db;DatabaseName=app;"
                + "Password=Mixed-Case-Pw;TrustServerCertificate=TRUE;Encrypt=strict;UserName=svc");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:sqlserver://db:1433/app"
                + "?tds=8.0&trustServerCertificate=true", result.properties().get(0));
        assertEquals("seclume.datasources.main.username=svc", result.properties().get(1));
        assertTrue(has(result, Level.UNSAFE, "trustServerCertificate=true accepts any"),
                result.render());
        assertTrue(has(result, Level.UNSAFE, "password stood in the configuration"),
                result.render());
        assertNotPrinted(result, "Mixed-Case-Pw");
    }

    @Test
    void anOraclePasswordWithAnAtInQuotes() {
        Result result = Migrate.translateUrl("jdbc:oracle:thin:scott/\"ti@ger-Xy\"@//db:1521/svc");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:oracle://db:1521/svc",
                result.properties().get(0));
        assertEquals("seclume.datasources.main.username=scott", result.properties().get(1));
        assertTrue(has(result, Level.UNSAFE, "password stood in the configuration"));
        assertNotPrinted(result, "ger-Xy", "ti@");

        Result open = Migrate.translateUrl("jdbc:oracle:thin:scott/\"Open-Quote@//db:1521/svc");
        assertTrue(open.properties().isEmpty());
        assertNotPrinted(open, "Open-Quote");
    }

    @Test
    void aUrlNobodyReadsIsNamedByItsSchemeOnly() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int status = Migrate.run("jdbc:h2:mem:x;PASSWORD=H2-Secret",
                new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
        String text = err.toString(StandardCharsets.UTF_8);
        assertEquals(2, status);
        assertTrue(text.contains("jdbc:h2:"), text);
        assertFalse(text.contains("H2-Secret") || text.contains("H2-Se"), text);
    }
}
