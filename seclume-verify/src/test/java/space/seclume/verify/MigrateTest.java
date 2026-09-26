package space.seclume.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.verify.Migrate.Level;
import space.seclume.verify.Migrate.Result;

/** Existing configurations, translated - and the unsafe settings in them named. */
class MigrateTest {

    @Test
    void pgjdbcWithRequireBecomesRequireAndIsCalledUnsafe() {
        Result result = Migrate.translateUrl("jdbc:postgresql://db1:5433,db2/app"
                + "?sslmode=require&user=app&password=geheim&ApplicationName=orders"
                + "&connectTimeout=5&targetServerType=master&prepareThreshold=3");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:postgresql://db1:5433,db2:5432/app"
                + "?tls=require&applicationName=orders&connectTimeout=5000"
                + "&targetServerType=primary", result.properties().get(0));
        assertEquals("seclume.datasources.main.username=app", result.properties().get(1));
        assertTrue(result.properties().get(2).startsWith("seclume.datasources.main.secret-uri=file:"));
        assertTrue(result.unsafe());
        assertTrue(has(result, Level.UNSAFE, "checks no certificate"));
        assertTrue(has(result, Level.UNSAFE, "password stood in the configuration"));
        assertFalse(result.render().contains("geheim"), "the password reached the output");
    }

    @Test
    void verifyFullAndNothingElseIsClean() {
        Result result = Migrate.translateUrl("jdbc:postgresql://db/app?sslmode=verify-full"
                + "&sslrootcert=/etc/ca.pem&user=app");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:postgresql://db:5432/app"
                + "?tls=verify-full&tlsRootCert=/etc/ca.pem", result.properties().get(0));
        assertFalse(result.unsafe(), result.render());
    }

    @Test
    void mysqlLegacyFlagsAndPublicKeyRetrieval() {
        Result result = Migrate.translateUrl("jdbc:mysql://db/app?useSSL=false"
                + "&allowPublicKeyRetrieval=true&serverTimezone=UTC&rewriteBatchedStatements=true");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:mysql://db:3306/app"
                + "?tls=off&allowPublicKeyRetrieval=true&rewriteBatchedInserts=true",
                result.properties().get(0));
        assertTrue(has(result, Level.UNSAFE, "switches encryption off"));
        assertTrue(has(result, Level.UNSAFE, "allowPublicKeyRetrieval=true without"));
        assertTrue(has(result, Level.CHANGED, "serverTimezone"));
    }

    @Test
    void mariaDbVerifyIdentity() {
        Result result = Migrate.translateUrl("jdbc:mariadb://db:3307/app?sslMode=VERIFY_IDENTITY");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:mysql://db:3307/app"
                + "?tls=verify-full", result.properties().get(0));
    }

    @Test
    void sqlServerTrustAndStrict() {
        Result result = Migrate.translateUrl("jdbc:sqlserver://db;databaseName=app;"
                + "encrypt=strict;trustServerCertificate=true;user=sa;password=x;"
                + "sendStringParametersAsUnicode=false;loginTimeout=15");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:sqlserver://db:1433/app"
                + "?tds=8.0&trustServerCertificate=true&connectTimeout=15000",
                result.properties().get(0));
        assertTrue(has(result, Level.UNSAFE, "trustServerCertificate=true accepts any"));
        assertTrue(has(result, Level.CHANGED, "decides per parameter"));
    }

    @Test
    void sqlServerIntegratedSecurityIsNamedAsMissing() {
        Result result = Migrate.translateUrl("jdbc:sqlserver://db\\SQLEXPRESS:1500;"
                + "databaseName=app;integratedSecurity=true");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:sqlserver://db:1500/app",
                result.properties().get(0));
        assertTrue(has(result, Level.NOT_TRANSLATED, "integratedSecurity=true"));
        assertTrue(has(result, Level.NOT_TRANSLATED, "instanceName=SQLEXPRESS"));
    }

    @Test
    void oracleForms() {
        assertEquals("seclume.datasources.main.url=jdbc:seclume:oracle://db:1521/FREEPDB1",
                Migrate.translateUrl("jdbc:oracle:thin:@//db:1521/FREEPDB1")
                        .properties().get(0));
        Result sid = Migrate.translateUrl("jdbc:oracle:thin:scott/tiger@db:1521:ORCL");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:oracle://db:1521/ORCL",
                sid.properties().get(0));
        assertEquals("seclume.datasources.main.username=scott", sid.properties().get(1));
        assertTrue(has(sid, Level.UNSAFE, "password stood in the configuration"));
        assertTrue(has(sid, Level.CHANGED, "SID"));
        assertFalse(sid.render().contains("tiger"));
        assertEquals("seclume.datasources.main.url=jdbc:seclume:oracle://db:2484/svc?tls=verify-full",
                Migrate.translateUrl("jdbc:oracle:thin:@tcps://db/svc").properties().get(0));
        assertTrue(Migrate.translateUrl("jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(HOST=db)))")
                .properties().isEmpty());
        assertEquals("seclume.datasources.main.url=jdbc:seclume:oracle:tns:ORDERS",
                Migrate.translateUrl("jdbc:oracle:thin:@ORDERS").properties().get(0));
    }

    @Test
    void aSpringFileWithHikariAndASecondSource(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("application.properties");
        Files.writeString(file, """
                spring.datasource.url=jdbc:postgresql://db/app?sslmode=verify-full
                spring.datasource.username=app
                spring.datasource.password=do-not-print-me
                spring.datasource.hikari.maximum-pool-size=20
                spring.datasource.hikari.connectionTimeout=2500
                spring.datasource.hikari.connection-test-query=select 1
                spring.datasource.hikari.data-source-properties.ApplicationName=orders
                app.reporting.datasource.url=jdbc:mysql://rep/stats?sslMode=REQUIRED
                app.reporting.datasource.username=reader
                spring.mail.password=also-not
                """, StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int status = Migrate.run(file.toString(), new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8));
        String text = out.toString(StandardCharsets.UTF_8);
        assertEquals(1, status, text);
        assertTrue(text.contains("seclume.datasources.main.url=jdbc:seclume:postgresql://db:5432/app"
                + "?tls=verify-full&applicationName=orders"), text);
        assertTrue(text.contains("seclume.datasources.main.pool.maximum-pool-size=20"), text);
        assertTrue(text.contains("seclume.datasources.main.pool.connection-timeout=2500ms"), text);
        assertTrue(text.contains("seclume.datasources.reporting.url=jdbc:seclume:mysql://rep:3306/stats"
                + "?tls=require"), text);
        assertTrue(text.contains("seclume.datasources.reporting.username=reader"), text);
        assertTrue(text.contains("spring.mail.password holds a password"), text);
        assertFalse(text.contains("do-not-print-me") || text.contains("also-not"), text);
    }

    /** What comes out is a URL the seclume drivers accept - not merely one that looks right. */
    @Test
    void theTranslatedUrlsParse() throws Exception {
        for (String vendor : List.of(
                "jdbc:postgresql://db/app?sslmode=require&sslnegotiation=direct",
                "jdbc:mysql://db/app?sslMode=PREFERRED&allowPublicKeyRetrieval=true",
                "jdbc:sqlserver://db;databaseName=app;encrypt=strict",
                "jdbc:oracle:thin:@tcps://db:2484/svc")) {
            String line = Migrate.translateUrl(vendor).properties().get(0);
            String url = line.substring(line.indexOf('=') + 1);
            assertTrue(DriverManager.getDriver(url) != null, url);
            assertTrue(DriverManager.getDriver(url).acceptsURL(url), url);
        }
    }

    @Test
    void anRdsHostGetsTheBundledCa() {
        Result result = Migrate.translateUrl("jdbc:postgresql://db.abc.eu-central-1.rds.amazonaws.com/app"
                + "?sslmode=verify-full");
        assertEquals("seclume.datasources.main.url=jdbc:seclume:postgresql://"
                + "db.abc.eu-central-1.rds.amazonaws.com:5432/app?tls=verify-full&tlsRootCert=aws-rds",
                result.properties().get(0));
    }

    @Test
    void anythingElseIsRefused() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int status = Migrate.run("jdbc:db2://x/y", new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(err, true, StandardCharsets.UTF_8));
        assertEquals(2, status);
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("jdbc:postgresql"));
    }

    private static boolean has(Result result, Level level, String text) {
        return result.findings().stream()
                .anyMatch(finding -> finding.level() == level && finding.text().contains(text));
    }
}
