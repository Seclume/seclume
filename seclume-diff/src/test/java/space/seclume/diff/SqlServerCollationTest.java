package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.tck.TestHosts;

/**
 * Single-byte text in every code page SQL Server has, read like mssql-jdbc.
 *
 * <p>A {@code varchar} is bytes in the code page its collation names - 1251
 * for Cyrillic, 936 for simplified Chinese, 932 for Japanese - or UTF-8 for a
 * {@code _UTF8} collation. The text is written as {@code nvarchar} literals and
 * stored into columns of each collation, then read through both drivers:
 * {@code getString}, and the text through a prepared statement's binary rows
 * as well as a plain one's.
 */
@Timeout(300)
class SqlServerCollationTest {

    /** Collation and text that it can hold. */
    private static final String[][] CASES = {
        {"SQL_Latin1_General_CP1_CI_AS", "Grüße, déjà vu, €100, „Anführung“, ‰"},
        {"Latin1_General_100_CI_AS", "Grüße, déjà vu, € ŠŽšž Œœ Ÿ"},
        {"Cyrillic_General_CI_AS", "Привет, мир! Ёё Ђђ"},
        {"Greek_CI_AS", "Γειά σου Κόσμε, αβγ ΆΈΉ"},
        {"Turkish_CI_AS", "İstanbul ğüşöç ĞÜŞÖÇ ı"},
        {"Hebrew_CI_AS", "שלום עולם"},
        {"Arabic_CI_AS", "مرحبا بالعالم"},
        {"Polish_CI_AS", "Zażółć gęślą jaźń"},
        {"Czech_CI_AS", "Příliš žluťoučký kůň"},
        {"Lithuanian_CI_AS", "Ąčęėįšųūž"},
        {"Vietnamese_CI_AS", "Tiếng Việt"},
        {"Thai_CI_AS", "สวัสดีชาวโลก"},
        {"Chinese_PRC_CI_AS", "你好，世界"},
        {"Chinese_Taiwan_Stroke_CI_AS", "你好，世界（繁體）"},
        {"Japanese_CI_AS", "こんにちは世界 カタカナ ｶﾀｶﾅ"},
        {"Korean_Wansung_CI_AS", "안녕하세요 세계"},
        {"Latin1_General_100_CI_AS_SC_UTF8", "Grüße 你好 😀 Привет"},
    };

    @ParameterizedTest
    @ValueSource(ints = {1433, 1435})
    void everyCodePageReadsLikeMssqlJdbc(int port) throws Exception {
        Path secret = TypeCatalogTest.locate(".local-mssql-password");
        String host = System.getProperty("seclume.mssql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        Properties vendor = new Properties();
        vendor.setProperty("user", "sa");
        vendor.setProperty("password", Files.readString(secret).trim());
        List<String> findings = new ArrayList<>();
        try (Connection ours = DriverManager.getConnection("jdbc:seclume:sqlserver://" + host
                + ":" + port + "/master?user=sa&trustServerCertificate=true&provider=file&path="
                + TypeCatalogTest.slash(secret));
             Connection theirs = DriverManager.getConnection("jdbc:sqlserver://" + host + ":"
                     + port + ";databaseName=master;encrypt=true;trustServerCertificate=true",
                     vendor)) {
            StringBuilder ddl = new StringBuilder("create table ##seclume_collation (id int");
            for (int i = 0; i < CASES.length; i++) {
                ddl.append(", c").append(i).append(" varchar(200) collate ").append(CASES[i][0]);
                // text for the code pages; UTF-8 collations refuse the legacy LOB
                // types, so there the chunked varchar(max) stands in.
                ddl.append(", t").append(i).append(CASES[i][0].endsWith("_UTF8")
                        ? " varchar(max) collate " : " text collate ").append(CASES[i][0]);
            }
            try (Statement statement = theirs.createStatement()) {
                statement.execute("drop table if exists ##seclume_collation");
                statement.execute(ddl.append(")").toString());
                StringBuilder insert = new StringBuilder("insert into ##seclume_collation values (1");
                for (String[] one : CASES) {
                    String literal = "N'" + one[1].replace("'", "''") + "'";
                    insert.append(", ").append(literal).append(", ").append(literal);
                }
                statement.execute(insert.append(")").toString());
            }
            String select = "select * from ##seclume_collation";
            List<String> vendorRow = row(theirs, select, false);
            for (boolean prepared : new boolean[] {false, true}) {
                List<String> mine = row(ours, select, prepared);
                for (int i = 0; i < CASES.length; i++) {
                    for (int kind = 0; kind < 2; kind++) {
                        int column = 2 + i * 2 + kind;
                        if (!vendorRow.get(column).equals(mine.get(column))) {
                            findings.add(CASES[i][0] + (kind == 0 ? " varchar" : " text")
                                    + (prepared ? " (prepared)" : "") + ": seclume="
                                    + mine.get(column) + " mssql-jdbc=" + vendorRow.get(column));
                        }
                    }
                }
            }
            // And the server stored what was meant: the vendor reads back the
            // text wherever the code page can hold it.
            for (int i = 0; i < CASES.length; i++) {
                if (!vendorRow.get(2 + i * 2).equals(CASES[i][1])) {
                    System.out.println("  (the server's " + CASES[i][0] + " holds "
                            + vendorRow.get(2 + i * 2) + ")");
                }
            }
        }
        findings.forEach(f -> System.out.println("  " + f));
        assertTrue(findings.isEmpty(), findings.size() + " columns read differently:\n"
                + String.join("\n", findings));
    }

    /**
     * Every collation the server knows, and the code page this driver would
     * read it in against the one the server says - so a collation added in a
     * later version is a failure here and not wrong text somewhere.
     */
    @ParameterizedTest
    @ValueSource(ints = {1433, 1435})
    void everyCollationMapsToTheServersCodePage(int port) throws Exception {
        Path secret = TypeCatalogTest.locate(".local-mssql-password");
        String host = System.getProperty("seclume.mssql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        List<String> wrong = new ArrayList<>();
        int checked = 0;
        try (Connection ours = DriverManager.getConnection("jdbc:seclume:sqlserver://" + host
                + ":" + port + "/master?user=sa&trustServerCertificate=true&provider=file&path="
                + TypeCatalogTest.slash(secret));
             Statement statement = ours.createStatement();
             ResultSet rows = statement.executeQuery("select name, "
                     + "cast(collationproperty(name, 'LCID') as int), "
                     + "cast(collationproperty(name, 'SortId') as int), "
                     + "cast(collationproperty(name, 'CodePage') as int) "
                     + "from sys.fn_helpcollations()")) {
            while (rows.next()) {
                String name = rows.getString(1);
                boolean utf8 = name.toUpperCase(java.util.Locale.ROOT).endsWith("_UTF8");
                int info = rows.getInt(2) | (utf8 ? 1 << 26 : 0);
                int expected = utf8 ? 65001 : rows.getInt(4);
                int mapped = space.seclume.sqlserver.tds.TdsCollation.codePage(info,
                        rows.getInt(3));
                // Code page 0 is a Unicode-only collation: no varchar can be
                // declared in it, so there is no single-byte text to read.
                if (expected != 0 && mapped != expected) {
                    wrong.add(name + ": " + mapped + " instead of " + expected);
                }
                checked++;
            }
        }
        assertTrue(checked > 5000, "only " + checked + " collations listed");
        assertTrue(wrong.isEmpty(), wrong.size() + " of " + checked + " collations map wrong:\n"
                + String.join("\n", wrong.subList(0, Math.min(20, wrong.size()))));
    }

    private static List<String> row(Connection connection, String sql, boolean prepared)
            throws Exception {
        List<String> values = new ArrayList<>();
        values.add(null);
        Statement statement = prepared ? connection.prepareStatement(sql)
                : connection.createStatement();
        try (statement;
             ResultSet rows = prepared ? ((PreparedStatement) statement).executeQuery()
                     : statement.executeQuery(sql)) {
            assertTrue(rows.next());
            for (int i = 1; i <= rows.getMetaData().getColumnCount(); i++) {
                values.add(i == 1 ? null : rows.getString(i));
            }
            assertEquals(1, rows.getInt(1));
        }
        return values;
    }
}
