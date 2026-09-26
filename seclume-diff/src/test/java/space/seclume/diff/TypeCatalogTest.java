package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * Every type the server has, read through seclume and through the vendor's
 * driver, and compared.
 *
 * <p>A driver fails on a <b>type</b>, not on a function: whatever a function
 * returns arrives as one of the server's types, and a type the decoder does
 * not know breaks not only its own column but every column behind it - that is
 * how SQL Server's {@code xml}, Oracle's {@code ROWID} and {@code XMLType}
 * were found. So the catalog is the server's own list of types wherever the
 * server keeps one ({@code pg_type}, {@code sys.types}), and the documented
 * list where it does not.
 *
 * <p>Per type, two rows: a NULL and a sample value. Each is read through both
 * drivers - {@code getString}, the class of {@code getObject}, the reported
 * type - and a column behind it has to read 42, or the row went out of step.
 * Where no sample can be written (internal types with no input function) the
 * NULL row still runs, and the report says so rather than leaving the type
 * out.
 *
 * <p>Differences the two drivers may legitimately have are named one by one
 * with the reason; everything else is a finding.
 */
@Timeout(600)
class TypeCatalogTest {

    /** One type: how to write a NULL and a value of it, or null for "no sample". */
    record Sample(String type, String nullSql, String valueSql) {
    }

    /** What happened to one type. */
    record Outcome(String type, String problem) {
    }

    // ---- PostgreSQL ---------------------------------------------------------

    /** Sample literals, by pg_type name; types missing here run as NULL only. */
    private static final Map<String, String> PG = new LinkedHashMap<>();

    static {
        PG.put("bit", "B'1'");
        PG.put("bool", "true");
        PG.put("box", "'((0,0),(1,1))'");
        PG.put("bpchar", "'x'");
        PG.put("bytea", "'\\xdeadbeef'");
        PG.put("char", "'a'");
        PG.put("cid", "'1'");
        PG.put("cidr", "'10.0.0.0/8'");
        PG.put("circle", "'<(0,0),1>'");
        PG.put("date", "'2024-02-29'");
        PG.put("datemultirange", "'{[2024-01-01,2024-02-01)}'");
        PG.put("daterange", "'[2024-01-01,2024-02-01)'");
        PG.put("float4", "1.5");
        PG.put("float8", "0.1");
        PG.put("inet", "'192.168.0.1/24'");
        PG.put("int2", "7");
        PG.put("int2vector", "'1 2 3'");
        PG.put("int4", "7");
        PG.put("int4multirange", "'{[1,5)}'");
        PG.put("int4range", "'[1,5)'");
        PG.put("int8", "7");
        PG.put("int8multirange", "'{[1,5)}'");
        PG.put("int8range", "'[1,5)'");
        PG.put("interval", "'1 day 02:03:04'");
        PG.put("json", "'{\"a\":[1,2],\"b\":\"Grüße\"}'");
        PG.put("jsonb", "'{\"a\":[1,2],\"b\":\"Grüße\"}'");
        PG.put("jsonpath", "'$.a[*]'");
        PG.put("line", "'{1,-1,0}'");
        PG.put("lseg", "'[(0,0),(1,1)]'");
        PG.put("macaddr", "'08:00:2b:01:02:03'");
        PG.put("macaddr8", "'08:00:2b:01:02:03:04:05'");
        PG.put("money", "'12.34'");
        PG.put("name", "'abc'");
        PG.put("numeric", "12.5");
        PG.put("nummultirange", "'{[1.5,2.5)}'");
        PG.put("numrange", "'[1.5,2.5)'");
        PG.put("oid", "12345");
        PG.put("oidvector", "'1 2'");
        PG.put("path", "'[(0,0),(1,1)]'");
        PG.put("pg_lsn", "'16/B374D848'");
        PG.put("pg_snapshot", "'10:20:10,14,15'");
        PG.put("point", "'(1,2)'");
        PG.put("polygon", "'((0,0),(1,1),(1,0))'");
        PG.put("refcursor", "'c1'");
        PG.put("regclass", "'pg_class'");
        PG.put("regcollation", "'\"C\"'");
        PG.put("regconfig", "'english'");
        PG.put("regdictionary", "'simple'");
        PG.put("regnamespace", "'public'");
        PG.put("regoperator", "'+(integer,integer)'");
        PG.put("regproc", "'now'");
        PG.put("regprocedure", "'abs(integer)'");
        PG.put("regrole", "'pg_monitor'");
        PG.put("regtype", "'integer'");
        PG.put("text", "'Grüße, 東京'");
        PG.put("tid", "'(0,1)'");
        PG.put("time", "'13:14:15.123'");
        PG.put("timestamp", "'2024-02-29 13:14:15.123456'");
        PG.put("timestamptz", "'2024-02-29 13:14:15.123456+01'");
        PG.put("timetz", "'13:14:15+02'");
        PG.put("tsmultirange", "'{[\"2024-01-01 00:00\",\"2024-01-02 00:00\")}'");
        PG.put("tsquery", "'fat & rat'");
        PG.put("tsrange", "'[\"2024-01-01 00:00\",\"2024-01-02 00:00\")'");
        PG.put("tstzmultirange", "'{[\"2024-01-01 00:00+00\",\"2024-01-02 00:00+00\")}'");
        PG.put("tstzrange", "'[\"2024-01-01 00:00+00\",\"2024-01-02 00:00+00\")'");
        PG.put("tsvector", "'a fat cat'");
        PG.put("txid_snapshot", "'10:20:10,14,15'");
        PG.put("uuid", "'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'");
        PG.put("varbit", "B'10101'");
        PG.put("varchar", "'x'");
        PG.put("xid", "'5'");
        PG.put("xid8", "'5'");
        PG.put("xml", "'<a x=\"1\">1</a>'");
    }

    @Test
    void everyPostgresTypeReadsLikePgjdbc() throws Exception {
        Path secret = locate(TestHosts.postgresPasswordFile());
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        reachable(host, port, secret);
        String url = "jdbc:seclume:postgresql://" + host + ":" + port
                + "/seclume_test?user=seclume_test&tls=off&provider=file&path=" + slash(secret);
        Properties vendor = new Properties();
        vendor.setProperty("user", "seclume_test");
        vendor.setProperty("password", Files.readString(secret).trim());
        try (Ours ours = new Ours(url);
             Connection theirs = DriverManager.getConnection(
                     "jdbc:postgresql://" + host + ":" + port + "/seclume_test", vendor)) {
            List<String> types = new ArrayList<>();
            try (Statement statement = theirs.createStatement();
                 ResultSet rows = statement.executeQuery("select typname from pg_type "
                         + "where typnamespace = 'pg_catalog'::regnamespace "
                         + "and typtype in ('b','r','m','e','d') and typname !~ '^_' "
                         + "and typisdefined order by typname")) {
                while (rows.next()) {
                    types.add(rows.getString(1));
                }
            }
            List<Sample> samples = new ArrayList<>();
            for (String type : types) {
                String literal = PG.get(type);
                samples.add(new Sample(type, "select null::\"" + type + "\", 42",
                        literal == null ? null : "select " + literal + "::\"" + type + "\", 42"));
            }
            report("PostgreSQL", types.size(), run(samples, ours, theirs, false));
        }
    }

    // ---- MySQL --------------------------------------------------------------

    /** MySQL keeps no list of its types; this is the manual's, plus the unsigned ones. */
    private static final List<Column> MYSQL = List.of(
            new Column("tinyint", "tinyint", "-7"),
            new Column("tinyint unsigned", "tinyint unsigned", "200"),
            new Column("tinyint(1)", "tinyint(1)", "1"),
            new Column("smallint", "smallint", "-7"),
            new Column("smallint unsigned", "smallint unsigned", "60000"),
            new Column("mediumint", "mediumint", "-7"),
            new Column("mediumint unsigned", "mediumint unsigned", "16000000"),
            new Column("int", "int", "-7"),
            new Column("int unsigned", "int unsigned", "4000000000"),
            new Column("bigint", "bigint", "-7"),
            new Column("bigint unsigned", "bigint unsigned", "18000000000000000000"),
            new Column("decimal", "decimal(10,2)", "12.5"),
            new Column("float", "float", "1.5"),
            new Column("double", "double", "0.1"),
            new Column("bit(1)", "bit(1)", "b'1'"),
            new Column("bit(8)", "bit(8)", "b'10101'"),
            new Column("date", "date", "'2024-02-29'"),
            new Column("datetime", "datetime", "'2024-02-29 13:14:15'"),
            new Column("datetime(6)", "datetime(6)", "'2024-02-29 13:14:15.123456'"),
            new Column("timestamp(3)", "timestamp(3) null", "'2024-02-29 13:14:15.123'"),
            new Column("time", "time", "'13:14:15'"),
            new Column("time(6)", "time(6)", "'12:34:56.123456'"),
            new Column("year", "year", "2024"),
            new Column("char", "char(5)", "'x'"),
            new Column("varchar", "varchar(20)", "'Grüße, 東京'"),
            new Column("binary", "binary(4)", "x'deadbeef'"),
            new Column("varbinary", "varbinary(8)", "x'deadbeef'"),
            new Column("tinyblob", "tinyblob", "x'deadbeef'"),
            new Column("blob", "blob", "x'deadbeef'"),
            new Column("mediumblob", "mediumblob", "x'deadbeef'"),
            new Column("longblob", "longblob", "x'deadbeef'"),
            new Column("tinytext", "tinytext", "'Grüße'"),
            new Column("text", "text", "'Grüße'"),
            new Column("mediumtext", "mediumtext", "'Grüße'"),
            new Column("longtext", "longtext", "'Grüße'"),
            new Column("enum", "enum('a','b')", "'b'"),
            new Column("set", "set('a','b')", "'a,b'"),
            new Column("json", "json", "'{\"a\": [1, 2], \"b\": \"Grüße\"}'"),
            new Column("geometry", "geometry", "st_geomfromtext('POINT(1 2)')"),
            new Column("point", "point", "point(1, 2)"),
            new Column("linestring", "linestring", "st_geomfromtext('LINESTRING(0 0,1 1)')"),
            new Column("polygon", "polygon", "st_geomfromtext('POLYGON((0 0,1 1,1 0,0 0))')"),
            new Column("multipoint", "multipoint", "st_geomfromtext('MULTIPOINT(0 0,1 1)')"),
            new Column("geometrycollection", "geometrycollection",
                    "st_geomfromtext('GEOMETRYCOLLECTION(POINT(1 2))')"),
            new Column("vector", "vector(3)", "string_to_vector('[1,2,3]')"));

    @Test
    void everyMySqlTypeReadsLikeConnectorJ() throws Exception {
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        Path secret = locate(".local-mysql-password");
        String host = System.getProperty("seclume.mysql.host", TestHosts.database());
        reachable(host, port, secret);
        Properties vendor = new Properties();
        vendor.setProperty("user", "seclume_test");
        vendor.setProperty("password", Files.readString(secret).trim());
        // Server-side prepares on both sides, so the prepared pass reads the
        // binary row format there as well as here.
        try (Ours ours = new Ours("jdbc:seclume:mysql://" + host + ":"
                + port + "/seclume_test?user=seclume_test&tls=off&allowPublicKeyRetrieval=true"
                + "&provider=file&path=" + slash(secret));
             Connection theirs = DriverManager.getConnection("jdbc:mysql://" + host + ":" + port
                     + "/seclume_test?allowPublicKeyRetrieval=true&sslMode=DISABLED"
                     + "&useServerPrepStmts=true", vendor)) {
            report("MySQL", MYSQL.size(),
                    runTables(MYSQL, ours, theirs, "seclume_type_catalog", true));
        }
    }

    // ---- SQL Server ---------------------------------------------------------

    /** Samples by sys.types name; a type missing here runs as NULL only. */
    private static final Map<String, Column> MSSQL = new LinkedHashMap<>();

    static {
        for (Column column : List.of(
                new Column("bigint", "bigint", "-7"),
                new Column("binary", "binary(4)", "0xdeadbeef"),
                new Column("bit", "bit", "1"),
                new Column("char", "char(5)", "'x'"),
                new Column("date", "date", "'2024-02-29'"),
                new Column("datetime", "datetime", "'2024-02-29T13:14:15.123'"),
                new Column("datetime2", "datetime2", "'2024-02-29T13:14:15.1234567'"),
                new Column("datetimeoffset", "datetimeoffset",
                        "'2024-02-29T13:14:15.1234567+02:00'"),
                new Column("decimal", "decimal(10,2)", "12.5"),
                new Column("float", "float", "0.1"),
                new Column("geography", "geography",
                        "geography::STGeomFromText('POINT(16 48)', 4326)"),
                new Column("geometry", "geometry", "geometry::STGeomFromText('POINT(1 2)', 0)"),
                new Column("hierarchyid", "hierarchyid", "hierarchyid::Parse('/1/2/')"),
                new Column("image", "image", "0xdeadbeef"),
                new Column("int", "int", "-7"),
                new Column("json", "json", "'{\"a\":[1,2],\"b\":\"Grüße\"}'"),
                new Column("money", "money", "12.34"),
                new Column("nchar", "nchar(5)", "N'ü'"),
                new Column("ntext", "ntext", "N'Grüße, 東京'"),
                new Column("numeric", "numeric(10,2)", "12.5"),
                new Column("nvarchar", "nvarchar(20)", "N'Grüße, 東京'"),
                new Column("real", "real", "1.5"),
                new Column("smalldatetime", "smalldatetime", "'2024-02-29T13:14:00'"),
                new Column("smallint", "smallint", "-7"),
                new Column("smallmoney", "smallmoney", "12.34"),
                new Column("sql_variant", "sql_variant", "cast(7 as int)"),
                new Column("sysname", "sysname null", "N'abc'"),
                new Column("text", "text", "'Gruesse'"),
                new Column("time", "time", "'13:14:15.1234567'"),
                // rowversion: the server writes it, whatever the insert says
                new Column("timestamp", "timestamp", ""),
                new Column("tinyint", "tinyint", "200"),
                new Column("uniqueidentifier", "uniqueidentifier",
                        "'A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11'"),
                new Column("varbinary", "varbinary(8)", "0xdeadbeef"),
                new Column("varchar", "varchar(20)", "'x'"),
                new Column("vector", "vector(3)", "'[1,2,3]'"),
                new Column("xml", "xml", "'<a x=\"1\">1</a>'"))) {
            MSSQL.put(column.type(), column);
        }
    }

    @Test
    void everySqlServer2022TypeReadsLikeMssqlJdbc() throws Exception {
        sqlServer("SQL Server 2022", Integer.getInteger("seclume.mssql.port", 1433));
    }

    @Test
    void everySqlServer2025TypeReadsLikeMssqlJdbc() throws Exception {
        sqlServer("SQL Server 2025", Integer.getInteger("seclume.mssql8.port", 1435));
    }

    private static void sqlServer(String name, int port) throws Exception {
        Path secret = locate(".local-mssql-password");
        String host = System.getProperty("seclume.mssql.host", TestHosts.database());
        reachable(host, port, secret);
        Properties vendor = new Properties();
        vendor.setProperty("user", "sa");
        vendor.setProperty("password", Files.readString(secret).trim());
        try (Ours ours = new Ours("jdbc:seclume:sqlserver://" + host
                + ":" + port + "/master?user=sa&trustServerCertificate=true&provider=file&path="
                + slash(secret));
             Connection theirs = DriverManager.getConnection("jdbc:sqlserver://" + host + ":"
                     + port + ";databaseName=master;encrypt=true;trustServerCertificate=true",
                     vendor)) {
            List<Column> columns = new ArrayList<>();
            try (Statement statement = theirs.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "select name from sys.types where is_user_defined = 0 order by name")) {
                while (rows.next()) {
                    String type = rows.getString(1);
                    columns.add(MSSQL.getOrDefault(type, new Column(type, type, null)));
                }
            }
            // A global temporary table: the one connection creates it, the
            // other can read it.
            report(name, columns.size(),
                    runTables(columns, ours, theirs, "##seclume_type_catalog", false));
        }
    }

    // ---- Oracle -------------------------------------------------------------

    /** The column types of the SQL reference, 23ai included. */
    private static final List<Column> ORACLE = List.of(
            new Column("NUMBER", "number", "12.5"),
            new Column("NUMBER(9)", "number(9)", "-7"),
            new Column("NUMBER(10)", "number(10)", "-7"),
            new Column("NUMBER(19)", "number(19)", "9000000000000000000"),
            new Column("NUMBER(10,2)", "number(10,2)", "12.5"),
            new Column("FLOAT", "float", "0.1"),
            new Column("BINARY_FLOAT", "binary_float", "1.5f"),
            new Column("BINARY_DOUBLE", "binary_double", "0.1d"),
            new Column("CHAR", "char(5)", "'x'"),
            new Column("NCHAR", "nchar(5)", "n'ü'"),
            new Column("VARCHAR2", "varchar2(40)", "'Grüße, 東京'"),
            new Column("NVARCHAR2", "nvarchar2(20)", "n'Grüße, 東京'"),
            new Column("CLOB", "clob", "to_clob('Grüße')"),
            new Column("NCLOB", "nclob", "to_nclob('Grüße')"),
            new Column("BLOB", "blob", "hextoraw('deadbeef')"),
            new Column("RAW", "raw(4)", "hextoraw('deadbeef')"),
            new Column("LONG", "long", "'Grüße'"),
            new Column("LONG RAW", "long raw", "hextoraw('deadbeef')"),
            new Column("DATE", "date", "date '2024-02-29'"),
            new Column("TIMESTAMP", "timestamp", "timestamp '2024-02-29 13:14:15.123456'"),
            new Column("TIMESTAMP WITH TIME ZONE", "timestamp with time zone",
                    "timestamp '2024-02-29 13:14:15.123456 +02:00'"),
            new Column("TIMESTAMP WITH TIME ZONE (region)", "timestamp with time zone",
                    "timestamp '2024-02-29 13:14:15 Europe/Vienna'"),
            new Column("TIMESTAMP WITH LOCAL TIME ZONE", "timestamp with local time zone",
                    "timestamp '2024-02-29 13:14:15.123456 +02:00'"),
            new Column("INTERVAL YEAR TO MONTH", "interval year to month",
                    "interval '1-2' year to month"),
            new Column("INTERVAL DAY TO SECOND", "interval day to second",
                    "interval '1 02:03:04.5' day to second"),
            new Column("INTERVAL DAY TO SECOND (negative)", "interval day(3) to second",
                    "interval '-0 02:03:04' day to second"),
            new Column("INTERVAL YEAR TO MONTH (negative)", "interval year to month",
                    "interval '-0-3' year to month"),
            new Column("ROWID", "rowid", "(select rowid from dual)"),
            new Column("UROWID", "urowid", "(select rowid from dual)"),
            new Column("XMLTYPE", "xmltype", "xmltype('<a x=\"1\">1</a>')"),
            new Column("JSON", "json", "json('{\"a\":[1,2],\"b\":\"Grüße\"}')"),
            new Column("BOOLEAN", "boolean", "true"),
            new Column("VECTOR", "vector(4, float32)", "to_vector('[-0.001,1234.5,0,3e30]')"),
            new Column("VECTOR FLOAT64", "vector(2, float64)", "to_vector('[0.1,-2e-300]', 2, float64)"),
            new Column("VECTOR INT8", "vector(3, int8)", "to_vector('[1,-2,127]')"),
            new Column("VECTOR BINARY", "vector(16, binary)", "to_vector('[1,255]', 16, binary)"),
            new Column("VECTOR (any)", "vector", "to_vector('[1.5,2]')"),
            new Column("BFILE", "bfile", "bfilename('DATA_PUMP_DIR', 'x.txt')"),
            new Column("SDO_GEOMETRY", "sdo_geometry",
                    "sdo_geometry(2001, null, sdo_point_type(1, 2, null), null, null)"));

    @Test
    void everyOracleTypeReadsLikeOjdbc() throws Exception {
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        Path secret = locate(".local-oracle-password");
        String host = System.getProperty("seclume.oracle.host", TestHosts.database());
        reachable(host, port, secret);
        try (Ours ours = new Ours("jdbc:seclume:oracle://" + host + ":"
                + port + "/FREEPDB1?user=seclume_test&provider=file&path=" + slash(secret));
             Connection theirs = DriverManager.getConnection(
                     "jdbc:oracle:thin:@//" + host + ":" + port + "/FREEPDB1",
                     JsonFunctionTest.oracleVendor(secret))) {
            report("Oracle", ORACLE.size(),
                    runTables(ORACLE, ours, theirs, "seclume_type_catalog", false));
        }
    }

    /**
     * A column type: how to declare it, and a literal to store in it - null
     * for "no sample", empty for "the server fills it in".
     */
    record Column(String type, String ddl, String literal) {
    }

    /**
     * Where a server has no cast for every type, the type goes into a table:
     * one table per type, created by the vendor's connection, a NULL row and
     * a value row, read by both.
     */
    static List<Outcome> runTables(List<Column> columns, Ours ours, Connection theirs,
            String table, boolean prepared) throws SQLException {
        List<Outcome> outcomes = new ArrayList<>();
        for (Column column : columns) {
            boolean value = column.literal() != null;
            try (Statement statement = theirs.createStatement()) {
                statement.execute("drop table if exists " + table);
                try {
                    statement.execute("create table " + table + " (id int, v " + column.ddl()
                            + ")");
                } catch (SQLException missing) {
                    outcomes.add(new Outcome(column.type(), "not on this server ("
                            + first(missing.getMessage()) + ")"));
                    continue;
                }
                statement.execute("insert into " + table + " (id) values (1)");
                if (value) {
                    try {
                        statement.execute(column.literal().isEmpty()
                                ? "insert into " + table + " (id) values (2)"
                                : "insert into " + table + " (id, v) values (2, "
                                        + column.literal() + ")");
                    } catch (SQLException refused) {
                        System.out.println("  " + column.type() + ": no sample - "
                                + first(refused.getMessage()));
                        value = false;
                    }
                }
            }
            // A text of its own per type: the same text over a table that
            // changed its column type is another question (StaleStatementTest).
            String select = "select v, 42 as c" + outcomes.size() + " from " + table
                    + " where id = ";
            outcomes.addAll(run(List.of(new Sample(column.type(), select + 1,
                    value ? select + 2 : null)), ours, theirs, prepared));
        }
        try (Statement statement = theirs.createStatement()) {
            statement.execute("drop table if exists " + table);
        }
        return outcomes;
    }

    // ---- the comparison -----------------------------------------------------

    /**
     * Runs every sample through both drivers and says what differed.
     *
     * @param prepared whether to run through a PreparedStatement as well - the
     *                 binary row format on MySQL, a second codec
     */
    static List<Outcome> run(List<Sample> samples, Ours ours, Connection theirs,
            boolean prepared) throws SQLException {
        List<Outcome> outcomes = new ArrayList<>();
        for (Sample sample : samples) {
            List<String> problems = new ArrayList<>();
            if (sample.nullSql() != null) {
                compare(sample.nullSql(), ours, theirs, false, problems, "null");
            }
            if (sample.valueSql() == null) {
                problems.add("NULL only - no sample");
            } else {
                compare(sample.valueSql(), ours, theirs, false, problems, "value");
                if (prepared) {
                    compare(sample.valueSql(), ours, theirs, true, problems, "value, prepared");
                }
            }
            // The connection after the type: still in step, or not.
            try (Statement statement = ours.get().createStatement();
                 ResultSet rows = statement.executeQuery(ours.probe)) {
                rows.next();
                if (rows.getInt(1) != 7) {
                    problems.add("the next query answered " + rows.getInt(1));
                }
            } catch (SQLException e) {
                problems.add("the connection broke after it: " + e.getMessage());
            }
            outcomes.add(new Outcome(sample.type(), String.join("; ", problems)));
        }
        return outcomes;
    }

    static void compare(String sql, Ours ours, Connection theirs, boolean prepared,
            List<String> problems, String what) {
        String[] mine;
        String[] vendor;
        try {
            vendor = read(theirs, sql, prepared);
        } catch (SQLException | RuntimeException | LinkageError e) {
            // ojdbc wants xdb.jar for XMLType - the vendor's gap, not ours
            problems.add(what + ": the vendor driver cannot read it either ("
                    + first(e.getMessage()) + ")");
            return;
        }
        try {
            mine = read(ours.get(), sql, prepared);
        } catch (SQLException | RuntimeException e) {
            problems.add(what + ": FAILS - " + e.getClass().getSimpleName() + ": "
                    + first(e.getMessage()));
            return;
        }
        String[] names = {"getString", "getObject class", "type", "type name", "after",
                "getObject value"};
        // Where the vendor hands back a class of its own - PGobject, PGbox,
        // DateTimeOffset - seclume cannot: its answer is a JDK class or the
        // text, and getString has to agree instead.
        boolean own = vendor[1] != null && !vendor[1].startsWith("java.")
                && !vendor[1].startsWith("[");
        for (int i = 0; i < names.length; i++) {
            if (own && (i == 1 || i == 5)) {
                continue;
            }
            if (vendor[i] != null && vendor[i].startsWith(FAILED)) {
                continue;                      // nothing to hold seclume against
            }
            if (mine[i] != null && mine[i].startsWith(FAILED)) {
                problems.add(what + ": " + names[i] + " FAILS - "
                        + mine[i].substring(FAILED.length()));
                continue;
            }
            if (!java.util.Objects.equals(mine[i], vendor[i])) {
                problems.add(what + ": " + names[i] + " seclume=" + shorten(mine[i])
                        + " vendor=" + shorten(vendor[i]));
            }
        }
    }

    /** getString, getObject's class, type, type name, and the column behind. */
    private static String[] read(Connection connection, String sql, boolean prepared)
            throws SQLException {
        Statement statement = prepared ? connection.prepareStatement(sql)
                : connection.createStatement();
        try (statement;
             ResultSet rows = prepared ? ((PreparedStatement) statement).executeQuery()
                     : statement.executeQuery(sql)) {
            if (!rows.next()) {
                return new String[] {"no row", null, null, null, null, null};
            }
            ResultSetMetaData meta = rows.getMetaData();
            // Each accessor on its own: a driver that cannot do one - ojdbc's
            // getString on a BLOB, its getObject on a LONG it has already
            // streamed, on an XMLType without xdb.jar - still answers the rest.
            String text = field(() -> rows.getString(1));
            Object[] object = new Object[1];
            String objectClass = field(() -> {
                object[0] = rows.getObject(1);
                return object[0] == null ? null : object[0].getClass().getName();
            });
            String after = field(() -> rows.getString(2));
            // The value itself only where both sides can hand back the same
            // kind of object: a JDK class. A driver's own class - PGobject,
            // PGpoint - says nothing comparable through toString.
            String value = objectClass != null && objectClass.startsWith(FAILED) ? objectClass
                    : object[0] == null ? null
                    : object[0].getClass().getName().startsWith("java.")
                            ? (object[0] instanceof byte[] bytes ? java.util.HexFormat.of()
                                    .formatHex(bytes) : String.valueOf(object[0]))
                            : "(driver class)";
            return new String[] {text, objectClass, String.valueOf(meta.getColumnType(1)),
                    meta.getColumnTypeName(1), after, value};
        }
    }

    /** Marks an accessor that threw, followed by the exception's class. */
    static final String FAILED = "\u0000failed: ";

    private interface Accessor {
        String get() throws SQLException;
    }

    private static String field(Accessor accessor) {
        try {
            return accessor.get();
        } catch (SQLException | RuntimeException | LinkageError e) {
            return FAILED + e.getClass().getSimpleName() + ": " + first(e.getMessage());
        }
    }

    static void report(String database, int types, List<Outcome> outcomes) {
        StringBuilder text = new StringBuilder("\n==== " + database + ": " + types + " types\n");
        int clean = 0;
        int unchecked = 0;
        int expected = 0;
        List<String> failures = new ArrayList<>();
        List<String> findings = new ArrayList<>();
        String family = database.replaceAll(" \\d{4}", "");
        for (Outcome outcome : outcomes) {
            if (outcome.problem().isEmpty()) {
                clean++;
                continue;
            }
            text.append(String.format("  %-24s %s%n", outcome.type(), outcome.problem()));
            if (outcome.problem().contains("FAILS") || outcome.problem().contains("broke")
                    || outcome.problem().contains("after seclume")
                    || outcome.problem().contains("next query")) {
                failures.add(outcome.type());
                continue;
            }
            // What is left once nothing could be compared: no sample, a type
            // this server lacks, a value the vendor's driver cannot read.
            boolean compared = false;
            // (the server's own message may hold a "; " - not split there)
            for (String part : outcome.problem().startsWith("not on this server")
                    ? new String[0] : outcome.problem().split("; ")) {
                compared |= !(part.equals("NULL only - no sample")
                        || part.startsWith("not on this server")
                        || part.contains("the vendor driver cannot read it either"));
            }
            if (!compared) {
                unchecked++;
            } else if (EXPECTED.containsKey(family + "/" + outcome.type())) {
                expected++;
                text.append(String.format("  %-24s   expected: %s%n", "",
                        EXPECTED.get(family + "/" + outcome.type())));
            } else {
                findings.add(outcome.type());
            }
        }
        text.append("  -> ").append(clean).append(" agree with the vendor driver, ")
                .append(expected).append(" differ for a stated reason, ")
                .append(unchecked).append(" could not be compared, ")
                .append(findings.size() + failures.size()).append(" findings\n");
        System.out.println(text);
        assertTrue(failures.isEmpty(), database + ": types that fail or break the row: "
                + failures + text);
        assertTrue(findings.isEmpty(), database + ": types that read differently: "
                + findings + text);
    }

    /**
     * The differences that are meant, each with its reason. Keyed by database
     * family and type; any other difference fails the test.
     */
    static final Map<String, String> EXPECTED = new LinkedHashMap<>();

    static {
        String ownCode = "the vendor reports a type code outside java.sql.Types; "
                + "seclume reports the standard one";
        EXPECTED.put("PostgreSQL/tid", "a tid is PostgreSQL's row address: seclume reports "
                + "ROWID and getRowId reads it; pgjdbc has no RowId and says OTHER");
        EXPECTED.put("SQL Server/datetimeoffset", ownCode + " (TIMESTAMP_WITH_TIMEZONE)");
        EXPECTED.put("SQL Server/geography", ownCode + " (VARBINARY, the bytes it is)");
        EXPECTED.put("SQL Server/geometry", ownCode + " (VARBINARY, the bytes it is)");
        EXPECTED.put("SQL Server/sql_variant", ownCode + " (OTHER)");
        String utf8 = "mssql-jdbc asks for the UTF8_SUPPORT feature at login and gets "
                + "varchar(max) in UTF-8; seclume does not, and the server sends the same "
                + "text as nvarchar(max)";
        EXPECTED.put("SQL Server/json", utf8);
        EXPECTED.put("SQL Server JSON/json type", utf8);
        EXPECTED.put("SQL Server/vector", utf8);
        EXPECTED.put("Oracle/BINARY_FLOAT", ownCode + " (REAL)");
        EXPECTED.put("Oracle/BINARY_DOUBLE", ownCode + " (DOUBLE)");
        EXPECTED.put("Oracle/TIMESTAMP WITH TIME ZONE", ownCode + " (TIMESTAMP_WITH_TIMEZONE)");
        EXPECTED.put("Oracle/TIMESTAMP WITH TIME ZONE (region)",
                ownCode + " (TIMESTAMP_WITH_TIMEZONE)");
        EXPECTED.put("Oracle/TIMESTAMP WITH LOCAL TIME ZONE", ownCode + " (TIMESTAMP)");
        for (String interval : List.of("INTERVAL YEAR TO MONTH", "INTERVAL DAY TO SECOND",
                "INTERVAL YEAR TO MONTH (negative)", "INTERVAL DAY TO SECOND (negative)")) {
            EXPECTED.put("Oracle/" + interval, ownCode + " (OTHER - JDBC has no interval)");
        }
        EXPECTED.put("Oracle/BFILE", ownCode + " (OTHER - JDBC has no file locator)");
        EXPECTED.put("Oracle/JSON", ownCode + " (OTHER)");
        for (String vector : List.of("VECTOR", "VECTOR FLOAT64", "VECTOR INT8",
                "VECTOR BINARY", "VECTOR (any)")) {
            EXPECTED.put("Oracle/" + vector, ownCode + " (OTHER - JDBC has no vector)");
        }
        for (String json : List.of("JSON_QUERY returning json", "JSON_OBJECT returning json",
                "JSON_TRANSFORM", "JSON() constructor", "JSON_SCALAR", "dot notation",
                "JSON with timestamps")) {
            EXPECTED.put("Oracle JSON/" + json, ownCode + " (OTHER, as for a JSON column)");
        }
        EXPECTED.put("Oracle/BOOLEAN", "ojdbc's getString answers \"false\" for a NULL "
                + "boolean; seclume answers null, as for every other NULL");
    }

    /**
     * seclume's side, opened again when a type broke it - otherwise one
     * broken type hides every type after it.
     */
    static final class Ours implements AutoCloseable {

        private final String url;
        final String probe;
        private Connection connection;

        Ours(String url) {
            this.url = url;
            this.probe = url.contains(":oracle:") ? "select 7 from dual" : "select 7";
        }

        Connection get() throws SQLException {
            if (connection == null || connection.isClosed()) {
                connection = DriverManager.getConnection(url);
            }
            return connection;
        }

        @Override
        public void close() throws SQLException {
            if (connection != null) {
                connection.close();
            }
        }
    }

    // ---- small things -------------------------------------------------------

    static String first(String message) {
        if (message == null) {
            return "";
        }
        int line = message.indexOf('\n');
        return shorten(line < 0 ? message : message.substring(0, line));
    }

    static String shorten(String text) {
        if (text == null) {
            return "null";
        }
        return text.length() > 70 ? text.substring(0, 67) + "..." : text;
    }

    static Path locate(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.abort("no " + name);
        return null;
    }

    static void reachable(String host, int port, Path secret) {
        Assumptions.assumeTrue(secret != null);
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException unreachable) {
            Assumptions.abort("nothing on " + host + ":" + port);
        }
    }

    static String slash(Path path) {
        return path.toString().replace(java.io.File.separatorChar, '/');
    }
}
