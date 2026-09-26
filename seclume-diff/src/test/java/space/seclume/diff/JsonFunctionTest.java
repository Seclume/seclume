package space.seclume.diff;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.TestHosts;

/**
 * Every JSON function each server has, read through seclume and through the
 * vendor's driver, and compared.
 *
 * <p>The type catalog asks whether a type reads; this asks whether what the
 * JSON functions hand back reads - which is a type too, but not always the
 * one the column would have: {@code ->>} is text, {@code jsonb_path_query} a
 * set of {@code jsonb}, {@code FOR JSON} a result split over rows, Oracle's
 * {@code JSON_OBJECT} a {@code VARCHAR2} unless it is told {@code RETURNING
 * JSON}. Each function is one statement with a column behind it, compared
 * the way {@link TypeCatalogTest} compares, with the same list of accepted
 * differences.
 */
@Timeout(600)
class JsonFunctionTest {

    private static final String DOC = "'{\"a\":[1,2,{\"b\":\"Grüße\"}],\"n\":null,\"x\":1.5,"
            + "\"t\":true}'";

    // ---- PostgreSQL ---------------------------------------------------------

    private static final Map<String, String> PG = new LinkedHashMap<>();

    static {
        String j = DOC + "::json";
        String jb = DOC + "::jsonb";
        PG.put("-> (json)", "select " + j + " -> 'a'");
        PG.put("->> (json)", "select " + j + " ->> 'x'");
        PG.put("-> (jsonb)", "select " + jb + " -> 'a'");
        PG.put("->> (jsonb)", "select " + jb + " ->> 'a'");
        PG.put("#>", "select " + jb + " #> '{a,2}'");
        PG.put("#>>", "select " + jb + " #>> '{a,2,b}'");
        PG.put("@>", "select " + jb + " @> '{\"t\":true}'");
        PG.put("?", "select " + jb + " ? 'n'");
        PG.put("?|", "select " + jb + " ?| array['q','x']");
        PG.put("||", "select " + jb + " || '{\"z\":0}'");
        PG.put("- key", "select " + jb + " - 'a'");
        PG.put("#- path", "select " + jb + " #- '{a,0}'");
        PG.put("@? jsonpath", "select " + jb + " @? '$.a[*] ? (@ > 1)'");
        PG.put("@@ jsonpath", "select " + jb + " @@ '$.x > 1'");
        PG.put("to_json", "select to_json('Grüße'::text)");
        PG.put("to_jsonb", "select to_jsonb(row(1, 'a'))");
        PG.put("array_to_json", "select array_to_json(array[1,2,3])");
        PG.put("row_to_json", "select row_to_json(row(1, 'a'))");
        PG.put("json_build_array", "select json_build_array(1, 'a', null, true)");
        PG.put("jsonb_build_object", "select jsonb_build_object('a', 1, 'b', now()::date)");
        PG.put("json_object", "select json_object('{a,1,b,2}')");
        PG.put("json_array_length", "select json_array_length(" + j + " -> 'a')");
        PG.put("jsonb_array_length", "select jsonb_array_length(" + jb + " -> 'a')");
        PG.put("json_typeof", "select json_typeof(" + j + " -> 'x')");
        PG.put("jsonb_typeof", "select jsonb_typeof(" + jb + " -> 'n')");
        PG.put("json_strip_nulls", "select json_strip_nulls(" + j + ")");
        PG.put("jsonb_set", "select jsonb_set(" + jb + ", '{x}', '2')");
        PG.put("jsonb_insert", "select jsonb_insert(" + jb + ", '{a,0}', '0')");
        PG.put("jsonb_pretty", "select jsonb_pretty(" + jb + ")");
        PG.put("jsonb_path_query_array", "select jsonb_path_query_array(" + jb + ", '$.a[*]')");
        PG.put("jsonb_path_query_first", "select jsonb_path_query_first(" + jb + ", '$.a[2].b')");
        PG.put("jsonb_path_exists", "select jsonb_path_exists(" + jb + ", '$.a[*] ? (@ == 2)')");
        PG.put("jsonb_path_match", "select jsonb_path_match(" + jb + ", '$.x > 1')");
        PG.put("json_each (first row)", "select value from json_each(" + j + ") limit 1");
        PG.put("jsonb_each_text (first row)",
                "select value from jsonb_each_text(" + jb + ") limit 1");
        PG.put("json_array_elements (first row)",
                "select value from json_array_elements(" + j + " -> 'a') limit 1");
        PG.put("jsonb_object_keys (first row)",
                "select k from jsonb_object_keys(" + jb + ") k limit 1");
        PG.put("jsonb_path_query (first row)",
                "select v from jsonb_path_query(" + jb + ", '$.a[*]') v limit 1");
        PG.put("json_populate_record", "select (json_populate_record(null::record_t_json, "
                + "'{\"a\":1}')).a");
        PG.put("json_to_record", "select a from json_to_record('{\"a\":1,\"b\":\"x\"}') "
                + "as r(a int, b text)");
        PG.put("json_agg", "select json_agg(g) from generate_series(1, 3) g");
        PG.put("jsonb_object_agg", "select jsonb_object_agg('k' || g, g) "
                + "from generate_series(1, 3) g");
        PG.put("IS JSON", "select " + DOC + " is json object");
        PG.put("JSON_EXISTS", "select json_exists(" + jb + ", '$.a[2]')");
        PG.put("JSON_VALUE", "select json_value(" + jb + ", '$.a[2].b')");
        PG.put("JSON_VALUE returning int", "select json_value(" + jb + ", '$.a[1]' "
                + "returning int)");
        PG.put("JSON_QUERY", "select json_query(" + jb + ", '$.a')");
        PG.put("JSON_OBJECT (SQL)", "select json_object('a' : 1, 'b' : 'x')");
        PG.put("JSON_ARRAY (SQL)", "select json_array(1, 'a', true)");
        PG.put("JSON_ARRAYAGG", "select json_arrayagg(g) from generate_series(1, 3) g");
        PG.put("JSON_OBJECTAGG", "select json_objectagg('k' || g : g) "
                + "from generate_series(1, 3) g");
        PG.put("JSON_TABLE (first row)", "select * from json_table(" + jb + ", '$.a[*]' "
                + "columns (v text path '$')) limit 1");
        PG.put("JSON() constructor", "select json('[1,2]')");
        PG.put("JSON_SCALAR", "select json_scalar(1.5)");
        PG.put("JSON_SERIALIZE", "select json_serialize('{\"a\":1}' returning text)");
    }

    @Test
    void postgresql() throws Exception {
        Path secret = TypeCatalogTest.locate(TestHosts.postgresPasswordFile());
        String host = TestHosts.postgres();
        int port = TestHosts.postgresPort();
        TypeCatalogTest.reachable(host, port, secret);
        Properties vendor = vendor("seclume_test", secret);
        try (TypeCatalogTest.Ours ours = new TypeCatalogTest.Ours("jdbc:seclume:postgresql://"
                + host + ":" + port + "/seclume_test?user=seclume_test&tls=off&provider=file"
                + "&path=" + TypeCatalogTest.slash(secret));
             Connection theirs = DriverManager.getConnection(
                     "jdbc:postgresql://" + host + ":" + port + "/seclume_test", vendor)) {
            try (var statement = theirs.createStatement()) {
                statement.execute("drop type if exists record_t_json");
                statement.execute("create type record_t_json as (a int)");
            }
            try {
                TypeCatalogTest.report("PostgreSQL JSON", PG.size(),
                        TypeCatalogTest.run(samples(PG, ""), ours, theirs, false));
            } finally {
                try (var statement = theirs.createStatement()) {
                    statement.execute("drop type if exists record_t_json");
                }
            }
        }
    }

    // ---- MySQL --------------------------------------------------------------

    private static final Map<String, String> MYSQL = new LinkedHashMap<>();

    static {
        String j = "cast(" + DOC + " as json)";
        MYSQL.put("->", "select j -> '$.a' from (select " + j + " j) t");
        MYSQL.put("->>", "select j ->> '$.a[2].b' from (select " + j + " j) t");
        MYSQL.put("JSON_ARRAY", "select json_array(1, 'a', null, true, 1.5)");
        MYSQL.put("JSON_OBJECT", "select json_object('a', 1, 'b', 'Grüße')");
        MYSQL.put("JSON_QUOTE", "select json_quote('a\"b')");
        MYSQL.put("JSON_CONTAINS", "select json_contains(" + j + ", '1', '$.a')");
        MYSQL.put("JSON_CONTAINS_PATH", "select json_contains_path(" + j + ", 'one', "
                + "'$.a', '$.q')");
        MYSQL.put("JSON_EXTRACT", "select json_extract(" + j + ", '$.a[2]')");
        MYSQL.put("JSON_KEYS", "select json_keys(" + j + ")");
        MYSQL.put("JSON_OVERLAPS", "select json_overlaps('[1,2]', '[2,3]')");
        MYSQL.put("JSON_SEARCH", "select json_search(" + j + ", 'one', 'Grüße')");
        MYSQL.put("JSON_VALUE", "select json_value(" + j + ", '$.x')");
        MYSQL.put("JSON_VALUE returning", "select json_value(" + j + ", '$.x' "
                + "returning decimal(4,2))");
        MYSQL.put("MEMBER OF", "select 2 member of ('[1,2]')");
        MYSQL.put("JSON_ARRAY_APPEND", "select json_array_append(" + j + ", '$.a', 3)");
        MYSQL.put("JSON_ARRAY_INSERT", "select json_array_insert(" + j + ", '$.a[0]', 0)");
        MYSQL.put("JSON_INSERT", "select json_insert(" + j + ", '$.z', 0)");
        MYSQL.put("JSON_MERGE_PATCH", "select json_merge_patch(" + j + ", '{\"x\":null}')");
        MYSQL.put("JSON_MERGE_PRESERVE", "select json_merge_preserve('[1]', '[2]')");
        MYSQL.put("JSON_REMOVE", "select json_remove(" + j + ", '$.a')");
        MYSQL.put("JSON_REPLACE", "select json_replace(" + j + ", '$.x', 2)");
        MYSQL.put("JSON_SET", "select json_set(" + j + ", '$.x', 2, '$.y', 3)");
        MYSQL.put("JSON_UNQUOTE", "select json_unquote('\"Grüße\"')");
        MYSQL.put("JSON_DEPTH", "select json_depth(" + j + ")");
        MYSQL.put("JSON_LENGTH", "select json_length(" + j + ", '$.a')");
        MYSQL.put("JSON_TYPE", "select json_type(" + j + ")");
        MYSQL.put("JSON_VALID", "select json_valid('{')");
        MYSQL.put("JSON_PRETTY", "select json_pretty(" + j + ")");
        MYSQL.put("JSON_STORAGE_SIZE", "select json_storage_size(" + j + ")");
        MYSQL.put("JSON_SCHEMA_VALID", "select json_schema_valid('{\"type\":\"object\"}', "
                + j + ")");
        MYSQL.put("JSON_ARRAYAGG", "select json_arrayagg(v) from (select 1 v union all "
                + "select 2) t");
        MYSQL.put("JSON_OBJECTAGG", "select json_objectagg(k, v) from (select 'a' k, 1 v "
                + "union all select 'b', 2) t");
        MYSQL.put("JSON_TABLE (first row)", "select v from json_table(" + j + ", '$.a[*]' "
                + "columns (v json path '$')) t limit 1");
        MYSQL.put("JSON_TABLE int column", "select v from json_table('[1,2]', '$[*]' "
                + "columns (v int path '$')) t limit 1");
    }

    @Test
    void mysql() throws Exception {
        int port = Integer.getInteger("seclume.mysql.port", 3307);
        Path secret = TypeCatalogTest.locate(".local-mysql-password");
        String host = System.getProperty("seclume.mysql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        try (TypeCatalogTest.Ours ours = new TypeCatalogTest.Ours("jdbc:seclume:mysql://" + host
                + ":" + port + "/seclume_test?user=seclume_test&tls=off"
                + "&allowPublicKeyRetrieval=true&provider=file&path="
                + TypeCatalogTest.slash(secret));
             Connection theirs = DriverManager.getConnection("jdbc:mysql://" + host + ":" + port
                     + "/seclume_test?allowPublicKeyRetrieval=true&sslMode=DISABLED"
                     + "&useServerPrepStmts=true", vendor("seclume_test", secret))) {
            TypeCatalogTest.report("MySQL JSON", MYSQL.size(),
                    TypeCatalogTest.run(samples(MYSQL, ""), ours, theirs, true));
        }
    }

    // ---- SQL Server ---------------------------------------------------------

    private static final Map<String, String> MSSQL = new LinkedHashMap<>();

    static {
        String j = "N" + DOC;
        MSSQL.put("ISJSON", "select isjson(" + j + ")");
        MSSQL.put("JSON_VALUE", "select json_value(" + j + ", '$.a[2].b')");
        MSSQL.put("JSON_QUERY", "select json_query(" + j + ", '$.a')");
        MSSQL.put("JSON_MODIFY", "select json_modify(" + j + ", '$.x', 2)");
        MSSQL.put("JSON_PATH_EXISTS", "select json_path_exists(" + j + ", '$.a')");
        MSSQL.put("JSON_OBJECT", "select json_object('a': 1, 'b': N'Grüße')");
        MSSQL.put("JSON_ARRAY", "select json_array(1, 'a', null)");
        MSSQL.put("OPENJSON (first row)", "select top 1 [value] from openjson(" + j + ")");
        MSSQL.put("OPENJSON with schema", "select top 1 v from openjson(" + j + ", '$.a') "
                + "with (v int '$')");
        MSSQL.put("FOR JSON PATH", "select (select 1 as a, N'Grüße' as b for json path)");
        MSSQL.put("FOR JSON AUTO", "select (select name from sys.databases where "
                + "database_id = 1 for json auto), 42");
        MSSQL.put("JSON_OBJECTAGG", "select json_objectagg(k: v) from (values ('a', 1), "
                + "('b', 2)) t(k, v)");
        MSSQL.put("JSON_ARRAYAGG", "select json_arrayagg(v) from (values (1), (2)) t(v)");
        MSSQL.put("json type", "select cast(" + j + " as json)");
        MSSQL.put("JSON_CONTAINS", "select json_contains(cast(" + j + " as json), 1, '$.a')");
    }

    @Test
    void sqlServer2022() throws Exception {
        sqlServer("SQL Server 2022 JSON", Integer.getInteger("seclume.mssql.port", 1433));
    }

    @Test
    void sqlServer2025() throws Exception {
        sqlServer("SQL Server 2025 JSON", Integer.getInteger("seclume.mssql8.port", 1435));
    }

    private static void sqlServer(String name, int port) throws Exception {
        Path secret = TypeCatalogTest.locate(".local-mssql-password");
        String host = System.getProperty("seclume.mssql.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        try (TypeCatalogTest.Ours ours = new TypeCatalogTest.Ours("jdbc:seclume:sqlserver://"
                + host + ":" + port + "/master?user=sa&trustServerCertificate=true"
                + "&provider=file&path=" + TypeCatalogTest.slash(secret));
             Connection theirs = DriverManager.getConnection("jdbc:sqlserver://" + host + ":"
                     + port + ";databaseName=master;encrypt=true;trustServerCertificate=true",
                     vendor("sa", secret))) {
            TypeCatalogTest.report(name, MSSQL.size(),
                    TypeCatalogTest.run(samples(MSSQL, ""), ours, theirs, false));
        }
    }

    // ---- Oracle -------------------------------------------------------------

    private static final Map<String, String> ORACLE = new LinkedHashMap<>();

    static {
        String j = DOC;
        String jj = "json(" + DOC + ")";
        ORACLE.put("IS JSON", "select case when " + j + " is json then 1 else 0 end");
        ORACLE.put("JSON_VALUE", "select json_value(" + j + ", '$.a[2].b')");
        ORACLE.put("JSON_VALUE returning number", "select json_value(" + j + ", '$.x' "
                + "returning number)");
        ORACLE.put("JSON_QUERY", "select json_query(" + j + ", '$.a')");
        ORACLE.put("JSON_QUERY returning json", "select json_query(" + j + ", '$.a' "
                + "returning json)");
        ORACLE.put("JSON_EXISTS", "select case when json_exists(" + j + ", '$.a[2]') "
                + "then 1 else 0 end");
        ORACLE.put("JSON_OBJECT", "select json_object('a' value 1, 'b' value 'Grüße')");
        ORACLE.put("JSON_OBJECT returning json", "select json_object('a' value 1 "
                + "returning json)");
        ORACLE.put("JSON_OBJECT returning clob", "select json_object('a' value 1 "
                + "returning clob)");
        ORACLE.put("JSON_ARRAY", "select json_array(1, 'a', null, true)");
        ORACLE.put("JSON with timestamps", "select json_object("
                + "'t' value timestamp '2024-02-29 13:14:15.5 +02:00', "
                + "'s' value timestamp '2024-02-29 13:14:15', "
                + "'d' value date '2024-02-29' returning json)");
        ORACLE.put("JSON_ARRAYAGG", "select json_arrayagg(level) from dual "
                + "connect by level <= 3");
        ORACLE.put("JSON_OBJECTAGG", "select json_objectagg(key 'k' || level value level) "
                + "from dual connect by level <= 3");
        ORACLE.put("JSON_SERIALIZE", "select json_serialize(" + jj + " pretty)");
        ORACLE.put("JSON_TRANSFORM", "select json_transform(" + jj + ", set '$.x' = 2)");
        ORACLE.put("JSON_MERGEPATCH", "select json_mergepatch(" + j + ", '{\"x\":null}')");
        ORACLE.put("JSON() constructor", "select " + jj);
        ORACLE.put("JSON_SCALAR", "select json_scalar(1.5)");
        ORACLE.put("dot notation", "select t.d.a from (select " + jj + " d) t");
        ORACLE.put("JSON_TABLE (first row)", "select v from json_table(" + j + ", '$.a[*]' "
                + "columns (v varchar2(20) path '$')) where rownum = 1");
        ORACLE.put("JSON_TABLE number column", "select v from json_table('[1,2]', '$[*]' "
                + "columns (v number path '$')) where rownum = 1");
        ORACLE.put("JSON_DATAGUIDE", "select json_dataguide(" + j + ")");
        ORACLE.put("JSON_EQUAL", "select case when json_equal('{\"a\":1}', '{ \"a\" : 1 }') "
                + "then 1 else 0 end");
    }

    @Test
    void oracle() throws Exception {
        int port = Integer.getInteger("seclume.oracle.port", 1521);
        Path secret = TypeCatalogTest.locate(".local-oracle-password");
        String host = System.getProperty("seclume.oracle.host", TestHosts.database());
        TypeCatalogTest.reachable(host, port, secret);
        try (TypeCatalogTest.Ours ours = new TypeCatalogTest.Ours("jdbc:seclume:oracle://" + host
                + ":" + port + "/FREEPDB1?user=seclume_test&provider=file&path="
                + TypeCatalogTest.slash(secret));
             Connection theirs = DriverManager.getConnection("jdbc:oracle:thin:@//" + host + ":"
                     + port + "/FREEPDB1", oracleVendor(secret))) {
            TypeCatalogTest.report("Oracle JSON", ORACLE.size(),
                    TypeCatalogTest.run(samples(ORACLE, " from dual"), ours, theirs, false));
        }
    }

    // ---- small things -------------------------------------------------------

    /**
     * Each statement with a column behind it. A statement that already has a
     * FROM gets the column in its select list; one without gets the tail
     * ({@code from dual} on Oracle); one that has its column already stays.
     */
    private static List<TypeCatalogTest.Sample> samples(Map<String, String> functions,
            String tail) {
        List<TypeCatalogTest.Sample> samples = new ArrayList<>();
        for (Map.Entry<String, String> function : functions.entrySet()) {
            String sql = function.getValue();
            int from = sql.toLowerCase(java.util.Locale.ROOT).indexOf(" from ");
            String withColumn = sql.endsWith(", 42") ? sql
                    : from < 0 ? sql + ", 42" + tail
                    : sql.substring(0, from) + ", 42" + sql.substring(from);
            samples.add(new TypeCatalogTest.Sample(function.getKey(), null, withColumn));
        }
        return samples;
    }

    /**
     * ojdbc refuses getObject on a native JSON value unless told which class
     * to hand out; told String, it is comparable with seclume's answer.
     */
    static Properties oracleVendor(Path secret) throws Exception {
        Properties vendor = vendor("seclume_test", secret);
        vendor.setProperty("oracle.jdbc.jsonDefaultGetObjectType", "java.lang.String");
        return vendor;
    }

    static Properties vendor(String user, Path secret) throws Exception {
        Properties vendor = new Properties();
        vendor.setProperty("user", user);
        vendor.setProperty("password", Files.readString(secret).trim());
        return vendor;
    }
}
