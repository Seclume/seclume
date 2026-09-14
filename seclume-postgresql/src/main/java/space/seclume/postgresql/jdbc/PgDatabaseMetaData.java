package space.seclume.postgresql.jdbc;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.RowIdLifetime;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * What the driver has to say about the server and about itself.
 *
 * <p>The information about tables and columns comes from real queries against
 * the system catalog - the same ones {@code psql \d} issues. Everything that
 * gives a fixed answer here gives it the way this driver actually behaves:
 * {@code supportsSavepoints()} is {@code false} because it has none, not
 * {@code true} because PostgreSQL would have them.
 */
final class PgDatabaseMetaData implements DatabaseMetaData {

    private final PgConnection connection;

    PgDatabaseMetaData(PgConnection connection) {
        this.connection = connection;
    }

    private ResultSet query(String sql) throws SQLException {
        Statement statement = connection.createStatement();
        return statement.executeQuery(sql);
    }

    /**
     * The type OID mapped to a {@link java.sql.Types} value - as SQL, because
     * it has to happen per row.
     *
     * <p>Hibernate reads this column when {@code ddl-auto=validate} compares
     * the schema, and a driver that answers 0 everywhere makes every column
     * look wrong. See {@code docs/roadmap.md}.
     *
     * <p>Mapped by OID rather than by type name: the name depends on the
     * search path and on how the type was written, the OID does not.
     */
    private static final String SQL_TYPE_CASE = """
            case a.atttypid
                 when 16 then 16      -- bool
                 when 20 then -5      -- int8
                 when 21 then 5       -- int2
                 when 23 then 4       -- int4
                 when 700 then 7      -- float4
                 when 701 then 8      -- float8
                 when 1700 then 2     -- numeric
                 when 1042 then 1     -- bpchar
                 when 1043 then 12    -- varchar
                 when 25 then 12      -- text
                 when 17 then -2      -- bytea
                 when 1082 then 91    -- date
                 when 1083 then 92    -- time
                 when 1266 then 2013  -- timetz
                 when 1114 then 93    -- timestamp
                 when 1184 then 2014  -- timestamptz
                 else 1111
            end""";
    /** A literal for a query - single quotes doubled. */
    private static String literal(String value) {
        return "'" + value.replace("'", "''") + "'";
    }

    /** A pattern such as {@code %} or {@code null} as a LIKE condition. */
    private static String like(String column, String pattern) {
        if (pattern == null || "%".equals(pattern)) {
            return "true";
        }
        return column + " like " + literal(pattern);
    }

    // ---- catalogs --------------------------------------------------------

    @Override
    public ResultSet getTables(String catalog, String schemaPattern, String tableNamePattern,
                               String[] types) throws SQLException {
        StringBuilder kinds = new StringBuilder();
        if (types == null) {
            kinds.append("'r','p','v','m','f'");
        } else {
            for (String type : types) {
                if (kinds.length() > 0) {
                    kinds.append(',');
                }
                kinds.append(switch (type.toUpperCase(java.util.Locale.ROOT)) {
                    case "TABLE" -> "'r','p'";
                    case "VIEW" -> "'v'";
                    case "MATERIALIZED VIEW" -> "'m'";
                    case "FOREIGN TABLE" -> "'f'";
                    case "SYSTEM TABLE" -> "'r'";
                    default -> "''";
                });
            }
        }
        return query("""
                select current_database() as "TABLE_CAT", n.nspname as "TABLE_SCHEM",
                       c.relname as "TABLE_NAME",
                       case c.relkind when 'r' then 'TABLE' when 'p' then 'TABLE'
                                      when 'v' then 'VIEW' when 'm' then 'MATERIALIZED VIEW'
                                      when 'f' then 'FOREIGN TABLE' else 'TABLE' end as "TABLE_TYPE",
                       d.description as "REMARKS",
                       null::text as "TYPE_CAT", null::text as "TYPE_SCHEM",
                       null::text as "TYPE_NAME", null::text as "SELF_REFERENCING_COL_NAME",
                       null::text as "REF_GENERATION"
                from pg_catalog.pg_class c
                join pg_catalog.pg_namespace n on n.oid = c.relnamespace
                left join pg_catalog.pg_description d on d.objoid = c.oid and d.objsubid = 0
                where c.relkind in (%s) and %s and %s
                order by 2, 3
                """.formatted(kinds, like("n.nspname", schemaPattern),
                        like("c.relname", tableNamePattern)));
    }

    @Override
    public ResultSet getColumns(String catalog, String schemaPattern, String tableNamePattern,
                                String columnNamePattern) throws SQLException {
        return query("""
                select current_database() as "TABLE_CAT", n.nspname as "TABLE_SCHEM",
                       c.relname as "TABLE_NAME", a.attname as "COLUMN_NAME",
                       %s as "DATA_TYPE", format_type(a.atttypid, a.atttypmod) as "TYPE_NAME",
                       coalesce(information_schema._pg_char_max_length(a.atttypid, a.atttypmod),
                                information_schema._pg_numeric_precision(a.atttypid, a.atttypmod),
                                0) as "COLUMN_SIZE",
                       null::int as "BUFFER_LENGTH",
                       information_schema._pg_numeric_scale(a.atttypid, a.atttypmod) as "DECIMAL_DIGITS",
                       10 as "NUM_PREC_RADIX",
                       case when a.attnotnull then 0 else 1 end as "NULLABLE",
                       d.description as "REMARKS",
                       pg_get_expr(ad.adbin, ad.adrelid) as "COLUMN_DEF",
                       null::int as "SQL_DATA_TYPE", null::int as "SQL_DATETIME_SUB",
                       null::int as "CHAR_OCTET_LENGTH", a.attnum as "ORDINAL_POSITION",
                       case when a.attnotnull then 'NO' else 'YES' end as "IS_NULLABLE",
                       null::text as "SCOPE_CATALOG", null::text as "SCOPE_SCHEMA",
                       null::text as "SCOPE_TABLE", null::int as "SOURCE_DATA_TYPE",
                       case when a.attidentity <> '' then 'YES'
                            when pg_get_expr(ad.adbin, ad.adrelid) like 'nextval(%%' then 'YES'
                            else 'NO' end as "IS_AUTOINCREMENT",
                       case when a.attgenerated <> '' then 'YES' else 'NO' end as "IS_GENERATEDCOLUMN",
                       a.atttypid as "ZL_TYPE_OID"
                from pg_catalog.pg_attribute a
                join pg_catalog.pg_class c on c.oid = a.attrelid
                join pg_catalog.pg_namespace n on n.oid = c.relnamespace
                left join pg_catalog.pg_attrdef ad on ad.adrelid = c.oid and ad.adnum = a.attnum
                left join pg_catalog.pg_description d on d.objoid = c.oid and d.objsubid = a.attnum
                where a.attnum > 0 and not a.attisdropped
                  and c.relkind in ('r','p','v','m','f')
                  and %s and %s and %s
                order by 2, 3, 17
                """.formatted(SQL_TYPE_CASE, like("n.nspname", schemaPattern),
                        like("c.relname", tableNamePattern),
                        like("a.attname", columnNamePattern)));
    }

    @Override
    public ResultSet getPrimaryKeys(String catalog, String schema, String table)
            throws SQLException {
        return query("""
                select current_database() as "TABLE_CAT", n.nspname as "TABLE_SCHEM",
                       c.relname as "TABLE_NAME", a.attname as "COLUMN_NAME",
                       k.ordinality::int as "KEY_SEQ", i.relname as "PK_NAME"
                from pg_catalog.pg_constraint con
                join pg_catalog.pg_class c on c.oid = con.conrelid
                join pg_catalog.pg_namespace n on n.oid = c.relnamespace
                join pg_catalog.pg_class i on i.oid = con.conindid
                join lateral unnest(con.conkey) with ordinality as k(attnum, ordinality) on true
                join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum = k.attnum
                where con.contype = 'p' and %s and %s
                order by 4
                """.formatted(schema == null ? "true" : "n.nspname = " + literal(schema),
                        table == null ? "true" : "c.relname = " + literal(table)));
    }

    @Override
    public ResultSet getImportedKeys(String catalog, String schema, String table)
            throws SQLException {
        return foreignKeys(schema, table, true);
    }

    @Override
    public ResultSet getExportedKeys(String catalog, String schema, String table)
            throws SQLException {
        return foreignKeys(schema, table, false);
    }

    private ResultSet foreignKeys(String schema, String table, boolean imported)
            throws SQLException {
        String side = imported ? "c.relname" : "rc.relname";
        String sideSchema = imported ? "n.nspname" : "rn.nspname";
        return query("""
                select current_database() as "PKTABLE_CAT", rn.nspname as "PKTABLE_SCHEM",
                       rc.relname as "PKTABLE_NAME", ra.attname as "PKCOLUMN_NAME",
                       current_database() as "FKTABLE_CAT", n.nspname as "FKTABLE_SCHEM",
                       c.relname as "FKTABLE_NAME", a.attname as "FKCOLUMN_NAME",
                       k.ordinality::int as "KEY_SEQ",
                       case con.confupdtype when 'c' then 0 when 'n' then 2 when 'd' then 4
                                            when 'r' then 1 else 3 end as "UPDATE_RULE",
                       case con.confdeltype when 'c' then 0 when 'n' then 2 when 'd' then 4
                                            when 'r' then 1 else 3 end as "DELETE_RULE",
                       con.conname as "FK_NAME", ri.relname as "PK_NAME",
                       case when con.condeferrable then 5 else 7 end as "DEFERRABILITY"
                from pg_catalog.pg_constraint con
                join pg_catalog.pg_class c on c.oid = con.conrelid
                join pg_catalog.pg_namespace n on n.oid = c.relnamespace
                join pg_catalog.pg_class rc on rc.oid = con.confrelid
                join pg_catalog.pg_namespace rn on rn.oid = rc.relnamespace
                join pg_catalog.pg_class ri on ri.oid = con.conindid
                join lateral unnest(con.conkey, con.confkey)
                     with ordinality as k(attnum, rattnum, ordinality) on true
                join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum = k.attnum
                join pg_catalog.pg_attribute ra on ra.attrelid = rc.oid and ra.attnum = k.rattnum
                where con.contype = 'f' and %s and %s
                order by 3, 9
                """.formatted(schema == null ? "true" : sideSchema + " = " + literal(schema),
                        table == null ? "true" : side + " = " + literal(table)));
    }

    @Override
    public ResultSet getIndexInfo(String catalog, String schema, String table, boolean unique,
                                  boolean approximate) throws SQLException {
        return query("""
                select current_database() as "TABLE_CAT", n.nspname as "TABLE_SCHEM",
                       c.relname as "TABLE_NAME", not ix.indisunique as "NON_UNIQUE",
                       null::text as "INDEX_QUALIFIER", i.relname as "INDEX_NAME",
                       3 as "TYPE", k.ordinality::int as "ORDINAL_POSITION",
                       a.attname as "COLUMN_NAME", null::text as "ASC_OR_DESC",
                       c.reltuples::bigint as "CARDINALITY", c.relpages::bigint as "PAGES",
                       null::text as "FILTER_CONDITION"
                from pg_catalog.pg_index ix
                join pg_catalog.pg_class c on c.oid = ix.indrelid
                join pg_catalog.pg_class i on i.oid = ix.indexrelid
                join pg_catalog.pg_namespace n on n.oid = c.relnamespace
                join lateral unnest(ix.indkey) with ordinality as k(attnum, ordinality) on true
                join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum = k.attnum
                where %s and %s and (%s or ix.indisunique)
                order by 4, 6, 8
                """.formatted(schema == null ? "true" : "n.nspname = " + literal(schema),
                        table == null ? "true" : "c.relname = " + literal(table),
                        unique ? "false" : "true"));
    }

    @Override
    public ResultSet getSchemas() throws SQLException {
        return query("""
                select nspname as "TABLE_SCHEM", current_database() as "TABLE_CATALOG"
                from pg_catalog.pg_namespace
                where nspname not like 'pg\\_temp%' and nspname not like 'pg\\_toast%'
                order by 1
                """);
    }

    @Override
    public ResultSet getSchemas(String catalog, String schemaPattern) throws SQLException {
        return query("""
                select nspname as "TABLE_SCHEM", current_database() as "TABLE_CATALOG"
                from pg_catalog.pg_namespace
                where nspname not like 'pg\\_temp%%' and nspname not like 'pg\\_toast%%' and %s
                order by 1
                """.formatted(like("nspname", schemaPattern)));
    }

    @Override
    public ResultSet getCatalogs() throws SQLException {
        return query("select datname as \"TABLE_CAT\" from pg_catalog.pg_database "
                + "where not datistemplate order by 1");
    }

    @Override
    public ResultSet getTableTypes() throws SQLException {
        return query("""
                select * from (values ('TABLE'), ('VIEW'), ('MATERIALIZED VIEW'),
                                      ('FOREIGN TABLE')) as t("TABLE_TYPE")
                order by 1
                """);
    }

    /**
     * The types this driver can actually read and write.
     *
     * <p>Deliberately not a query against {@code pg_type}: the server has
     * several hundred types, and this driver decodes a few dozen. A list that
     * names them all would be a promise the driver does not keep - and Flyway
     * and Liquibase read this list and believe it.
     */
    @Override
    public ResultSet getTypeInfo() throws SQLException {
        return query("""
                select "TYPE_NAME", "DATA_TYPE", "PRECISION", "LITERAL_PREFIX",
                       "LITERAL_SUFFIX", "CREATE_PARAMS", 1 as "NULLABLE",
                       "CASE_SENSITIVE", 3 as "SEARCHABLE",
                       false as "UNSIGNED_ATTRIBUTE", "FIXED_PREC_SCALE",
                       "AUTO_INCREMENT", "TYPE_NAME" as "LOCAL_TYPE_NAME",
                       "MINIMUM_SCALE", "MAXIMUM_SCALE", null::int as "SQL_DATA_TYPE",
                       null::int as "SQL_DATETIME_SUB", 10 as "NUM_PREC_RADIX"
                from (values
                    ('bool',        16,   1,          null, null, null,
                     false, false, false, 0, 0),
                    ('int8',        -5,   19,         null, null, null,
                     false, false, true,  0, 0),
                    ('int2',        5,    5,          null, null, null,
                     false, false, true,  0, 0),
                    ('int4',        4,    10,         null, null, null,
                     false, false, true,  0, 0),
                    ('float4',      7,    9,          null, null, null,
                     false, false, false, 0, 0),
                    ('float8',      8,    17,         null, null, null,
                     false, false, false, 0, 0),
                    ('numeric',     2,    1000,       null, null, 'precision,scale',
                     false, true,  false, 0, 1000),
                    ('bpchar',      1,    10485760,   '''', '''', 'length',
                     true,  false, false, 0, 0),
                    ('varchar',     12,   10485760,   '''', '''', 'length',
                     true,  false, false, 0, 0),
                    ('text',        12,   2147483647, '''', '''', null,
                     true,  false, false, 0, 0),
                    ('bytea',       -2,   2147483647, '''', '''', null,
                     true,  false, false, 0, 0),
                    ('date',        91,   13,         '''', '''', null,
                     false, false, false, 0, 0),
                    ('time',        92,   15,         '''', '''', 'precision',
                     false, false, false, 0, 6),
                    ('timetz',      2013, 21,         '''', '''', 'precision',
                     false, false, false, 0, 6),
                    ('timestamp',   93,   29,         '''', '''', 'precision',
                     false, false, false, 0, 6),
                    ('timestamptz', 2014, 35,         '''', '''', 'precision',
                     false, false, false, 0, 6)
                ) as t("TYPE_NAME", "DATA_TYPE", "PRECISION", "LITERAL_PREFIX",
                       "LITERAL_SUFFIX", "CREATE_PARAMS", "CASE_SENSITIVE",
                       "FIXED_PREC_SCALE", "AUTO_INCREMENT", "MINIMUM_SCALE",
                       "MAXIMUM_SCALE")
                order by "DATA_TYPE", "PRECISION"
                """);
    }

    // Information this driver does not give: empty rather than guessed.

    @Override
    public ResultSet getProcedures(String c, String s, String p) throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getProcedureColumns(String c, String s, String p, String col)
            throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getFunctions(String c, String s, String p) throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getFunctionColumns(String c, String s, String p, String col)
            throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getColumnPrivileges(String c, String s, String t, String col)
            throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getTablePrivileges(String c, String s, String t) throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getBestRowIdentifier(String c, String s, String t, int scope,
                                          boolean nullable) throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getVersionColumns(String c, String s, String t) throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getCrossReference(String pc, String ps, String pt, String fc, String fs,
                                       String ft) throws SQLException {
        return foreignKeys(fs, ft, true);
    }

    @Override
    public ResultSet getUDTs(String c, String s, String t, int[] types) throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getSuperTypes(String c, String s, String t) throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getSuperTables(String c, String s, String t) throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getAttributes(String c, String s, String t, String a) throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getClientInfoProperties() throws SQLException {
        return empty();
    }

    @Override
    public ResultSet getPseudoColumns(String c, String s, String t, String col)
            throws SQLException {
        return empty();
    }

    private ResultSet empty() throws SQLException {
        return query("select null::text as \"NAME\" where false");
    }

    // ---- server and driver -----------------------------------------------

    @Override
    public Connection getConnection() {
        return connection;
    }

    @Override
    public String getURL() {
        return connection.url();
    }

    @Override
    public String getUserName() throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("select current_user")) {
            return result.next() ? result.getString(1) : null;
        }
    }

    @Override
    public String getDatabaseProductName() {
        return "PostgreSQL";
    }

    @Override
    public String getDatabaseProductVersion() throws SQLException {
        return connection.session().parameters().getOrDefault("server_version", "unknown");
    }

    @Override
    public int getDatabaseMajorVersion() throws SQLException {
        String version = getDatabaseProductVersion();
        int dot = version.indexOf('.');
        try {
            return Integer.parseInt(dot < 0 ? version.trim() : version.substring(0, dot));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    @Override
    public int getDatabaseMinorVersion() throws SQLException {
        String version = getDatabaseProductVersion();
        int dot = version.indexOf('.');
        if (dot < 0) {
            return 0;
        }
        try {
            return Integer.parseInt(version.substring(dot + 1).replaceAll("\\D.*", ""));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    @Override
    public String getDriverName() {
        return "seclume";
    }

    @Override
    public String getDriverVersion() {
        return "0.1";
    }

    @Override
    public int getDriverMajorVersion() {
        return 0;
    }

    @Override
    public int getDriverMinorVersion() {
        return 1;
    }

    @Override
    public int getJDBCMajorVersion() {
        return 4;
    }

    @Override
    public int getJDBCMinorVersion() {
        return 3;
    }

    @Override
    public String getIdentifierQuoteString() {
        return "\"";
    }

    @Override
    public String getSearchStringEscape() {
        return "\\";
    }

    @Override
    public String getExtraNameCharacters() {
        return "";
    }

    @Override
    public String getSQLKeywords() {
        return "";
    }

    @Override
    public String getNumericFunctions() {
        return "";
    }

    @Override
    public String getStringFunctions() {
        return "";
    }

    @Override
    public String getSystemFunctions() {
        return "";
    }

    @Override
    public String getTimeDateFunctions() {
        return "";
    }

    @Override
    public String getCatalogTerm() {
        return "database";
    }

    @Override
    public String getSchemaTerm() {
        return "schema";
    }

    @Override
    public String getProcedureTerm() {
        return "function";
    }

    @Override
    public String getCatalogSeparator() {
        return ".";
    }

    @Override
    public boolean isCatalogAtStart() {
        return true;
    }

    @Override
    public int getSQLStateType() {
        return sqlStateSQL;
    }

    @Override
    public RowIdLifetime getRowIdLifetime() {
        return RowIdLifetime.ROWID_UNSUPPORTED;
    }

    // ---- what the driver can do - and what it cannot ---------------------

    @Override
    public boolean allProceduresAreCallable() {
        return false;
    }

    @Override
    public boolean allTablesAreSelectable() {
        return false;
    }

    @Override
    public boolean isReadOnly() throws SQLException {
        return connection.isReadOnly();
    }

    @Override
    public boolean nullsAreSortedHigh() {
        return true;
    }

    @Override
    public boolean nullsAreSortedLow() {
        return false;
    }

    @Override
    public boolean nullsAreSortedAtStart() {
        return false;
    }

    @Override
    public boolean nullsAreSortedAtEnd() {
        return false;
    }

    @Override
    public boolean usesLocalFiles() {
        return false;
    }

    @Override
    public boolean usesLocalFilePerTable() {
        return false;
    }

    @Override
    public boolean supportsMixedCaseIdentifiers() {
        return false;
    }

    @Override
    public boolean storesUpperCaseIdentifiers() {
        return false;
    }

    @Override
    public boolean storesLowerCaseIdentifiers() {
        return true;
    }

    @Override
    public boolean storesMixedCaseIdentifiers() {
        return false;
    }

    @Override
    public boolean supportsMixedCaseQuotedIdentifiers() {
        return true;
    }

    @Override
    public boolean storesUpperCaseQuotedIdentifiers() {
        return false;
    }

    @Override
    public boolean storesLowerCaseQuotedIdentifiers() {
        return false;
    }

    @Override
    public boolean storesMixedCaseQuotedIdentifiers() {
        return true;
    }

    @Override
    public boolean supportsAlterTableWithAddColumn() {
        return true;
    }

    @Override
    public boolean supportsAlterTableWithDropColumn() {
        return true;
    }

    @Override
    public boolean supportsColumnAliasing() {
        return true;
    }

    @Override
    public boolean nullPlusNonNullIsNull() {
        return true;
    }

    @Override
    public boolean supportsConvert() {
        return false;
    }

    @Override
    public boolean supportsConvert(int fromType, int toType) {
        return false;
    }

    @Override
    public boolean supportsTableCorrelationNames() {
        return true;
    }

    @Override
    public boolean supportsDifferentTableCorrelationNames() {
        return false;
    }

    @Override
    public boolean supportsExpressionsInOrderBy() {
        return true;
    }

    @Override
    public boolean supportsOrderByUnrelated() {
        return true;
    }

    @Override
    public boolean supportsGroupBy() {
        return true;
    }

    @Override
    public boolean supportsGroupByUnrelated() {
        return true;
    }

    @Override
    public boolean supportsGroupByBeyondSelect() {
        return true;
    }

    @Override
    public boolean supportsLikeEscapeClause() {
        return true;
    }

    @Override
    public boolean supportsMultipleResultSets() {
        return false;
    }

    @Override
    public boolean supportsMultipleTransactions() {
        return true;
    }

    @Override
    public boolean supportsNonNullableColumns() {
        return true;
    }

    @Override
    public boolean supportsMinimumSQLGrammar() {
        return true;
    }

    @Override
    public boolean supportsCoreSQLGrammar() {
        return true;
    }

    @Override
    public boolean supportsExtendedSQLGrammar() {
        return false;
    }

    @Override
    public boolean supportsANSI92EntryLevelSQL() {
        return true;
    }

    @Override
    public boolean supportsANSI92IntermediateSQL() {
        return false;
    }

    @Override
    public boolean supportsANSI92FullSQL() {
        return false;
    }

    @Override
    public boolean supportsIntegrityEnhancementFacility() {
        return true;
    }

    @Override
    public boolean supportsOuterJoins() {
        return true;
    }

    @Override
    public boolean supportsFullOuterJoins() {
        return true;
    }

    @Override
    public boolean supportsLimitedOuterJoins() {
        return true;
    }

    @Override
    public boolean supportsSchemasInDataManipulation() {
        return true;
    }

    @Override
    public boolean supportsSchemasInProcedureCalls() {
        return true;
    }

    @Override
    public boolean supportsSchemasInTableDefinitions() {
        return true;
    }

    @Override
    public boolean supportsSchemasInIndexDefinitions() {
        return true;
    }

    @Override
    public boolean supportsSchemasInPrivilegeDefinitions() {
        return true;
    }

    @Override
    public boolean supportsCatalogsInDataManipulation() {
        return false;
    }

    @Override
    public boolean supportsCatalogsInProcedureCalls() {
        return false;
    }

    @Override
    public boolean supportsCatalogsInTableDefinitions() {
        return false;
    }

    @Override
    public boolean supportsCatalogsInIndexDefinitions() {
        return false;
    }

    @Override
    public boolean supportsCatalogsInPrivilegeDefinitions() {
        return false;
    }

    @Override
    public boolean supportsPositionedDelete() {
        return false;
    }

    @Override
    public boolean supportsPositionedUpdate() {
        return false;
    }

    @Override
    public boolean supportsSelectForUpdate() {
        return true;
    }

    @Override
    public boolean supportsStoredProcedures() {
        return false;
    }

    @Override
    public boolean supportsSubqueriesInComparisons() {
        return true;
    }

    @Override
    public boolean supportsSubqueriesInExists() {
        return true;
    }

    @Override
    public boolean supportsSubqueriesInIns() {
        return true;
    }

    @Override
    public boolean supportsSubqueriesInQuantifieds() {
        return true;
    }

    @Override
    public boolean supportsCorrelatedSubqueries() {
        return true;
    }

    @Override
    public boolean supportsUnion() {
        return true;
    }

    @Override
    public boolean supportsUnionAll() {
        return true;
    }

    @Override
    public boolean supportsOpenCursorsAcrossCommit() {
        return false;
    }

    @Override
    public boolean supportsOpenCursorsAcrossRollback() {
        return false;
    }

    @Override
    public boolean supportsOpenStatementsAcrossCommit() {
        return true;
    }

    @Override
    public boolean supportsOpenStatementsAcrossRollback() {
        return true;
    }

    // Limits: 0 means "no known limit".

    @Override
    public int getMaxBinaryLiteralLength() {
        return 0;
    }

    @Override
    public int getMaxCharLiteralLength() {
        return 0;
    }

    @Override
    public int getMaxColumnNameLength() {
        return 63;
    }

    @Override
    public int getMaxColumnsInGroupBy() {
        return 0;
    }

    @Override
    public int getMaxColumnsInIndex() {
        return 32;
    }

    @Override
    public int getMaxColumnsInOrderBy() {
        return 0;
    }

    @Override
    public int getMaxColumnsInSelect() {
        return 0;
    }

    @Override
    public int getMaxColumnsInTable() {
        return 1600;
    }

    @Override
    public int getMaxConnections() {
        return 0;
    }

    @Override
    public int getMaxCursorNameLength() {
        return 63;
    }

    @Override
    public int getMaxIndexLength() {
        return 0;
    }

    @Override
    public int getMaxSchemaNameLength() {
        return 63;
    }

    @Override
    public int getMaxProcedureNameLength() {
        return 63;
    }

    @Override
    public int getMaxCatalogNameLength() {
        return 63;
    }

    @Override
    public int getMaxRowSize() {
        return 1_073_741_824;
    }

    @Override
    public boolean doesMaxRowSizeIncludeBlobs() {
        return false;
    }

    @Override
    public int getMaxStatementLength() {
        return 0;
    }

    @Override
    public int getMaxStatements() {
        return 0;
    }

    @Override
    public int getMaxTableNameLength() {
        return 63;
    }

    @Override
    public int getMaxTablesInSelect() {
        return 0;
    }

    @Override
    public int getMaxUserNameLength() {
        return 63;
    }

    @Override
    public int getDefaultTransactionIsolation() {
        return Connection.TRANSACTION_READ_COMMITTED;
    }

    @Override
    public boolean supportsTransactions() {
        return true;
    }

    @Override
    public boolean supportsTransactionIsolationLevel(int level) {
        return level == Connection.TRANSACTION_READ_COMMITTED
                || level == Connection.TRANSACTION_REPEATABLE_READ
                || level == Connection.TRANSACTION_SERIALIZABLE
                || level == Connection.TRANSACTION_READ_UNCOMMITTED;
    }

    @Override
    public boolean supportsDataDefinitionAndDataManipulationTransactions() {
        return true;
    }

    @Override
    public boolean supportsDataManipulationTransactionsOnly() {
        return false;
    }

    @Override
    public boolean dataDefinitionCausesTransactionCommit() {
        return false;
    }

    @Override
    public boolean dataDefinitionIgnoredInTransactions() {
        return false;
    }

    @Override
    public boolean supportsResultSetType(int type) {
        return type == ResultSet.TYPE_FORWARD_ONLY;
    }

    @Override
    public boolean supportsResultSetConcurrency(int type, int concurrency) {
        return type == ResultSet.TYPE_FORWARD_ONLY && concurrency == ResultSet.CONCUR_READ_ONLY;
    }

    @Override
    public boolean ownUpdatesAreVisible(int type) {
        return false;
    }

    @Override
    public boolean ownDeletesAreVisible(int type) {
        return false;
    }

    @Override
    public boolean ownInsertsAreVisible(int type) {
        return false;
    }

    @Override
    public boolean othersUpdatesAreVisible(int type) {
        return false;
    }

    @Override
    public boolean othersDeletesAreVisible(int type) {
        return false;
    }

    @Override
    public boolean othersInsertsAreVisible(int type) {
        return false;
    }

    @Override
    public boolean updatesAreDetected(int type) {
        return false;
    }

    @Override
    public boolean deletesAreDetected(int type) {
        return false;
    }

    @Override
    public boolean insertsAreDetected(int type) {
        return false;
    }

    @Override
    public boolean supportsBatchUpdates() {
        return true;
    }

    @Override
    public boolean supportsSavepoints() {
        return false;
    }

    @Override
    public boolean supportsNamedParameters() {
        return false;
    }

    @Override
    public boolean supportsMultipleOpenResults() {
        return false;
    }

    @Override
    public boolean supportsGetGeneratedKeys() {
        return false;
    }

    @Override
    public boolean supportsResultSetHoldability(int holdability) {
        return holdability == ResultSet.CLOSE_CURSORS_AT_COMMIT;
    }

    @Override
    public int getResultSetHoldability() {
        return ResultSet.CLOSE_CURSORS_AT_COMMIT;
    }

    @Override
    public boolean locatorsUpdateCopy() {
        return false;
    }

    @Override
    public boolean supportsStatementPooling() {
        return false;
    }

    @Override
    public boolean supportsStoredFunctionsUsingCallSyntax() {
        return false;
    }

    @Override
    public boolean autoCommitFailureClosesAllResultSets() {
        return false;
    }

    @Override
    public boolean generatedKeyAlwaysReturned() {
        return false;
    }

    @Override
    public boolean supportsRefCursors() {
        return false;
    }

    @Override
    public boolean supportsSharding() {
        return false;
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        throw new SQLException("not a wrapper for " + iface.getName());
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) {
        return iface.isInstance(this);
    }
}
