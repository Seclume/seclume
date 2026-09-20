package space.seclume.mysql.jdbc;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.RowIdLifetime;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * What the driver has to say about the server and about itself.
 *
 * <p>The information about tables and columns comes from queries against
 * {@code information_schema} - the same source {@code SHOW COLUMNS} draws on,
 * only in a shape that can carry JDBC column names.
 *
 * <p>Everything that gives a fixed answer here gives it the way this driver
 * behaves: {@code supportsSavepoints()} is {@code true} because it has them,
 * and {@code supportsStoredProcedures()} is {@code false} because there is no
 * {@code CallableStatement} - even though MySQL could do both.
 */
final class MyDatabaseMetaData implements DatabaseMetaData {

    private final MyConnection connection;

    MyDatabaseMetaData(MyConnection connection) {
        this.connection = connection;
    }

    private ResultSet query(String sql) throws SQLException {
        Statement statement = connection.createStatement();
        return statement.executeQuery(sql);
    }

    /**
     * The type name from {@code information_schema} mapped to a
     * {@link java.sql.Types} value - as SQL, because it has to happen per row.
     *
     * <p>Hibernate reads this column when {@code ddl-auto=validate} compares
     * the schema, and a driver that answers 0 everywhere makes every column
     * look wrong. See the README.
     */
    private static final String SQL_TYPE_CASE = """
            case data_type
                 when 'bit' then -7
                 when 'tinyint' then -6
                 when 'smallint' then 5
                 when 'mediumint' then 4
                 when 'int' then 4
                 when 'integer' then 4
                 when 'bigint' then -5
                 when 'float' then 7
                 when 'double' then 8
                 when 'decimal' then 3
                 when 'year' then 5
                 when 'date' then 91
                 when 'time' then 92
                 when 'datetime' then 93
                 when 'timestamp' then 93
                 when 'char' then 1
                 when 'varchar' then 12
                 when 'enum' then 12
                 when 'set' then 12
                 when 'tinytext' then -1
                 when 'text' then -1
                 when 'mediumtext' then -1
                 when 'longtext' then -1
                 when 'json' then -1
                 when 'binary' then -2
                 when 'varbinary' then -3
                 when 'tinyblob' then -4
                 when 'blob' then -4
                 when 'mediumblob' then -4
                 when 'longblob' then -4
                 else 1111
            end""";

    /** A literal for a query - quotes and backslash escaped. */
    private static String literal(String value) {
        return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'";
    }

    /** A pattern such as {@code %} or {@code null} as a LIKE condition. */
    private static String like(String column, String pattern) {
        if (pattern == null || "%".equals(pattern)) {
            return "true";
        }
        return column + " like " + literal(pattern);
    }

    /**
     * In MySQL the catalog is the database; there is no schema below it.
     * JDBC callers pass sometimes the one, sometimes the other - both mean the
     * same thing here.
     */
    private static String database(String catalog, String schemaPattern) {
        return schema("table_schema", catalog, schemaPattern);
    }

    /** The same, for a view whose schema column is not called {@code table_schema}. */
    private static String schema(String column, String catalog, String schemaPattern) {
        String name = catalog != null && !catalog.isEmpty() ? catalog : schemaPattern;
        if (name == null || name.isEmpty() || "%".equals(name)) {
            return column + " = database()";
        }
        return column + " = " + literal(name);
    }

    // ---- catalogs --------------------------------------------------------

    @Override
    public ResultSet getTables(String catalog, String schemaPattern, String tableNamePattern,
                               String[] types) throws SQLException {
        StringBuilder kinds = new StringBuilder(); // seclume-allow: SQL text, never a secret
        if (types != null) {
            for (String type : types) {
                if (kinds.length() > 0) {
                    kinds.append(',');
                }
                // JDBC says TABLE, information_schema says BASE TABLE. Filtering
                // with the JDBC word found nothing at all - and that is the call
                // Hibernate makes for ddl-auto=validate, so the application
                // started with "missing table" for a table that was right there.
                String name = type.toUpperCase(java.util.Locale.ROOT);
                kinds.append(literal("TABLE".equals(name) ? "BASE TABLE" : name));
            }
        }
        String kindFilter = kinds.length() == 0 ? "true" : "table_type in (" + kinds + ")";
        return query("""
                select table_schema as `TABLE_CAT`, null as `TABLE_SCHEM`,
                       table_name as `TABLE_NAME`,
                       case table_type when 'BASE TABLE' then 'TABLE' else table_type end
                           as `TABLE_TYPE`,
                       table_comment as `REMARKS`, null as `TYPE_CAT`, null as `TYPE_SCHEM`,
                       null as `TYPE_NAME`, null as `SELF_REFERENCING_COL_NAME`,
                       null as `REF_GENERATION`
                from information_schema.tables
                where %s and %s and %s
                order by table_type, table_schema, table_name
                """.formatted(database(catalog, schemaPattern),
                        like("table_name", tableNamePattern), kindFilter));
    }

    @Override
    public ResultSet getColumns(String catalog, String schemaPattern, String tableNamePattern,
                                String columnNamePattern) throws SQLException {
        return query("""
                select table_schema as `TABLE_CAT`, null as `TABLE_SCHEM`,
                       table_name as `TABLE_NAME`, column_name as `COLUMN_NAME`,
                       %s as `DATA_TYPE`,
                       -- data_type, not column_type. column_type is the
                       -- declaration - "tinyint(1)", "varbinary(32)" - where
                       -- TYPE_NAME is meant to be the type, and Connector/J
                       -- answers "TINYINT" and "VARBINARY". A dialect that
                       -- matches on the name does not recognise the long
                       -- form. Found by the differential run, same mistake
                       -- as the PostgreSQL driver was making.
                       -- ...with UNSIGNED kept: in MySQL it is part of the
                       -- type and Connector/J answers "BIGINT UNSIGNED".
                       -- Built by concatenation rather than by stripping the
                       -- width out of column_type, so no regular expression
                       -- has to be right about enum('a(1)','b').
                       upper(concat(data_type,
                               if(locate('unsigned', column_type) > 0,
                                  ' unsigned', ''))) as `TYPE_NAME`,
                       -- The temporal case is here for the same reason the
                       -- PostgreSQL driver grew one: information_schema has
                       -- no length for a date, so the catalogue answered 0
                       -- while ResultSetMetaData answered 10. Hibernate and
                       -- Flyway read the catalogue. The widths are the
                       -- printed ones - 'YYYY-MM-DD' is ten characters, a
                       -- datetime nineteen, and a fractional part adds its
                       -- digits and the point.
                       coalesce(character_maximum_length, numeric_precision,
                                case data_type
                                     when 'date' then 10
                                     when 'year' then 4
                                     when 'time' then
                                          8 + if(datetime_precision > 0,
                                                 datetime_precision + 1, 0)
                                     when 'datetime' then
                                          19 + if(datetime_precision > 0,
                                                  datetime_precision + 1, 0)
                                     when 'timestamp' then
                                          19 + if(datetime_precision > 0,
                                                  datetime_precision + 1, 0)
                                end,
                                0) as `COLUMN_SIZE`,
                       null as `BUFFER_LENGTH`,
                       coalesce(numeric_scale, datetime_precision, 0) as `DECIMAL_DIGITS`,
                       10 as `NUM_PREC_RADIX`,
                       case when is_nullable = 'YES' then 1 else 0 end as `NULLABLE`,
                       column_comment as `REMARKS`, column_default as `COLUMN_DEF`,
                       null as `SQL_DATA_TYPE`, null as `SQL_DATETIME_SUB`,
                       character_octet_length as `CHAR_OCTET_LENGTH`,
                       ordinal_position as `ORDINAL_POSITION`,
                       is_nullable as `IS_NULLABLE`,
                       null as `SCOPE_CATALOG`, null as `SCOPE_SCHEMA`, null as `SCOPE_TABLE`,
                       null as `SOURCE_DATA_TYPE`,
                       case when extra like '%%auto_increment%%' then 'YES' else 'NO' end
                           as `IS_AUTOINCREMENT`,
                       case when extra like '%%GENERATED%%' then 'YES' else 'NO' end
                           as `IS_GENERATEDCOLUMN`
                from information_schema.columns
                where %s and %s and %s
                order by table_schema, table_name, ordinal_position
                """.formatted(SQL_TYPE_CASE, database(catalog, schemaPattern),
                        like("table_name", tableNamePattern),
                        like("column_name", columnNamePattern)));
    }

    @Override
    public ResultSet getPrimaryKeys(String catalog, String schema, String table)
            throws SQLException {
        return query("""
                select table_schema as `TABLE_CAT`, null as `TABLE_SCHEM`,
                       table_name as `TABLE_NAME`, column_name as `COLUMN_NAME`,
                       seq_in_index as `KEY_SEQ`, index_name as `PK_NAME`
                from information_schema.statistics
                where index_name = 'PRIMARY' and %s and %s
                order by column_name
                """.formatted(database(catalog, schema), like("table_name", table)));
    }

    @Override
    public ResultSet getImportedKeys(String catalog, String schema, String table)
            throws SQLException {
        return foreignKeys(database(catalog, schema), like("k.table_name", table));
    }

    @Override
    public ResultSet getExportedKeys(String catalog, String schema, String table)
            throws SQLException {
        return foreignKeys("k.referenced_table_schema = " + (schema == null || schema.isEmpty()
                ? "database()" : literal(schema)), like("k.referenced_table_name", table));
    }

    private ResultSet foreignKeys(String databaseFilter, String tableFilter) throws SQLException {
        String scoped = databaseFilter.replace("table_schema", "k.table_schema");
        return query("""
                select k.referenced_table_schema as `PKTABLE_CAT`, null as `PKTABLE_SCHEM`,
                       k.referenced_table_name as `PKTABLE_NAME`,
                       k.referenced_column_name as `PKCOLUMN_NAME`,
                       k.table_schema as `FKTABLE_CAT`, null as `FKTABLE_SCHEM`,
                       k.table_name as `FKTABLE_NAME`, k.column_name as `FKCOLUMN_NAME`,
                       k.ordinal_position as `KEY_SEQ`,
                       case r.update_rule when 'CASCADE' then 0 when 'SET NULL' then 2
                            when 'SET DEFAULT' then 4 when 'RESTRICT' then 1 else 3 end
                            as `UPDATE_RULE`,
                       case r.delete_rule when 'CASCADE' then 0 when 'SET NULL' then 2
                            when 'SET DEFAULT' then 4 when 'RESTRICT' then 1 else 3 end
                            as `DELETE_RULE`,
                       k.constraint_name as `FK_NAME`, 'PRIMARY' as `PK_NAME`,
                       7 as `DEFERRABILITY`
                from information_schema.key_column_usage k
                join information_schema.referential_constraints r
                     on r.constraint_schema = k.constraint_schema
                    and r.constraint_name = k.constraint_name
                where k.referenced_table_name is not null and %s and %s
                order by k.referenced_table_name, k.ordinal_position
                """.formatted(scoped, tableFilter));
    }

    @Override
    public ResultSet getIndexInfo(String catalog, String schema, String table, boolean unique,
                                  boolean approximate) throws SQLException {
        return query("""
                select table_schema as `TABLE_CAT`, null as `TABLE_SCHEM`,
                       table_name as `TABLE_NAME`, non_unique as `NON_UNIQUE`,
                       null as `INDEX_QUALIFIER`, index_name as `INDEX_NAME`,
                       3 as `TYPE`, seq_in_index as `ORDINAL_POSITION`,
                       column_name as `COLUMN_NAME`, collation as `ASC_OR_DESC`,
                       cardinality as `CARDINALITY`, 0 as `PAGES`,
                       null as `FILTER_CONDITION`
                from information_schema.statistics
                where %s and %s and (%s or non_unique = 0)
                order by non_unique, index_name, seq_in_index
                """.formatted(database(catalog, schema), like("table_name", table),
                        unique ? "false" : "true"));
    }

    @Override
    public ResultSet getCatalogs() throws SQLException {
        return query("select schema_name as `TABLE_CAT` from information_schema.schemata "
                + "order by schema_name");
    }

    /** MySQL has no schemas below the database - the result is empty. */
    @Override
    public ResultSet getSchemas() throws SQLException {
        return query("select null as `TABLE_SCHEM`, null as `TABLE_CATALOG` from dual where false");
    }

    @Override
    public ResultSet getSchemas(String catalog, String schemaPattern) throws SQLException {
        return getSchemas();
    }

    @Override
    public ResultSet getTableTypes() throws SQLException {
        // In JDBC's vocabulary, not the server's: whoever reads this list uses
        // the words in it as the filter for getTables, and "BASE TABLE" would
        // then be the one word that finds nothing there.
        return query("select 'SYSTEM VIEW' as `TABLE_TYPE` union all select 'TABLE' "
                + "union all select 'VIEW' order by 1");
    }

    /**
     * The types this driver can actually read and write.
     *
     * <p>A type the server has but the driver does not decode has no business
     * in this list - Flyway and Liquibase read it and believe it. That is also
     * why this is a written-out table and not a query against
     * {@code information_schema}: the server knows its own types, but not
     * which of them <b>this</b> driver handles.
     */
    @Override
    public ResultSet getTypeInfo() throws SQLException {
        return query("""
                select `TYPE_NAME`, `DATA_TYPE`, `PRECISION`, `LITERAL_PREFIX`,
                       `LITERAL_SUFFIX`, `CREATE_PARAMS`, 1 as `NULLABLE`,
                       `CASE_SENSITIVE`, 3 as `SEARCHABLE`, `UNSIGNED_ATTRIBUTE`,
                       `FIXED_PREC_SCALE`, `AUTO_INCREMENT`,
                       `TYPE_NAME` as `LOCAL_TYPE_NAME`,
                       `MINIMUM_SCALE`, `MAXIMUM_SCALE`, null as `SQL_DATA_TYPE`,
                       null as `SQL_DATETIME_SUB`, 10 as `NUM_PREC_RADIX`
                from (
                    select 'bit' as `TYPE_NAME`, -7 as `DATA_TYPE`, 1 as `PRECISION`,
                           null as `LITERAL_PREFIX`, null as `LITERAL_SUFFIX`,
                           null as `CREATE_PARAMS`, 0 as `CASE_SENSITIVE`,
                           1 as `UNSIGNED_ATTRIBUTE`, 0 as `FIXED_PREC_SCALE`,
                           0 as `AUTO_INCREMENT`, 0 as `MINIMUM_SCALE`,
                           0 as `MAXIMUM_SCALE`
                    union all select 'tinyint', -6, 3, null, null, null, 0, 0, 0, 1, 0, 0
                    union all select 'smallint', 5, 5, null, null, null, 0, 0, 0, 1, 0, 0
                    union all select 'year', 5, 4, null, null, null, 0, 1, 0, 0, 0, 0
                    union all select 'mediumint', 4, 8, null, null, null, 0, 0, 0, 1, 0, 0
                    union all select 'int', 4, 10, null, null, null, 0, 0, 0, 1, 0, 0
                    union all select 'bigint', -5, 19, null, null, null, 0, 0, 0, 1, 0, 0
                    union all select 'float', 7, 12, null, null, null, 0, 0, 0, 0, 0, 31
                    union all select 'double', 8, 22, null, null, null, 0, 0, 0, 0, 0, 31
                    union all select 'decimal', 3, 65, null, null, 'precision,scale',
                                     0, 0, 1, 0, 0, 30
                    union all select 'date', 91, 10, char(39), char(39), null,
                                     0, 1, 0, 0, 0, 0
                    union all select 'time', 92, 16, char(39), char(39), 'fsp',
                                     0, 1, 0, 0, 0, 6
                    union all select 'datetime', 93, 26, char(39), char(39), 'fsp',
                                     0, 1, 0, 0, 0, 6
                    union all select 'timestamp', 93, 26, char(39), char(39), 'fsp',
                                     0, 1, 0, 0, 0, 6
                    union all select 'char', 1, 255, char(39), char(39), 'length',
                                     1, 1, 0, 0, 0, 0
                    union all select 'varchar', 12, 65535, char(39), char(39), 'length',
                                     1, 1, 0, 0, 0, 0
                    union all select 'binary', -2, 255, '0x', '', 'length',
                                     1, 1, 0, 0, 0, 0
                    union all select 'varbinary', -3, 65535, '0x', '', 'length',
                                     1, 1, 0, 0, 0, 0
                    union all select 'tinytext', -1, 255, char(39), char(39), null,
                                     1, 1, 0, 0, 0, 0
                    union all select 'text', -1, 65535, char(39), char(39), null,
                                     1, 1, 0, 0, 0, 0
                    union all select 'mediumtext', -1, 16777215, char(39), char(39), null,
                                     1, 1, 0, 0, 0, 0
                    union all select 'longtext', -1, 2147483647, char(39), char(39), null,
                                     1, 1, 0, 0, 0, 0
                    union all select 'json', -1, 2147483647, char(39), char(39), null,
                                     1, 1, 0, 0, 0, 0
                    union all select 'tinyblob', -4, 255, '0x', '', null,
                                     1, 1, 0, 0, 0, 0
                    union all select 'blob', -4, 65535, '0x', '', null,
                                     1, 1, 0, 0, 0, 0
                    union all select 'mediumblob', -4, 16777215, '0x', '', null,
                                     1, 1, 0, 0, 0, 0
                    union all select 'longblob', -4, 2147483647, '0x', '', null,
                                     1, 1, 0, 0, 0, 0
                ) as `types`
                order by `DATA_TYPE`, `PRECISION`
                """);
    }

    // Information this driver does not give: empty rather than guessed.

    /**
     * The routines of a schema.
     *
     * <p>MySQL has no schema below a database, so the database is the
     * catalog and the schema column is null - the same shape
     * {@link #getTables} uses, for the same reason.
     */
    @Override
    public ResultSet getProcedures(String catalog, String schemaPattern, String namePattern)
            throws SQLException {
        return query("""
                select routine_schema as `PROCEDURE_CAT`, null as `PROCEDURE_SCHEM`,
                       routine_name as `PROCEDURE_NAME`, null as `RESERVED_1`,
                       null as `RESERVED_2`, null as `RESERVED_3`,
                       routine_comment as `REMARKS`,
                       case routine_type when 'PROCEDURE' then 1 else 2 end
                           as `PROCEDURE_TYPE`,
                       specific_name as `SPECIFIC_NAME`
                from information_schema.routines
                where %s and %s
                order by routine_schema, routine_name
                """.formatted(schema("routine_schema", catalog, schemaPattern),
                        like("routine_name", namePattern)));
    }

    /**
     * The parameters of a routine, which is what a call framework asks for.
     *
     * <p>{@code ordinal_position} is 0 for a function's return value and
     * that is how it is recognised here - MySQL gives it no name and no
     * mode. Everything else follows the mode column.
     *
     * <p>Nullability is reported as unknown rather than guessed: MySQL does
     * not say whether a parameter may be null, and answering
     * {@code procedureNullable} would be an invention.
     */
    @Override
    public ResultSet getProcedureColumns(String catalog, String schemaPattern,
            String namePattern, String columnPattern) throws SQLException {
        return query("""
                select specific_schema as `PROCEDURE_CAT`, null as `PROCEDURE_SCHEM`,
                       specific_name as `PROCEDURE_NAME`,
                       coalesce(parameter_name, '') as `COLUMN_NAME`,
                       case when ordinal_position = 0 then 5
                            when parameter_mode = 'IN' then 1
                            when parameter_mode = 'INOUT' then 2
                            when parameter_mode = 'OUT' then 4
                            else 0 end as `COLUMN_TYPE`,
                       %s as `DATA_TYPE`, dtd_identifier as `TYPE_NAME`,
                       coalesce(character_maximum_length, numeric_precision, 0)
                           as `PRECISION`,
                       coalesce(character_maximum_length, numeric_precision, 0) as `LENGTH`,
                       coalesce(numeric_scale, 0) as `SCALE`, 10 as `RADIX`,
                       2 as `NULLABLE`, null as `REMARKS`, null as `COLUMN_DEF`,
                       null as `SQL_DATA_TYPE`, null as `SQL_DATETIME_SUB`,
                       character_octet_length as `CHAR_OCTET_LENGTH`,
                       ordinal_position as `ORDINAL_POSITION`, '' as `IS_NULLABLE`,
                       specific_name as `SPECIFIC_NAME`
                from information_schema.parameters
                where %s and %s and %s
                order by specific_schema, specific_name, ordinal_position
                """.formatted(SQL_TYPE_CASE,
                        schema("specific_schema", catalog, schemaPattern),
                        like("specific_name", namePattern),
                        like("parameter_name", columnPattern)));
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
        return getImportedKeys(fc, fs, ft);
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
        return query("select null as `NAME` from dual where false");
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
             ResultSet result = statement.executeQuery("select current_user()")) {
            return result.next() ? result.getString(1) : null;
        }
    }

    @Override
    public String getDatabaseProductName() throws SQLException {
        return connection.session().isMariaDb() ? "MariaDB" : "MySQL";
    }

    @Override
    public String getDatabaseProductVersion() throws SQLException {
        return connection.session().serverVersion();
    }

    @Override
    public int getDatabaseMajorVersion() throws SQLException {
        return versionPart(0);
    }

    @Override
    public int getDatabaseMinorVersion() throws SQLException {
        return versionPart(1);
    }

    private int versionPart(int index) throws SQLException {
        String[] parts = getDatabaseProductVersion().split("[.\\-]");
        try {
            return index < parts.length ? Integer.parseInt(parts[index]) : 0;
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

    /** MySQL quotes with backticks, not with double quotes. */
    @Override
    public String getIdentifierQuoteString() {
        return "`";
    }

    @Override
    public String getSearchStringEscape() {
        return "\\";
    }

    @Override
    public String getExtraNameCharacters() {
        return "$";
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
        return "";
    }

    @Override
    public String getProcedureTerm() {
        return "procedure";
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
        return false;
    }

    @Override
    public boolean nullsAreSortedLow() {
        return true;
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

    /**
     * Depends on the server's operating system: under Windows table names
     * compare equal, under Linux they do not. Without the server value any
     * answer would be a guess - which is why it gets read.
     */
    @Override
    public boolean supportsMixedCaseIdentifiers() {
        return lowerCaseTableNames() == 0;
    }

    @Override
    public boolean storesLowerCaseIdentifiers() {
        return lowerCaseTableNames() == 1;
    }

    @Override
    public boolean storesUpperCaseIdentifiers() {
        return false;
    }

    /**
     * True whenever the server keeps a name as it was written - which on Linux
     * ({@code lower_case_table_names=0}) is also the case where
     * {@link #supportsMixedCaseIdentifiers()} is true.
     *
     * <p><b>Read strictly, that pair is a contradiction</b>: the specification
     * says {@code supports} means „stored mixed and compared case
     * sensitively" and {@code stores} means „stored mixed and compared case
     * <em>in</em>sensitively". Answering only the first, which is what the
     * letter demands, is what this method did — and it breaks Hibernate: with
     * all three {@code stores*} answers false, Hibernate falls back to the SQL
     * default and looks for {@code ZL_CUSTOMER}, which on Linux does not
     * exist. The result is „Schema validation: missing table" for a table that
     * is plainly there.
     *
     * <p>MySQL Connector/J answers the same pair the same way, and every
     * framework is calibrated against that. So this follows the ecosystem
     * rather than the letter, on purpose, and says why.
     */
    @Override
    public boolean storesMixedCaseIdentifiers() {
        return lowerCaseTableNames() != 1;
    }

    @Override
    public boolean supportsMixedCaseQuotedIdentifiers() {
        return supportsMixedCaseIdentifiers();
    }

    @Override
    public boolean storesUpperCaseQuotedIdentifiers() {
        return false;
    }

    @Override
    public boolean storesLowerCaseQuotedIdentifiers() {
        return storesLowerCaseIdentifiers();
    }

    @Override
    public boolean storesMixedCaseQuotedIdentifiers() {
        return storesMixedCaseIdentifiers();
    }

    private int lowerCaseTableNames() {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("select @@lower_case_table_names")) {
            return result.next() ? result.getInt(1) : 0;
        } catch (SQLException e) {
            return 0;
        }
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
        return true;
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

    /** Only with CLIENT_MULTI_STATEMENTS - and this driver does not set it. */
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

    /** MySQL has no FULL OUTER JOIN - nor does MariaDB. */
    @Override
    public boolean supportsFullOuterJoins() {
        return false;
    }

    @Override
    public boolean supportsLimitedOuterJoins() {
        return true;
    }

    @Override
    public boolean supportsSchemasInDataManipulation() {
        return false;
    }

    @Override
    public boolean supportsSchemasInProcedureCalls() {
        return false;
    }

    @Override
    public boolean supportsSchemasInTableDefinitions() {
        return false;
    }

    @Override
    public boolean supportsSchemasInIndexDefinitions() {
        return false;
    }

    @Override
    public boolean supportsSchemasInPrivilegeDefinitions() {
        return false;
    }

    @Override
    public boolean supportsCatalogsInDataManipulation() {
        return true;
    }

    @Override
    public boolean supportsCatalogsInProcedureCalls() {
        return true;
    }

    @Override
    public boolean supportsCatalogsInTableDefinitions() {
        return true;
    }

    @Override
    public boolean supportsCatalogsInIndexDefinitions() {
        return true;
    }

    @Override
    public boolean supportsCatalogsInPrivilegeDefinitions() {
        return true;
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
        return 64;
    }

    @Override
    public int getMaxColumnsInGroupBy() {
        return 0;
    }

    @Override
    public int getMaxColumnsInIndex() {
        return 16;
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
        return 4096;
    }

    @Override
    public int getMaxConnections() {
        return 0;
    }

    @Override
    public int getMaxCursorNameLength() {
        return 64;
    }

    @Override
    public int getMaxIndexLength() {
        return 3072;
    }

    @Override
    public int getMaxSchemaNameLength() {
        return 0;
    }

    @Override
    public int getMaxProcedureNameLength() {
        return 64;
    }

    @Override
    public int getMaxCatalogNameLength() {
        return 64;
    }

    @Override
    public int getMaxRowSize() {
        return 65535;
    }

    @Override
    public boolean doesMaxRowSizeIncludeBlobs() {
        return false;
    }

    /** The default of {@code max_allowed_packet}. */
    @Override
    public int getMaxStatementLength() {
        return 65535;
    }

    @Override
    public int getMaxStatements() {
        return 0;
    }

    @Override
    public int getMaxTableNameLength() {
        return 64;
    }

    @Override
    public int getMaxTablesInSelect() {
        return 61;
    }

    @Override
    public int getMaxUserNameLength() {
        return 32;
    }

    @Override
    public int getDefaultTransactionIsolation() {
        return Connection.TRANSACTION_REPEATABLE_READ;
    }

    @Override
    public boolean supportsTransactions() {
        return true;
    }

    @Override
    public boolean supportsTransactionIsolationLevel(int level) {
        return level == Connection.TRANSACTION_READ_UNCOMMITTED
                || level == Connection.TRANSACTION_READ_COMMITTED
                || level == Connection.TRANSACTION_REPEATABLE_READ
                || level == Connection.TRANSACTION_SERIALIZABLE;
    }

    @Override
    public boolean supportsDataDefinitionAndDataManipulationTransactions() {
        return false;
    }

    @Override
    public boolean supportsDataManipulationTransactionsOnly() {
        return true;
    }

    /** In MySQL every DDL ends the running transaction - implicitly. */
    @Override
    public boolean dataDefinitionCausesTransactionCommit() {
        return true;
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
        return true;
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
        return true;
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
        return true;
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
