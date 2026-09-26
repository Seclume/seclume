package space.seclume.oracle.jdbc;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.RowIdLifetime;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * What the driver has to say about the server and about itself.
 *
 * <p>The information about tables and columns comes from the {@code ALL_}
 * views - not from {@code DBA_}: the first shows what this user may see, the
 * second needs rights most users do not have and would fail rather than return
 * less.
 *
 * <p>One Oracle peculiarity runs through all of it: <b>unquoted names are
 * stored in upper case</b>. A caller who asks for the table {@code employees}
 * means {@code EMPLOYEES}, and comparing as given would find nothing and look
 * like an empty database. Every pattern here is therefore upper-cased.
 *
 * <p>Everything that gives a fixed answer gives it the way this driver
 * behaves, not the way Oracle could: {@code supportsSavepoints()} is
 * {@code true} because the driver has them, and
 * {@code supportsStoredProcedures()} is {@code false} because there is no
 * {@code CallableStatement}.
 */
final class OraDatabaseMetaData implements DatabaseMetaData {

    private final OraConnection connection;
    /** The connection this was made through, as the application sees it - see {@link space.seclume.internal.jdbc.Fronted}. */
    private final Connection owner;

    OraDatabaseMetaData(OraConnection connection) {
        this.connection = connection;
        this.owner = connection.frontOrSelf();
    }

    /**
     * The type name from the catalog mapped to a {@link java.sql.Types} value -
     * as SQL, because it has to happen per row.
     *
     * <p>Oracle has one numeric type for everything, so the mapping depends on
     * the scale: no decimals and few digits is an integer, anything else is a
     * decimal. A {@code NUMBER} without a declared scale is reported as
     * {@code NUMERIC}, which is the honest answer rather than a guess.
     */
    private static final String SQL_TYPE_CASE = """
            case
                 when data_type = 'NUMBER' and data_scale = 0
                      and nvl(data_precision, 39) <= 9 then 4
                 when data_type = 'NUMBER' then 2
                 when data_type = 'FLOAT' then 8
                 when data_type = 'BINARY_FLOAT' then 7
                 when data_type = 'BINARY_DOUBLE' then 8
                 when data_type = 'CHAR' then 1
                 when data_type = 'NCHAR' then 1
                 when data_type = 'VARCHAR2' then 12
                 when data_type = 'NVARCHAR2' then 12
                 when data_type = 'CLOB' then 2005
                 when data_type = 'NCLOB' then 2011
                 when data_type = 'BLOB' then 2004
                 when data_type = 'RAW' then -3
                 when data_type = 'LONG RAW' then -4
                 when data_type = 'LONG' then -1
                 when data_type = 'DATE' then 93
                 when data_type like 'TIMESTAMP%' then 93
                 else 1111
            end""";

    private ResultSet query(String sql) throws SQLException {
        Statement statement = connection.createStatement();
        return statement.executeQuery(sql);
    }

    /** A literal for a query - the single quote doubled, as SQL wants it. */
    private static String literal(String value) {
        return "'" + value.replace("'", "''") + "'";
    }

    /**
     * A pattern as a LIKE condition.
     *
     * <p>Oracle stores unquoted names in upper case and quoted ones exactly as
     * written, and a pattern is matched against the name <b>as stored</b>.
     * That is the contract, and it is the only one that works.
     *
     * <p>This used to upper-case the pattern, with a comment claiming every
     * Oracle driver does that. It does not, and the cost of the mistake was
     * out of all proportion: Flyway creates its history table quoted and in
     * lower case, then asks whether it exists. Upper-cased, the question is
     * about a different table, the answer is no - and Flyway creates it again.
     * And again. In one run it did so <b>14 950 times</b> before the test was
     * killed, and from the outside it looked like a hung driver: a thread dump
     * shows a socket read, the server shows a session that has long since
     * answered. Nothing in either pointed at a metadata method.
     *
     * <p>So the pattern goes through as it came. A caller who means
     * {@code EMPLOYEES} has to write it that way, exactly as with the vendor
     * driver.
     */
    private static String like(String column, String pattern) {
        if (pattern == null || "%".equals(pattern)) {
            return "1 = 1";
        }
        return column + " like " + literal(pattern);
    }

    /** An exact name, likewise as stored. */
    private static String equals(String column, String name) {
        if (name == null || name.isEmpty() || "%".equals(name)) {
            return "1 = 1";
        }
        return column + " = " + literal(name);
    }

    // ---- catalogs --------------------------------------------------------

    /**
     * The tables the user may see.
     *
     * <p>Deliberately {@code all_tables} and not {@code dba_tables}: the first
     * shows what this user has rights to, the second needs rights most users
     * do not have and would fail rather than return less.
     */
    @Override
    public ResultSet getTables(String catalog, String schemaPattern, String tableNamePattern,
                               String[] types) throws SQLException {
        boolean wantsTables = types == null;
        boolean wantsViews = types == null;
        if (types != null) {
            for (String type : types) {
                wantsTables |= "TABLE".equalsIgnoreCase(type);
                wantsViews |= "VIEW".equalsIgnoreCase(type);
            }
        }
        StringBuilder sql = new StringBuilder(); // seclume-allow: SQL text, never a secret
        if (wantsTables) {
            sql.append("""
                    select null as "TABLE_CAT", owner as "TABLE_SCHEM",
                           table_name as "TABLE_NAME", 'TABLE' as "TABLE_TYPE",
                           null as "REMARKS", null as "TYPE_CAT", null as "TYPE_SCHEM",
                           null as "TYPE_NAME", null as "SELF_REFERENCING_COL_NAME",
                           null as "REF_GENERATION"
                    from all_tables where %s and %s
                    """.formatted(like("owner", schemaPattern),
                            like("table_name", tableNamePattern)));
        }
        if (wantsTables && wantsViews) {
            sql.append(" union all ");
        }
        if (wantsViews) {
            sql.append("""
                    select null, owner, view_name, 'VIEW', null, null, null, null, null, null
                    from all_views where %s and %s
                    """.formatted(like("owner", schemaPattern),
                            like("view_name", tableNamePattern)));
        }
        if (sql.isEmpty()) {
            return empty();
        }
        return query(sql + " order by 4, 2, 3");
    }

    /**
     * The column list.
     *
     * <p>Deliberately {@code all_tab_columns} and not {@code all_tab_cols}: the
     * latter knows about identity and virtual columns, but is not granted as
     * widely - and a metadata call that fails is worse than one that answers
     * "NO" to two questions.
     *
     * <p>{@code DATA_TYPE} has to be a {@link java.sql.Types} value, and the
     * catalog names the type instead - so the mapping happens in the query.
     * Hibernate reads this column when {@code ddl-auto=validate} compares the
     * schema; a driver that answers {@code OTHER} everywhere makes every
     * column look wrong.
     */
    @Override
    public ResultSet getColumns(String catalog, String schemaPattern, String tableNamePattern,
                                String columnNamePattern) throws SQLException {
        return query("""
                select null as "TABLE_CAT", owner as "TABLE_SCHEM",
                       table_name as "TABLE_NAME", column_name as "COLUMN_NAME",
                       %s as "DATA_TYPE", data_type as "TYPE_NAME",
                       nvl(data_precision, data_length) as "COLUMN_SIZE",
                       null as "BUFFER_LENGTH", data_scale as "DECIMAL_DIGITS",
                       10 as "NUM_PREC_RADIX",
                       case when nullable = 'Y' then 1 else 0 end as "NULLABLE",
                       null as "REMARKS", data_default as "COLUMN_DEF",
                       null as "SQL_DATA_TYPE", null as "SQL_DATETIME_SUB",
                       data_length as "CHAR_OCTET_LENGTH",
                       column_id as "ORDINAL_POSITION",
                       nullable as "IS_NULLABLE",
                       null as "SCOPE_CATALOG", null as "SCOPE_SCHEMA",
                       null as "SCOPE_TABLE", null as "SOURCE_DATA_TYPE",
                       'NO' as "IS_AUTOINCREMENT", 'NO' as "IS_GENERATEDCOLUMN"
                from all_tab_columns
                where %s and %s and %s
                order by owner, table_name, column_id
                """.formatted(SQL_TYPE_CASE, like("owner", schemaPattern),
                        like("table_name", tableNamePattern),
                        like("column_name", columnNamePattern)));
    }

    @Override
    public ResultSet getPrimaryKeys(String catalog, String schema, String table)
            throws SQLException {
        return query("""
                select null as "TABLE_CAT", c.owner as "TABLE_SCHEM",
                       c.table_name as "TABLE_NAME", k.column_name as "COLUMN_NAME",
                       k.position as "KEY_SEQ", c.constraint_name as "PK_NAME"
                from all_constraints c
                join all_cons_columns k on k.owner = c.owner
                                       and k.constraint_name = c.constraint_name
                where c.constraint_type = 'P' and %s and %s
                order by k.column_name
                """.formatted(equals("c.owner", schema), equals("c.table_name", table)));
    }

    @Override
    public ResultSet getImportedKeys(String catalog, String schema, String table)
            throws SQLException {
        return foreignKeys(equals("fk.owner", schema), equals("fk.table_name", table));
    }

    @Override
    public ResultSet getExportedKeys(String catalog, String schema, String table)
            throws SQLException {
        return foreignKeys(equals("pk.owner", schema), equals("pk.table_name", table));
    }

    /**
     * Foreign keys, both sides joined through {@code all_constraints}.
     *
     * <p>Oracle names the referenced constraint rather than the referenced
     * table, so the join goes over the constraint and then to its columns -
     * and the column pairs are matched by their position, which is the only
     * thing that ties them together.
     */
    private ResultSet foreignKeys(String schemaFilter, String tableFilter) throws SQLException {
        return query("""
                select null as "PKTABLE_CAT", pk.owner as "PKTABLE_SCHEM",
                       pk.table_name as "PKTABLE_NAME", pc.column_name as "PKCOLUMN_NAME",
                       null as "FKTABLE_CAT", fk.owner as "FKTABLE_SCHEM",
                       fk.table_name as "FKTABLE_NAME", fc.column_name as "FKCOLUMN_NAME",
                       fc.position as "KEY_SEQ",
                       3 as "UPDATE_RULE",
                       case fk.delete_rule when 'CASCADE' then 0
                                           when 'SET NULL' then 2 else 3 end as "DELETE_RULE",
                       fk.constraint_name as "FK_NAME", pk.constraint_name as "PK_NAME",
                       7 as "DEFERRABILITY"
                from all_constraints fk
                join all_constraints pk on pk.owner = fk.r_owner
                                       and pk.constraint_name = fk.r_constraint_name
                join all_cons_columns fc on fc.owner = fk.owner
                                        and fc.constraint_name = fk.constraint_name
                join all_cons_columns pc on pc.owner = pk.owner
                                        and pc.constraint_name = pk.constraint_name
                                        and pc.position = fc.position
                where fk.constraint_type = 'R' and %s and %s
                order by fk.table_name, fc.position
                """.formatted(schemaFilter, tableFilter));
    }

    @Override
    public ResultSet getIndexInfo(String catalog, String schema, String table, boolean unique,
                                  boolean approximate) throws SQLException {
        return query("""
                select null as "TABLE_CAT", i.table_owner as "TABLE_SCHEM",
                       i.table_name as "TABLE_NAME",
                       case when i.uniqueness = 'UNIQUE' then 0 else 1 end as "NON_UNIQUE",
                       null as "INDEX_QUALIFIER", i.index_name as "INDEX_NAME",
                       3 as "TYPE", c.column_position as "ORDINAL_POSITION",
                       c.column_name as "COLUMN_NAME",
                       case when c.descend = 'DESC' then 'D' else 'A' end as "ASC_OR_DESC",
                       i.distinct_keys as "CARDINALITY", i.leaf_blocks as "PAGES",
                       null as "FILTER_CONDITION"
                from all_indexes i
                join all_ind_columns c on c.index_owner = i.owner
                                      and c.index_name = i.index_name
                where %s and %s and %s
                order by 4, 6, 8
                """.formatted(equals("i.table_owner", schema), equals("i.table_name", table),
                        unique ? "i.uniqueness = 'UNIQUE'" : "1 = 1"));
    }

    /** Oracle has no catalogs; the schema is the unit of naming. */
    @Override
    public ResultSet getCatalogs() throws SQLException {
        return query("select null as \"TABLE_CAT\" from dual where 1 = 0");
    }

    @Override
    public ResultSet getSchemas() throws SQLException {
        return getSchemas(null, null);
    }

    @Override
    public ResultSet getSchemas(String catalog, String schemaPattern) throws SQLException {
        return query("""
                select username as "TABLE_SCHEM", null as "TABLE_CATALOG"
                from all_users where %s order by username
                """.formatted(like("username", schemaPattern)));
    }

    @Override
    public ResultSet getTableTypes() throws SQLException {
        return query("""
                select 'TABLE' as "TABLE_TYPE" from dual
                union all select 'VIEW' from dual
                """);
    }

    /**
     * The types this driver can actually read and write.
     *
     * <p>A short list, and honestly so: Oracle has one numeric type and a
     * handful of text types that this driver decodes. What it cannot decode
     * yet - LOBs, intervals, objects - has no business being in a list that
     * Flyway and Liquibase read and believe.
     */
    @Override
    public ResultSet getTypeInfo() throws SQLException {
        return query("""
                select 'NUMBER' as "TYPE_NAME", 2 as "DATA_TYPE", 38 as "PRECISION",
                       null as "LITERAL_PREFIX", null as "LITERAL_SUFFIX",
                       'precision,scale' as "CREATE_PARAMS", 1 as "NULLABLE",
                       0 as "CASE_SENSITIVE", 3 as "SEARCHABLE", 0 as "UNSIGNED_ATTRIBUTE",
                       1 as "FIXED_PREC_SCALE", 0 as "AUTO_INCREMENT",
                       'NUMBER' as "LOCAL_TYPE_NAME", 0 as "MINIMUM_SCALE",
                       38 as "MAXIMUM_SCALE", null as "SQL_DATA_TYPE",
                       null as "SQL_DATETIME_SUB", 10 as "NUM_PREC_RADIX"
                from dual
                union all select 'CHAR', 1, 2000, '''', '''', 'length', 1, 1, 3, 0, 0, 0,
                       'CHAR', 0, 0, null, null, 10 from dual
                union all select 'VARCHAR2', 12, 4000, '''', '''', 'length',
                       1, 1, 3, 0, 0, 0, 'VARCHAR2', 0, 0, null, null, 10 from dual
                union all select 'DATE', 93, 19, '''', '''', null, 1, 0, 3, 0, 0, 0,
                       'DATE', 0, 0, null, null, 10 from dual
                union all select 'RAW', -3, 2000, '''', '''', 'length', 1, 1, 3, 0, 0, 0,
                       'RAW', 0, 0, null, null, 10 from dual
                order by 2
                """);
    }

    // Everything this driver does not describe answers with an empty result -
    // not with an exception, because a tool that walks the metadata would
    // stumble over one where an empty list says the same thing.

    /**
     * The procedures and functions this user can see.
     *
     * <p>Oracle's package is what JDBC calls the catalog here - that is the
     * mapping its own driver uses, and a call framework that reads a package
     * name out of {@code PROCEDURE_CAT} and puts it back into
     * {@code pkg.proc} has to find it there.
     *
     * <p><b>{@code all_procedures} has no {@code package_name} column</b>,
     * unlike {@code all_arguments}: for a packaged procedure the package is
     * in {@code object_name} and the member in {@code procedure_name}, and
     * for a stand-alone one {@code procedure_name} is null and the procedure
     * itself is {@code object_name}. Asking for a column that is not there
     * fails the whole metadata lookup, and Spring then compiles the call as
     * {@code {call P()}} - no parameters, no error anyone would connect to
     * the catalog.
     */
    @Override
    public ResultSet getProcedures(String catalog, String schemaPattern, String namePattern)
            throws SQLException {
        return query("""
                select case when procedure_name is null then null else object_name end
                           as "PROCEDURE_CAT",
                       owner as "PROCEDURE_SCHEM",
                       nvl(procedure_name, object_name) as "PROCEDURE_NAME",
                       null as "RESERVED_1", null as "RESERVED_2", null as "RESERVED_3",
                       null as "REMARKS", 0 as "PROCEDURE_TYPE",
                       nvl(procedure_name, object_name) as "SPECIFIC_NAME"
                from all_procedures
                where %s and %s
                order by owner, nvl(procedure_name, object_name)
                """.formatted(like("owner", schemaPattern),
                        like("nvl(procedure_name, object_name)", namePattern)));
    }

    /**
     * The arguments of a procedure, which is what a call framework asks for.
     *
     * <p>Two details of {@code all_arguments} decide whether this is right:
     * {@code data_level = 0}, because a record argument is listed again one
     * row per field and those are not parameters of their own; and
     * {@code position = 0}, which is a function's return value - JDBC counts
     * it as parameter 1 by itself and marks it {@code procedureColumnReturn}.
     *
     * <p>Whether an argument may be null is not in the catalog, so it is
     * reported as unknown rather than invented.
     */
    @Override
    public ResultSet getProcedureColumns(String catalog, String schemaPattern,
            String namePattern, String columnPattern) throws SQLException {
        return query("""
                select package_name as "PROCEDURE_CAT", owner as "PROCEDURE_SCHEM",
                       object_name as "PROCEDURE_NAME",
                       nvl(argument_name, ' ') as "COLUMN_NAME",
                       case when position = 0 then 5
                            when in_out = 'IN' then 1
                            when in_out = 'IN/OUT' then 2
                            when in_out = 'OUT' then 4
                            else 0 end as "COLUMN_TYPE",
                       %s as "DATA_TYPE", data_type as "TYPE_NAME",
                       nvl(data_precision, nvl(data_length, 0)) as "PRECISION",
                       nvl(data_length, 0) as "LENGTH", nvl(data_scale, 0) as "SCALE",
                       10 as "RADIX", 2 as "NULLABLE", null as "REMARKS",
                       null as "COLUMN_DEF", null as "SQL_DATA_TYPE",
                       null as "SQL_DATETIME_SUB", data_length as "CHAR_OCTET_LENGTH",
                       position as "ORDINAL_POSITION", '' as "IS_NULLABLE",
                       object_name as "SPECIFIC_NAME"
                from all_arguments
                where data_level = 0 and %s and %s and %s
                order by owner, object_name, position
                """.formatted(SQL_TYPE_CASE, like("owner", schemaPattern),
                        like("object_name", namePattern),
                        like("nvl(argument_name, ' ')", columnPattern)));
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
        return foreignKeys(equals("pk.owner", ps), equals("pk.table_name", pt));
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
        return query("select null as \"NAME\" from dual where 1 = 0");
    }

    // ---- server and driver -----------------------------------------------

    @Override
    public Connection getConnection() {
        return owner;
    }

    @Override
    public String getURL() {
        return connection.url();
    }

    @Override
    public String getUserName() throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("select user from dual")) {
            return result.next() ? result.getString(1) : null;
        }
    }

    @Override
    public String getDatabaseProductName() {
        return "Oracle";
    }

    @Override
    public String getDatabaseProductVersion() throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select version from product_component_version "
                     + "where product like 'Oracle%'")) {
            return result.next() ? result.getString(1) : "";
        }
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
        return "$#";
    }

    @Override
    public String getSQLKeywords() {
        // Only what Oracle has beyond the SQL standard - that is what JDBC
        // asks for here, not the whole reserved list.
        return "ACCESS,AUDIT,CLUSTER,COMMENT,COMPRESS,EXCLUSIVE,FILE,IDENTIFIED,"
                + "INCREMENT,INITIAL,LOCK,LONG,MAXEXTENTS,MINUS,MLSLABEL,MODIFY,NOAUDIT,"
                + "NOCOMPRESS,NOWAIT,NUMBER,OFFLINE,ONLINE,PCTFREE,PRIOR,RAW,RENAME,"
                + "RESOURCE,ROW,ROWID,ROWNUM,SHARE,START,SUCCESSFUL,SYNONYM,SYSDATE,"
                + "UID,VALIDATE,VARCHAR2";
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

    /** Oracle has no catalogs at all - the schema is the unit of naming. */
    @Override
    public String getCatalogTerm() {
        return "";
    }

    @Override
    public String getSchemaTerm() {
        return "schema";
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
        // A ROWID names a row until the row moves, which a plain heap table
        // only lets it do when row movement was switched on - ojdbc answers
        // the same.
        return RowIdLifetime.ROWID_VALID_FOREVER;
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
     * Oracle folds an unquoted name to upper case and stores it that way. A
     * quoted one keeps its spelling and is then case-sensitive - which is why
     * the quoted answers differ from the unquoted ones.
     */
    @Override
    public boolean supportsMixedCaseIdentifiers() {
        return false;
    }

    @Override
    public boolean storesLowerCaseIdentifiers() {
        return false;
    }

    @Override
    public boolean storesUpperCaseIdentifiers() {
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

    /**
     * The protocol sends them, this driver does not hand them out yet -
     * {@code getMoreResults} always answers false. An open point, and named
     * as one in the README rather than faked.
     */
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

    // Oracle has no catalogs, so none of these can be true.

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
        return 128;
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
        return 1000;
    }

    @Override
    public int getMaxConnections() {
        return 0;
    }

    @Override
    public int getMaxCursorNameLength() {
        return 128;
    }

    @Override
    public int getMaxIndexLength() {
        return 0;
    }

    @Override
    public int getMaxSchemaNameLength() {
        return 128;
    }

    @Override
    public int getMaxProcedureNameLength() {
        return 128;
    }

    @Override
    public int getMaxCatalogNameLength() {
        return 128;
    }

    @Override
    public int getMaxRowSize() {
        return 0;
    }

    @Override
    public boolean doesMaxRowSizeIncludeBlobs() {
        return false;
    }

    /** A batch may be as long as it likes; the packets are split anyway. */
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
        return 128;
    }

    @Override
    public int getMaxTablesInSelect() {
        return 256;
    }

    @Override
    public int getMaxUserNameLength() {
        return 128;
    }

    @Override
    public int getDefaultTransactionIsolation() {
        return Connection.TRANSACTION_READ_COMMITTED;
    }

    @Override
    public boolean supportsTransactions() {
        return true;
    }

    /** Oracle offers exactly two, and pretending otherwise helps nobody. */
    @Override
    public boolean supportsTransactionIsolationLevel(int level) {
        return level == Connection.TRANSACTION_READ_COMMITTED
                || level == Connection.TRANSACTION_SERIALIZABLE;
    }

    /** In Oracle every DDL commits the running transaction, implicitly. */
    @Override
    public boolean supportsDataDefinitionAndDataManipulationTransactions() {
        return false;
    }

    @Override
    public boolean supportsDataManipulationTransactionsOnly() {
        return true;
    }

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

    /**
     * Through {@code prepareStatement(sql, columnNames)}, which is where
     * frameworks ask for keys: it needs "returning into" and therefore bind
     * variables, so a plain {@code Statement} refuses the request rather than
     * ignoring it - see OraStatement. It used to answer {@code false} here,
     * which made Spring's {@code SimpleJdbcInsert} refuse a table whose keys
     * the driver can deliver. Found by the Spring JDBC suite.
     */
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
