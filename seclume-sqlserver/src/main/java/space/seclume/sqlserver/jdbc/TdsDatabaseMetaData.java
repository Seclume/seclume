package space.seclume.sqlserver.jdbc;

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
 * {@code INFORMATION_SCHEMA} where that view is enough, and against the
 * {@code sys} catalog where it is not - foreign keys and indexes are only
 * fully described there.
 *
 * <p>Everything that gives a fixed answer here gives it the way this driver
 * behaves, not the way SQL Server could: {@code supportsSavepoints()} is
 * {@code true} because the driver has them, and
 * {@code supportsStoredProcedures()} is {@code false} because there is no
 * {@code CallableStatement} - even though the server has both.
 */
final class TdsDatabaseMetaData implements DatabaseMetaData {

    private final TdsConnection connection;
    /** The connection this was made through, as the application sees it - see {@link space.seclume.internal.jdbc.Fronted}. */
    private final Connection owner;

    TdsDatabaseMetaData(TdsConnection connection) {
        this.connection = connection;
        this.owner = connection.frontOrSelf();
    }

    private ResultSet query(String sql) throws SQLException {
        Statement statement = connection.createStatement();
        return statement.executeQuery(sql);
    }

    /**
     * The type name from the catalog view mapped to a {@link java.sql.Types}
     * value - as SQL, because it has to happen per row.
     *
     * <p>The numbers follow {@code TdsTypes.sqlType}, so that a column
     * describes itself the same way whether it is read from a result or from
     * the catalog. {@code varchar(max)} is the exception worth noting: the
     * view reports it as {@code varchar} with a length of -1, and JDBC calls
     * that a long type.
     */
    private static final String SQL_TYPE_CASE = """
            case c.data_type
                 when 'bit' then 16
                 when 'tinyint' then -6
                 when 'smallint' then 5
                 when 'int' then 4
                 when 'bigint' then -5
                 when 'real' then 7
                 when 'float' then 8
                 when 'decimal' then 3
                 when 'numeric' then 2
                 when 'money' then 3
                 when 'smallmoney' then 3
                 when 'date' then 91
                 when 'time' then 92
                 when 'datetime' then 93
                 when 'datetime2' then 93
                 when 'smalldatetime' then 93
                 when 'datetimeoffset' then 2014
                 when 'char' then 1
                 when 'nchar' then -15
                 when 'uniqueidentifier' then 1
                 when 'varchar' then
                      case when c.character_maximum_length = -1 then -1 else 12 end
                 when 'nvarchar' then
                      case when c.character_maximum_length = -1 then -16 else -9 end
                 when 'text' then -1
                 when 'ntext' then -16
                 when 'binary' then -2
                 when 'varbinary' then
                      case when c.character_maximum_length = -1 then -4 else -3 end
                 when 'image' then -4
                 when 'xml' then 2009
                 else 1111
            end""";

    /** A literal for a query - the single quote doubled, as SQL wants it. */
    private static String literal(String value) {
        return "'" + value.replace("'", "''") + "'";
    }

    /** A pattern such as {@code %} or {@code null} as a LIKE condition. */
    private static String like(String column, String pattern) {
        if (pattern == null || "%".equals(pattern)) {
            return "1 = 1";
        }
        // The escape character has to be named; SQL Server has none by
        // default, and getSearchStringEscape promises a backslash.
        return column + " like " + literal(pattern) + " escape '\\'";
    }

    /** An exact name, or no condition at all when none was given. */
    private static String equals(String column, String name) {
        if (name == null || name.isEmpty() || "%".equals(name)) {
            return "1 = 1";
        }
        return column + " = " + literal(name);
    }

    /**
     * A catalog other than the current one cannot be reached from a query -
     * {@code INFORMATION_SCHEMA} always shows the database the session is in.
     * Rather than quietly answer about the wrong one, a foreign catalog is
     * refused with a reason.
     */
    private void requireCurrentCatalog(String catalog) throws SQLException {
        if (catalog == null || catalog.isEmpty() || "%".equals(catalog)) {
            return;
        }
        String current = connection.getCatalog();
        if (!catalog.equalsIgnoreCase(current)) {
            throw new SQLException("this connection is in '" + current + "', so it cannot "
                    + "describe '" + catalog + "' - open a connection to that database or "
                    + "call setCatalog first");
        }
    }

    // ---- catalogs --------------------------------------------------------

    @Override
    public ResultSet getTables(String catalog, String schemaPattern, String tableNamePattern,
                               String[] types) throws SQLException {
        requireCurrentCatalog(catalog);
        StringBuilder kinds = new StringBuilder();
        if (types != null) {
            for (String type : types) {
                if (kinds.length() > 0) {
                    kinds.append(',');
                }
                // JDBC says TABLE, INFORMATION_SCHEMA says BASE TABLE.
                String name = type.toUpperCase(java.util.Locale.ROOT);
                kinds.append(literal("TABLE".equals(name) ? "BASE TABLE" : name));
            }
        }
        String kindFilter = kinds.length() == 0 ? "1 = 1" : "t.table_type in (" + kinds + ")";
        return query("""
                select t.table_catalog as [TABLE_CAT], t.table_schema as [TABLE_SCHEM],
                       t.table_name as [TABLE_NAME],
                       case t.table_type when 'BASE TABLE' then 'TABLE' else t.table_type end
                           as [TABLE_TYPE],
                       cast(null as varchar(1)) as [REMARKS],
                       cast(null as varchar(1)) as [TYPE_CAT],
                       cast(null as varchar(1)) as [TYPE_SCHEM],
                       cast(null as varchar(1)) as [TYPE_NAME],
                       cast(null as varchar(1)) as [SELF_REFERENCING_COL_NAME],
                       cast(null as varchar(1)) as [REF_GENERATION]
                from information_schema.tables t
                where %s and %s and %s
                order by t.table_type, t.table_schema, t.table_name
                """.formatted(like("t.table_schema", schemaPattern),
                        like("t.table_name", tableNamePattern), kindFilter));
    }

    /**
     * The column list.
     *
     * <p>{@code DATA_TYPE} has to be the {@link java.sql.Types} value, and the
     * catalog view does not know it - it names the type instead. So the
     * mapping happens in the query, as a {@code case} over the type name.
     *
     * <p>That is not cosmetic: Hibernate reads this column when
     * {@code ddl-auto=validate} compares the schema, and a driver that answers
     * {@code OTHER} everywhere makes every column look wrong. See
     * the README.
     */
    @Override
    public ResultSet getColumns(String catalog, String schemaPattern, String tableNamePattern,
                                String columnNamePattern) throws SQLException {
        requireCurrentCatalog(catalog);
        return query("""
                select c.table_catalog as [TABLE_CAT], c.table_schema as [TABLE_SCHEM],
                       c.table_name as [TABLE_NAME], c.column_name as [COLUMN_NAME],
                       %s as [DATA_TYPE], c.data_type as [TYPE_NAME],
                       -- information_schema has a length for the character
                       -- types and a precision for the numeric ones, and
                       -- nothing at all for a bit, a date or a
                       -- uniqueidentifier - so the catalogue answered 0 for
                       -- those while ResultSetMetaData answered 1, 10 and 36.
                       -- Third driver, same mistake; the widths are the
                       -- printed ones. Hibernate and Flyway read this.
                       coalesce(c.character_maximum_length, c.numeric_precision,
                                case c.data_type
                                     when 'bit' then 1
                                     when 'uniqueidentifier' then 36
                                     when 'date' then 10
                                     when 'smalldatetime' then 16
                                     when 'datetime' then 23
                                     when 'time' then
                                          8 + case when c.datetime_precision > 0
                                                   then c.datetime_precision + 1 else 0 end
                                     when 'datetime2' then
                                          19 + case when c.datetime_precision > 0
                                                    then c.datetime_precision + 1 else 0 end
                                     when 'datetimeoffset' then
                                          26 + case when c.datetime_precision > 0
                                                    then c.datetime_precision + 1 else 0 end
                                end,
                                0) as [COLUMN_SIZE],
                       cast(null as int) as [BUFFER_LENGTH],
                       coalesce(c.numeric_scale, c.datetime_precision, 0) as [DECIMAL_DIGITS],
                       -- real and float are binary floating point, so their
                       -- digits are counted in base two. Answering 10 for
                       -- them said they were decimal, which they are not.
                       case when c.data_type in ('real', 'float') then 2
                            when c.data_type in ('tinyint', 'smallint', 'int',
                                                 'bigint', 'decimal', 'numeric',
                                                 'money', 'smallmoney') then 10
                            -- A radix is a property of a number. For a date
                            -- or a blob there is none, and saying 10 claimed
                            -- there was.
                            else null end as [NUM_PREC_RADIX],
                       case when c.is_nullable = 'YES' then 1 else 0 end as [NULLABLE],
                       cast(null as varchar(1)) as [REMARKS],
                       c.column_default as [COLUMN_DEF],
                       cast(null as int) as [SQL_DATA_TYPE],
                       cast(null as int) as [SQL_DATETIME_SUB],
                       c.character_octet_length as [CHAR_OCTET_LENGTH],
                       c.ordinal_position as [ORDINAL_POSITION],
                       c.is_nullable as [IS_NULLABLE],
                       cast(null as varchar(1)) as [SCOPE_CATALOG],
                       cast(null as varchar(1)) as [SCOPE_SCHEMA],
                       cast(null as varchar(1)) as [SCOPE_TABLE],
                       cast(null as smallint) as [SOURCE_DATA_TYPE],
                       case when columnproperty(object_id(quotename(c.table_schema)
                                + '.' + quotename(c.table_name)), c.column_name,
                                'IsIdentity') = 1 then 'YES' else 'NO' end as [IS_AUTOINCREMENT],
                       case when columnproperty(object_id(quotename(c.table_schema)
                                + '.' + quotename(c.table_name)), c.column_name,
                                'IsComputed') = 1 then 'YES' else 'NO' end as [IS_GENERATEDCOLUMN]
                from information_schema.columns c
                where %s and %s and %s
                order by c.table_schema, c.table_name, c.ordinal_position
                """.formatted(SQL_TYPE_CASE, like("c.table_schema", schemaPattern),
                        like("c.table_name", tableNamePattern),
                        like("c.column_name", columnNamePattern)));
    }

    @Override
    public ResultSet getPrimaryKeys(String catalog, String schema, String table)
            throws SQLException {
        requireCurrentCatalog(catalog);
        return query("""
                select k.table_catalog as [TABLE_CAT], k.table_schema as [TABLE_SCHEM],
                       k.table_name as [TABLE_NAME], k.column_name as [COLUMN_NAME],
                       k.ordinal_position as [KEY_SEQ], k.constraint_name as [PK_NAME]
                from information_schema.key_column_usage k
                join information_schema.table_constraints c
                     on c.constraint_name = k.constraint_name
                    and c.constraint_schema = k.constraint_schema
                where c.constraint_type = 'PRIMARY KEY' and %s and %s
                order by k.column_name
                """.formatted(equals("k.table_schema", schema), equals("k.table_name", table)));
    }

    @Override
    public ResultSet getImportedKeys(String catalog, String schema, String table)
            throws SQLException {
        requireCurrentCatalog(catalog);
        return foreignKeys(equals("schema_name(ft.schema_id)", schema),
                equals("ft.name", table));
    }

    @Override
    public ResultSet getExportedKeys(String catalog, String schema, String table)
            throws SQLException {
        requireCurrentCatalog(catalog);
        return foreignKeys(equals("schema_name(pt.schema_id)", schema),
                equals("pt.name", table));
    }

    /**
     * Foreign keys come from the {@code sys} catalog, not from
     * {@code INFORMATION_SCHEMA}: the view there names the constraint but not
     * the column pairs, so it would take two more joins and still not say
     * which column matches which.
     *
     * <p>The rule codes have to be translated: SQL Server counts 0 = no
     * action, 1 = cascade, 2 = set null, 3 = set default; JDBC counts
     * differently, and a straight copy would report a cascade as a
     * restriction.
     */
    private ResultSet foreignKeys(String schemaFilter, String tableFilter) throws SQLException {
        return query("""
                select db_name() as [PKTABLE_CAT], schema_name(pt.schema_id) as [PKTABLE_SCHEM],
                       pt.name as [PKTABLE_NAME], pc.name as [PKCOLUMN_NAME],
                       db_name() as [FKTABLE_CAT], schema_name(ft.schema_id) as [FKTABLE_SCHEM],
                       ft.name as [FKTABLE_NAME], fc.name as [FKCOLUMN_NAME],
                       fkc.constraint_column_id as [KEY_SEQ],
                       case fk.update_referential_action
                            when 0 then 3 when 1 then 0 when 2 then 2 else 4 end
                           as [UPDATE_RULE],
                       case fk.delete_referential_action
                            when 0 then 3 when 1 then 0 when 2 then 2 else 4 end
                           as [DELETE_RULE],
                       fk.name as [FK_NAME], pk.name as [PK_NAME], 7 as [DEFERRABILITY]
                from sys.foreign_keys fk
                join sys.foreign_key_columns fkc on fkc.constraint_object_id = fk.object_id
                join sys.tables ft on ft.object_id = fk.parent_object_id
                join sys.tables pt on pt.object_id = fk.referenced_object_id
                join sys.columns fc on fc.object_id = fkc.parent_object_id
                                   and fc.column_id = fkc.parent_column_id
                join sys.columns pc on pc.object_id = fkc.referenced_object_id
                                   and pc.column_id = fkc.referenced_column_id
                left join sys.key_constraints pk on pk.parent_object_id = pt.object_id
                                                and pk.type = 'PK'
                where %s and %s
                order by ft.name, fkc.constraint_column_id
                """.formatted(schemaFilter, tableFilter));
    }

    @Override
    public ResultSet getIndexInfo(String catalog, String schema, String table, boolean unique,
                                  boolean approximate) throws SQLException {
        requireCurrentCatalog(catalog);
        return query("""
                select db_name() as [TABLE_CAT], schema_name(t.schema_id) as [TABLE_SCHEM],
                       t.name as [TABLE_NAME],
                       case when i.is_unique = 1 then 0 else 1 end as [NON_UNIQUE],
                       cast(null as varchar(1)) as [INDEX_QUALIFIER], i.name as [INDEX_NAME],
                       3 as [TYPE], ic.key_ordinal as [ORDINAL_POSITION],
                       c.name as [COLUMN_NAME],
                       case when ic.is_descending_key = 1 then 'D' else 'A' end
                           as [ASC_OR_DESC],
                       cast(null as int) as [CARDINALITY], cast(null as int) as [PAGES],
                       cast(null as varchar(1)) as [FILTER_CONDITION]
                from sys.indexes i
                join sys.tables t on t.object_id = i.object_id
                join sys.index_columns ic on ic.object_id = i.object_id
                                         and ic.index_id = i.index_id
                join sys.columns c on c.object_id = ic.object_id
                                  and c.column_id = ic.column_id
                where i.type <> 0 and %s and %s and %s
                order by [NON_UNIQUE], i.name, ic.key_ordinal
                """.formatted(equals("schema_name(t.schema_id)", schema),
                        equals("t.name", table), unique ? "i.is_unique = 1" : "1 = 1"));
    }

    @Override
    public ResultSet getCatalogs() throws SQLException {
        return query("select name as [TABLE_CAT] from sys.databases order by name");
    }

    @Override
    public ResultSet getSchemas() throws SQLException {
        return getSchemas(null, null);
    }

    @Override
    public ResultSet getSchemas(String catalog, String schemaPattern) throws SQLException {
        requireCurrentCatalog(catalog);
        return query("""
                select name as [TABLE_SCHEM], db_name() as [TABLE_CATALOG]
                from sys.schemas
                where %s
                order by name
                """.formatted(like("name", schemaPattern)));
    }

    @Override
    public ResultSet getTableTypes() throws SQLException {
        return query("""
                select 'TABLE' as [TABLE_TYPE]
                union all select 'VIEW'
                union all select 'SYSTEM TABLE'
                """);
    }

    /**
     * The types this driver can actually read and write. A type that the
     * server has but the driver does not decode has no business being in this
     * list - a caller relies on it.
     */
    @Override
    public ResultSet getTypeInfo() throws SQLException {
        return query("""
                select [TYPE_NAME], [DATA_TYPE], [PRECISION], [NULLABLE], [SEARCHABLE],
                       [UNSIGNED_ATTRIBUTE], [FIXED_PREC_SCALE], [AUTO_INCREMENT],
                       [MINIMUM_SCALE], [MAXIMUM_SCALE], [NUM_PREC_RADIX]
                from (values
                    ('bit', 16, 1, 1, 2, 1, 0, 0, 0, 0, 10),
                    ('tinyint', -6, 3, 1, 2, 1, 0, 1, 0, 0, 10),
                    ('smallint', 5, 5, 1, 2, 0, 0, 1, 0, 0, 10),
                    ('int', 4, 10, 1, 2, 0, 0, 1, 0, 0, 10),
                    ('bigint', -5, 19, 1, 2, 0, 0, 1, 0, 0, 10),
                    ('real', 7, 7, 1, 2, 0, 0, 0, 0, 0, 10),
                    ('float', 8, 15, 1, 2, 0, 0, 0, 0, 0, 10),
                    ('decimal', 3, 38, 1, 2, 0, 1, 0, 0, 38, 10),
                    ('numeric', 2, 38, 1, 2, 0, 1, 0, 0, 38, 10),
                    ('money', 3, 19, 1, 2, 0, 1, 0, 4, 4, 10),
                    ('char', 1, 8000, 1, 3, 1, 0, 0, 0, 0, 10),
                    ('varchar', 12, 8000, 1, 3, 1, 0, 0, 0, 0, 10),
                    ('nchar', 1, 4000, 1, 3, 1, 0, 0, 0, 0, 10),
                    ('nvarchar', 12, 4000, 1, 3, 1, 0, 0, 0, 0, 10),
                    ('binary', -2, 8000, 1, 0, 1, 0, 0, 0, 0, 10),
                    ('varbinary', -3, 8000, 1, 0, 1, 0, 0, 0, 0, 10),
                    ('uniqueidentifier', 1, 36, 1, 2, 1, 0, 0, 0, 0, 10),
                    ('date', 91, 10, 1, 2, 1, 0, 0, 0, 0, 10),
                    ('time', 92, 16, 1, 2, 1, 0, 0, 0, 7, 10),
                    ('datetime', 93, 23, 1, 2, 1, 0, 0, 3, 3, 10),
                    ('datetime2', 93, 27, 1, 2, 1, 0, 0, 0, 7, 10),
                    ('datetimeoffset', 2014, 34, 1, 2, 1, 0, 0, 0, 7, 10)
                ) as t([TYPE_NAME], [DATA_TYPE], [PRECISION], [NULLABLE], [SEARCHABLE],
                       [UNSIGNED_ATTRIBUTE], [FIXED_PREC_SCALE], [AUTO_INCREMENT],
                       [MINIMUM_SCALE], [MAXIMUM_SCALE], [NUM_PREC_RADIX])
                order by [DATA_TYPE]
                """);
    }

    // Everything the driver does not describe answers with an empty result -
    // not with an exception, because a tool that walks the metadata would
    // stumble over one where an empty list says the same thing.

    /** The procedures and functions of the current database. */
    @Override
    public ResultSet getProcedures(String catalog, String schemaPattern, String namePattern)
            throws SQLException {
        requireCurrentCatalog(catalog);
        return query("""
                select r.specific_catalog as [PROCEDURE_CAT],
                       r.specific_schema as [PROCEDURE_SCHEM],
                       r.specific_name as [PROCEDURE_NAME],
                       cast(null as varchar(1)) as [RESERVED_1],
                       cast(null as varchar(1)) as [RESERVED_2],
                       cast(null as varchar(1)) as [RESERVED_3],
                       cast(null as varchar(1)) as [REMARKS],
                       cast(case r.routine_type when 'PROCEDURE' then 1 else 2 end as smallint)
                           as [PROCEDURE_TYPE],
                       r.specific_name as [SPECIFIC_NAME]
                from information_schema.routines r
                where %s and %s
                order by r.specific_schema, r.specific_name
                """.formatted(like("r.specific_schema", schemaPattern),
                        like("r.specific_name", namePattern)));
    }

    /**
     * The parameters of a procedure, which is what a call framework asks for.
     *
     * <p>A scalar function's return value is the row with
     * {@code ordinal_position = 0}; SQL Server leaves its name empty, and
     * JDBC counts it as parameter 1 by itself. Everything else follows
     * {@code parameter_mode}.
     *
     * <p>The table is aliased {@code c} because the shared type mapping is
     * written against a column list of that name - the same mapping
     * {@link #getColumns} uses, so a parameter and a column of one type are
     * described identically.
     */
    @Override
    public ResultSet getProcedureColumns(String catalog, String schemaPattern,
            String namePattern, String columnPattern) throws SQLException {
        requireCurrentCatalog(catalog);
        return query("""
                select c.specific_catalog as [PROCEDURE_CAT],
                       c.specific_schema as [PROCEDURE_SCHEM],
                       c.specific_name as [PROCEDURE_NAME],
                       coalesce(c.parameter_name, '') as [COLUMN_NAME],
                       cast(case when c.ordinal_position = 0 then 5
                                 when c.parameter_mode = 'IN' then 1
                                 when c.parameter_mode = 'INOUT' then 2
                                 when c.parameter_mode = 'OUT' then 4
                                 else 0 end as smallint) as [COLUMN_TYPE],
                       %s as [DATA_TYPE], c.data_type as [TYPE_NAME],
                       coalesce(c.character_maximum_length, c.numeric_precision, 0)
                           as [PRECISION],
                       coalesce(c.character_maximum_length, c.numeric_precision, 0)
                           as [LENGTH],
                       cast(coalesce(c.numeric_scale, 0) as smallint) as [SCALE],
                       cast(10 as smallint) as [RADIX],
                       cast(2 as smallint) as [NULLABLE],
                       cast(null as varchar(1)) as [REMARKS],
                       cast(null as varchar(1)) as [COLUMN_DEF],
                       cast(null as int) as [SQL_DATA_TYPE],
                       cast(null as int) as [SQL_DATETIME_SUB],
                       c.character_octet_length as [CHAR_OCTET_LENGTH],
                       c.ordinal_position as [ORDINAL_POSITION],
                       '' as [IS_NULLABLE],
                       c.specific_name as [SPECIFIC_NAME]
                from information_schema.parameters c
                where %s and %s and %s
                order by c.specific_schema, c.specific_name, c.ordinal_position
                """.formatted(SQL_TYPE_CASE, like("c.specific_schema", schemaPattern),
                        like("c.specific_name", namePattern),
                        like("c.parameter_name", columnPattern)));
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
        return foreignKeys(equals("schema_name(pt.schema_id)", ps), equals("pt.name", pt));
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
        return query("select cast(null as varchar(1)) as [NAME] where 1 = 0");
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
             ResultSet result = statement.executeQuery("select suser_name()")) {
            return result.next() ? result.getString(1) : null;
        }
    }

    @Override
    public String getDatabaseProductName() {
        return "Microsoft SQL Server";
    }

    /** {@code serverproperty} answers more precisely than the LOGINACK does. */
    @Override
    public String getDatabaseProductVersion() throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select cast(serverproperty('ProductVersion') as varchar(64))")) {
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

    /**
     * SQL Server quotes with brackets and, with {@code quoted_identifier} on,
     * with double quotes as well. The standard one is the honest answer here.
     */
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
        return "$#@";
    }

    @Override
    public String getSQLKeywords() {
        // Only the ones SQL Server has beyond the SQL standard - that is what
        // JDBC asks for here, not the whole reserved list.
        return "BREAK,BROWSE,BULK,CHECKPOINT,CLUSTERED,COMPUTE,CONTAINSTABLE,DATABASE,"
                + "DBCC,DENY,DISK,DISTRIBUTED,DUMP,ERRLVL,EXIT,FILE,FILLFACTOR,FREETEXT,"
                + "FREETEXTTABLE,HOLDLOCK,IDENTITYCOL,IDENTITY_INSERT,KILL,LINENO,LOAD,"
                + "MERGE,NOCHECK,NONCLUSTERED,OFFSETS,OPENDATASOURCE,OPENQUERY,OPENROWSET,"
                + "OPENXML,PIVOT,PLAN,PRINT,PROC,RAISERROR,READTEXT,RECONFIGURE,"
                + "REPLICATION,RESTORE,ROWCOUNT,ROWGUIDCOL,RULE,SAVE,SEMANTICKEYPHRASETABLE,"
                + "SETUSER,SHUTDOWN,STATISTICS,TEXTSIZE,TOP,TRAN,TRUNCATE,TSEQUAL,UNPIVOT,"
                + "UPDATETEXT,USE,WAITFOR,WRITETEXT";
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
     * SQL Server keeps a name the way it was written, but compares it the way
     * the collation says - and the usual collations are case-insensitive.
     * {@code supportsMixedCaseIdentifiers} asks about the comparison, the
     * {@code stores...} methods about the storage; hence the different
     * answers.
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
        return false;
    }

    @Override
    public boolean storesMixedCaseIdentifiers() {
        return true;
    }

    @Override
    public boolean supportsMixedCaseQuotedIdentifiers() {
        return false;
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
     * {@code getMoreResults} always answers false. Recorded in
     * {@code PROVENANCE.md}.
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

    // SQL Server has schemas below the database, and they may be named
    // everywhere a table may be named.

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
        return 1024;
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
        return 900;
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
        return 8060;
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

    @Override
    public boolean supportsTransactionIsolationLevel(int level) {
        return level == Connection.TRANSACTION_READ_UNCOMMITTED
                || level == Connection.TRANSACTION_READ_COMMITTED
                || level == Connection.TRANSACTION_REPEATABLE_READ
                || level == Connection.TRANSACTION_SERIALIZABLE;
    }

    /** SQL Server can roll back a CREATE TABLE - few systems can. */
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
