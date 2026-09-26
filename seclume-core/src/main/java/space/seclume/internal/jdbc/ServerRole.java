package space.seclume.internal.jdbc;

/**
 * What a server says about its own part in a cluster.
 *
 * <p>Three values and not more, because three is what every one of the four
 * databases can answer without a privilege the application may not have. A
 * standby is a standby whether it is a PostgreSQL replica, a MySQL replica
 * with {@code read_only}, an Always On secondary or an Oracle physical
 * standby - and a driver choosing a host needs no finer distinction than
 * that.
 *
 * <p><b>{@link #UNKNOWN} is not a failure.</b> A server that cannot be asked -
 * an old version, a user without the right, a database that has no such notion
 * - answers this, and a host list that was told to look for a primary then has
 * to decide what to do with it. The decision is written down in
 * {@link TargetServer}: unknown is accepted, because refusing every server
 * that cannot describe itself would turn a working connection into an outage
 * over a question nobody asked.
 */
public enum ServerRole {

    /** Writes are accepted here. */
    PRIMARY,

    /** A copy: readable, and not writable. */
    STANDBY,

    /** The server did not say, and that is not the same as either. */
    UNKNOWN;

    /** How each database answers, as one statement that needs no privilege. */
    public static final String POSTGRESQL = "select pg_is_in_recovery()";

    /**
     * {@code read_only} rather than {@code super_read_only}: a replica sets
     * both, and a primary being briefly made read-only for maintenance is a
     * server an application should also stay away from. And
     * {@code innodb_read_only} as well: an Aurora MySQL reader says so there,
     * and not necessarily in {@code read_only}.
     */
    public static final String MYSQL = "select @@read_only or @@innodb_read_only";

    /**
     * The database's own updateability, which answers for an Always On
     * secondary and for a plainly read-only database alike. Not
     * {@code sys.dm_hadr_*}: those need a permission the application user
     * usually has not got, and a probe that fails for want of a right reports
     * a standby that is not there.
     */
    public static final String SQLSERVER =
            "select cast(databasepropertyex(db_name(), 'Updateability') as varchar(30))";

    /**
     * {@code sys_context} and <b>not</b> {@code v$database}. Measured on
     * 22.09.2026: the test user can read the first and not the second, which
     * is the ordinary shape of an application account - and a probe only the
     * DBA can run is a probe that answers {@link #UNKNOWN} in production.
     */
    public static final String ORACLE = "select sys_context('USERENV','DATABASE_ROLE') from dual";

    /**
     * Reads one of those answers.
     *
     * <p>Deliberately generous about the spelling and strict about the
     * meaning: anything that is recognisably "this is a copy" is a standby,
     * anything recognisably "writes land here" is a primary, and everything
     * else is unknown rather than guessed. A wrong guess here sends writes to
     * a server that will refuse them, or steers traffic away from the only
     * server that works.
     */
    public static ServerRole read(String answer) {
        if (answer == null) {
            return UNKNOWN;
        }
        String said = answer.trim().toUpperCase(java.util.Locale.ROOT);
        return switch (said) {
            case "T", "TRUE", "1", "Y", "YES", "READ_ONLY", "PHYSICAL STANDBY",
                 "LOGICAL STANDBY", "SNAPSHOT STANDBY", "FAR SYNC" -> STANDBY;
            case "F", "FALSE", "0", "N", "NO", "READ_WRITE", "PRIMARY" -> PRIMARY;
            default -> UNKNOWN;
        };
    }
}
