/**
 * The connection pool - without third-party dependencies and without being
 * tied to any one
 * particular driver.
 *
 * <p>It knows only {@code javax.sql.DataSource}. It therefore pools the drivers
 * of this library just as it pools any other - and it holds no secret itself,
 * because it never gets to see one.
 */
module seclume.pool {

    requires transitive java.sql;
    requires java.logging;
    // Flight Recorder events of its own - a JDK module, so the pool keeps
    // its promise of knowing DataSource and nothing else. See PoolEvents.
    requires jdk.jfr;

    exports space.seclume.pool;
}
