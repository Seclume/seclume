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

    exports space.seclume.pool;
}
