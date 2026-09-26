package space.seclume.frameworks;

import javax.sql.DataSource;

/** Jooq against Postgres. */
class JooqOnPostgresTest extends JooqCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("postgres");
    }
}
