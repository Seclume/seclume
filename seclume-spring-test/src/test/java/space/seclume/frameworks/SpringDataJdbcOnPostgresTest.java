package space.seclume.frameworks;

import javax.sql.DataSource;

/** SpringDataJdbc against Postgres. */
class SpringDataJdbcOnPostgresTest extends SpringDataJdbcCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("postgres");
    }
}
