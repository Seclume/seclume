package space.seclume.frameworks;

import javax.sql.DataSource;

/** Liquibase against Postgres. */
class LiquibaseOnPostgresTest extends LiquibaseCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("postgres");
    }
}
