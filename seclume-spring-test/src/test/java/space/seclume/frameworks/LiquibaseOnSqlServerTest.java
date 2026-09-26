package space.seclume.frameworks;

import javax.sql.DataSource;

/** Liquibase against SqlServer. */
class LiquibaseOnSqlServerTest extends LiquibaseCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("sqlServer");
    }
}
