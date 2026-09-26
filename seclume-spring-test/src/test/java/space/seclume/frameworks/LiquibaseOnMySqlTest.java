package space.seclume.frameworks;

import javax.sql.DataSource;

/** Liquibase against MySql. */
class LiquibaseOnMySqlTest extends LiquibaseCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("mysql");
    }
}
