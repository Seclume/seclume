package space.seclume.frameworks;

import javax.sql.DataSource;

/** Liquibase against Oracle. */
class LiquibaseOnOracleTest extends LiquibaseCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("oracle");
    }
}
