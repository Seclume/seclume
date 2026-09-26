package space.seclume.frameworks;

import javax.sql.DataSource;

/** SpringDataJdbc against Oracle. */
class SpringDataJdbcOnOracleTest extends SpringDataJdbcCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("oracle");
    }
}
