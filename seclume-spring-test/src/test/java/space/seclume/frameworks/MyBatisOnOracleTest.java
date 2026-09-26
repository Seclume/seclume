package space.seclume.frameworks;

import javax.sql.DataSource;

/** MyBatis against Oracle. */
class MyBatisOnOracleTest extends MyBatisCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("oracle");
    }
}
