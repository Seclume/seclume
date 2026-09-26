package space.seclume.frameworks;

import javax.sql.DataSource;

/** MyBatis against MySql. */
class MyBatisOnMySqlTest extends MyBatisCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("mysql");
    }
}
