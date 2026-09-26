package space.seclume.frameworks;

import javax.sql.DataSource;

/** MyBatis against SqlServer. */
class MyBatisOnSqlServerTest extends MyBatisCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("sqlServer");
    }
}
