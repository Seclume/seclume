package space.seclume.frameworks;

import javax.sql.DataSource;

/** MyBatis against Postgres. */
class MyBatisOnPostgresTest extends MyBatisCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("postgres");
    }
}
