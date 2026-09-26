package space.seclume.frameworks;

import javax.sql.DataSource;

/** SpringDataJdbc against MySql. */
class SpringDataJdbcOnMySqlTest extends SpringDataJdbcCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("mysql");
    }
}
