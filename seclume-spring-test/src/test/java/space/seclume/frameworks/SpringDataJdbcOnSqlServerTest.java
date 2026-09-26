package space.seclume.frameworks;

import javax.sql.DataSource;

/** SpringDataJdbc against SqlServer. */
class SpringDataJdbcOnSqlServerTest extends SpringDataJdbcCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("sqlServer");
    }
}
