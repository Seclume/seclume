package space.seclume.frameworks;

import javax.sql.DataSource;

/** Jooq against SqlServer. */
class JooqOnSqlServerTest extends JooqCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("sqlServer");
    }
}
