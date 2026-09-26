package space.seclume.frameworks;

import javax.sql.DataSource;

/** Jooq against MySql. */
class JooqOnMySqlTest extends JooqCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("mysql");
    }
}
