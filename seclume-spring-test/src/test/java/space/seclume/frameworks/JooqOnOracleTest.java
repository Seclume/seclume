package space.seclume.frameworks;

import javax.sql.DataSource;

/** Jooq against Oracle. */
class JooqOnOracleTest extends JooqCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("oracle");
    }
}
