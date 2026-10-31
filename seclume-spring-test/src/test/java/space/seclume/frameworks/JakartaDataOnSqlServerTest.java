package space.seclume.frameworks;

import javax.sql.DataSource;

class JakartaDataOnSqlServerTest extends JakartaDataCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("sqlServer");
    }
}
