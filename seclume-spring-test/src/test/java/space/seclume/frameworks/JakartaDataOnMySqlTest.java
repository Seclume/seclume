package space.seclume.frameworks;

import javax.sql.DataSource;

class JakartaDataOnMySqlTest extends JakartaDataCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("mysql");
    }
}
