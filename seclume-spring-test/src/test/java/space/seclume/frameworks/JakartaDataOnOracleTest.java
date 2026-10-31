package space.seclume.frameworks;

import javax.sql.DataSource;

class JakartaDataOnOracleTest extends JakartaDataCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("oracle");
    }
}
