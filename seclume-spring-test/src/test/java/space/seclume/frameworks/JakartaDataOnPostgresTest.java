package space.seclume.frameworks;

import javax.sql.DataSource;

class JakartaDataOnPostgresTest extends JakartaDataCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("postgres");
    }
}
