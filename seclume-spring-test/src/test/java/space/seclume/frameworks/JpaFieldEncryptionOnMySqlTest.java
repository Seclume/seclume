package space.seclume.frameworks;

import javax.sql.DataSource;

class JpaFieldEncryptionOnMySqlTest extends JpaFieldEncryptionCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("mysql");
    }

    @Override
    String url() {
        return FrameworksServers.mysqlUrl();
    }
}
