package space.seclume.frameworks;

import javax.sql.DataSource;

class JpaFieldEncryptionOnOracleTest extends JpaFieldEncryptionCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("oracle");
    }

    @Override
    String url() {
        return FrameworksServers.oracleUrl();
    }
}
