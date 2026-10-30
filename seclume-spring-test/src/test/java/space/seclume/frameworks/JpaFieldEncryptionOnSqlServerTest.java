package space.seclume.frameworks;

import javax.sql.DataSource;

class JpaFieldEncryptionOnSqlServerTest extends JpaFieldEncryptionCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("sqlServer");
    }

    @Override
    String url() {
        return FrameworksServers.sqlServerUrl();
    }
}
