package space.seclume.frameworks;

import javax.sql.DataSource;

class JpaFieldEncryptionOnPostgresTest extends JpaFieldEncryptionCase {

    @Override
    DataSource dataSource() throws Exception {
        return FrameworksServers.shared("postgres");
    }

    @Override
    String url() {
        return FrameworksServers.postgresUrl();
    }
}
