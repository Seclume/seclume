package space.seclume.frameworks;

import org.junit.jupiter.api.Test;

/** Liquibase: update, rollback, update again, and the history it keeps. See FrameworksTest. */
abstract class LiquibaseCase extends FrameworksTest {

    @Test
    void repeatedDeploymentDoesNotRepeatChanges() throws Exception {
        checkLiquibaseRepeatedDeployment();
    }

    @Test
    void failedDataMigrationRollsBackAndReleasesLock() throws Exception {
        checkLiquibaseFailedMigration();
    }

    @Test
    void liquibaseUpdatesRollsBackAndUpdatesAgain() throws Exception {
        checkLiquibaseUpdatesRollsBackAndUpdatesAgain();
    }
}
