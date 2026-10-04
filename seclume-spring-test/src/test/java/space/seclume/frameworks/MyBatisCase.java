package space.seclume.frameworks;

import org.junit.jupiter.api.Test;

/** MyBatis: generated keys, dynamic SQL, the batch executor, a typed null. See FrameworksTest. */
abstract class MyBatisCase extends FrameworksTest {

    @Test
    void failedBatchRollsBackEarlierWrites() throws Exception {
        checkMyBatisFailedBatchRollback();
    }

    @Test
    void earlyCursorCloseAllowsAnotherQuery() throws Exception {
        checkMyBatisEarlyCursorClose();
    }

    @Test
    void myBatisGeneratedKeysDynamicSqlBatchAndNull() {
        checkMyBatisGeneratedKeysDynamicSqlBatchAndNull();
    }
}
