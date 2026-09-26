package space.seclume.frameworks;

import org.junit.jupiter.api.Test;

/** jOOQ: inserts, a batch, a typed read, a transaction rolled back, a lazy cursor. See FrameworksTest. */
abstract class JooqCase extends FrameworksTest {

    @Test
    void jooqInsertsQueriesBatchesAndRollsBack() {
        checkJooqInsertsQueriesBatchesAndRollsBack();
    }
}
