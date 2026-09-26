package space.seclume.frameworks;

import org.junit.jupiter.api.Test;

/** Spring Data JDBC: an aggregate over two tables, optimistic locking, paging. See FrameworksTest. */
abstract class SpringDataJdbcCase extends FrameworksTest {

    @Test
    void springDataJdbcSavesAnAggregateAcrossTwoTables() {
        checkSpringDataJdbcSavesAnAggregateAcrossTwoTables();
    }
}
