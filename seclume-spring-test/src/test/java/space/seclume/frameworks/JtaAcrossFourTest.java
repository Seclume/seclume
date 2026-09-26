package space.seclume.frameworks;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import javax.sql.DataSource;
import javax.sql.XADataSource;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.jta.JtaTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.atomikos.icatch.config.UserTransactionService;
import com.atomikos.icatch.config.UserTransactionServiceImp;
import com.atomikos.icatch.jta.UserTransactionManager;
import com.atomikos.jdbc.AtomikosDataSourceBean;

/**
 * One global transaction over all four databases - Atomikos coordinating,
 * Spring's {@code JtaTransactionManager} in front, the seclume XA data sources
 * underneath.
 *
 * <p>The drivers' own XA tests drive {@code XAResource} by hand: start, end,
 * prepare, commit, in the order the test chooses. A transaction manager
 * chooses differently - it enlists each resource when it is first used,
 * decides whether one-phase is enough, runs recovery when it starts, and asks
 * {@code isSameRM} to decide how many branches there are. That is the part
 * this test adds: the four drivers in the hands of a real coordinator.
 *
 * <p>PostgreSQL is the {@code seclume.pgxa} server: two-phase commit needs
 * {@code max_prepared_transactions} above 0, which the shared test server
 * does not have.
 *
 * <p>Three outcomes, each on all four at once: a commit that reaches every
 * database, a rollback that reaches every database, and a failure in the last
 * one that takes back what the first three had already done.
 */
@Timeout(300)
class JtaAcrossFourTest {

    private static final List<String> NAMES = List.of("pg", "my", "mssql", "ora");

    private static UserTransactionService service;
    private static UserTransactionManager manager;
    private static final Map<String, AtomikosDataSourceBean> XA = new LinkedHashMap<>();
    private static final Map<String, DataSource> PLAIN = new LinkedHashMap<>();
    private static TransactionTemplate tx;

    @BeforeAll
    static void coordinator(@org.junit.jupiter.api.io.TempDir Path logs) throws Exception {
        PLAIN.put("pg", FrameworksServers.postgresXa());
        PLAIN.put("my", FrameworksServers.mysql());
        PLAIN.put("mssql", FrameworksServers.sqlServer());
        PLAIN.put("ora", FrameworksServers.oracle());

        for (Map.Entry<String, DataSource> entry : PLAIN.entrySet()) {
            try (Connection connection = entry.getValue().getConnection();
                 Statement statement = connection.createStatement()) {
                String product = connection.getMetaData().getDatabaseProductName()
                        .toLowerCase(Locale.ROOT);
                if (product.contains("oracle")) {
                    statement.execute("begin execute immediate 'drop table xa_ledger purge'; "
                            + "exception when others then null; end;");
                } else {
                    statement.execute("drop table if exists xa_ledger");
                }
                statement.execute("create table xa_ledger (id int primary key, note varchar(80))");
            }
        }

        Properties properties = new Properties();
        properties.setProperty("com.atomikos.icatch.log_base_dir", logs.toString());
        properties.setProperty("com.atomikos.icatch.output_dir", logs.toString());
        properties.setProperty("com.atomikos.icatch.tm_unique_name", "seclume-jta-test");
        properties.setProperty("com.atomikos.icatch.default_jta_timeout", "60000");
        service = new UserTransactionServiceImp(properties);
        service.init();
        manager = new UserTransactionManager();
        manager.setStartupTransactionService(false);
        manager.init();

        XA.put("pg", bean("pg", xa(new space.seclume.postgresql.jdbc.SeclumeXaDataSource(),
                FrameworksServers.postgresXaUrl())));
        XA.put("my", bean("my", xa(new space.seclume.mysql.jdbc.MyXaDataSource(),
                FrameworksServers.mysqlUrl())));
        XA.put("mssql", bean("mssql", xa(new space.seclume.sqlserver.jdbc.TdsXaDataSource(),
                FrameworksServers.sqlServerUrl())));
        XA.put("ora", bean("ora", xa(new space.seclume.oracle.jdbc.OraXaDataSource(),
                FrameworksServers.oracleUrl())));

        tx = new TransactionTemplate(new JtaTransactionManager(manager, manager));
    }

    @AfterAll
    static void shutDown() throws Exception {
        XA.values().forEach(AtomikosDataSourceBean::close);
        if (manager != null) {
            manager.close();
        }
        if (service != null) {
            service.shutdown(true);
        }
        for (DataSource source : PLAIN.values()) {
            if (source instanceof AutoCloseable closeable) {
                closeable.close();
            }
        }
    }

    @BeforeEach
    void empty() {
        PLAIN.values().forEach(source -> new JdbcTemplate(source).update("delete from xa_ledger"));
    }

    @Test
    void aCommitReachesAllFour() {
        tx.executeWithoutResult(status -> {
            for (String name : NAMES) {
                insert(name, 1, "committed");
            }
        });
        assertEquals(List.of(1, 1, 1, 1), counts());
    }

    @Test
    void aRollbackReachesAllFour() {
        assertThrows(IllegalStateException.class, () -> tx.executeWithoutResult(status -> {
            for (String name : NAMES) {
                insert(name, 1, "rolled back");
            }
            throw new IllegalStateException("roll all four back");
        }));
        assertEquals(List.of(0, 0, 0, 0), counts());
    }

    /** The last one fails; the three that had already written are rolled back too. */
    @Test
    void aFailureInTheLastTakesBackTheFirstThree() {
        new JdbcTemplate(PLAIN.get("ora")).update("insert into xa_ledger values (7, 'there')");
        assertThrows(DataIntegrityViolationException.class, () -> tx.executeWithoutResult(
                status -> {
                    for (String name : NAMES) {
                        insert(name, 7, "clashes on Oracle");
                    }
                }));
        assertEquals(List.of(0, 0, 0, 1), counts(), "only Oracle's own row may be there");
    }

    private static void insert(String name, int id, String note) {
        new JdbcTemplate(XA.get(name)).update("insert into xa_ledger (id, note) values (?, ?)",
                id, note);
    }

    private static List<Integer> counts() {
        List<Integer> counts = new ArrayList<>();
        for (String name : NAMES) {
            counts.add(new JdbcTemplate(PLAIN.get(name))
                    .queryForObject("select count(*) from xa_ledger", Integer.class));
        }
        return counts;
    }

    private static XADataSource xa(XADataSource source, String url) throws Exception {
        Object settings = source.getClass().getMethod("settings").invoke(source);
        settings.getClass().getMethod("setUrl", String.class).invoke(settings, url);
        return source;
    }

    private static AtomikosDataSourceBean bean(String name, XADataSource source) {
        AtomikosDataSourceBean bean = new AtomikosDataSourceBean();
        bean.setUniqueResourceName("seclume-" + name);
        bean.setXaDataSource(source);
        bean.setPoolSize(2);
        bean.setBorrowConnectionTimeout(30);
        return bean;
    }
}
