package space.seclume.diff;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.function.Function;

import javax.sql.DataSource;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import space.seclume.mysql.jdbc.MyDataSource;
import space.seclume.oracle.jdbc.OraDataSource;
import space.seclume.postgresql.jdbc.SeclumeDataSource;
import space.seclume.sqlserver.jdbc.TdsDataSource;

/**
 * The URL option {@code transport} reaches the transport, through the driver
 * and through the data source, on all four.
 *
 * <p>It was documented and read by nobody until 25.09.2026: a connection that
 * asked for another transport quietly got a socket. Asked here for one that
 * does not exist, every one of them has to say so by name - which it can only
 * do if the option arrived. No server is needed for that.
 */
class TransportOptionTest {

    @TempDir
    static Path dir;

    record Kind(String name, String url, Function<String, DataSource> dataSource) {
        @Override
        public String toString() {
            return name;
        }
    }

    static List<Kind> kinds() {
        return List.of(
                new Kind("PostgreSQL", "jdbc:seclume:postgresql://127.0.0.1:1/db", url -> {
                    SeclumeDataSource ds = new SeclumeDataSource();
                    set(() -> ds.setUrl(url));
                    return ds;
                }),
                new Kind("MySQL", "jdbc:seclume:mysql://127.0.0.1:1/db", url -> {
                    MyDataSource ds = new MyDataSource();
                    set(() -> ds.setUrl(url));
                    return ds;
                }),
                new Kind("SQL Server", "jdbc:seclume:sqlserver://127.0.0.1:1/db", url -> {
                    TdsDataSource ds = new TdsDataSource();
                    set(() -> ds.setUrl(url));
                    return ds;
                }),
                new Kind("Oracle", "jdbc:seclume:oracle://127.0.0.1:1/db", url -> {
                    OraDataSource ds = new OraDataSource();
                    set(() -> ds.setUrl(url));
                    return ds;
                }));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("kinds")
    void theOptionReachesTheTransport(Kind kind) throws Exception {
        Path secret = Files.writeString(dir.resolve("secret-" + kind.name().replace(' ', '-')),
                "not-used");
        String url = kind.url() + "?user=u&provider=file&path="
                + secret.toString().replace('\\', '/') + "&connectTimeout=500&transport=quantum";

        SQLException viaDriver = assertThrows(SQLException.class,
                () -> DriverManager.getConnection(url).close());
        assertTrue(mentions(viaDriver, "'quantum'"), kind + " through the driver: "
                + chain(viaDriver));

        SQLException viaDataSource = assertThrows(SQLException.class,
                () -> kind.dataSource().apply(url).getConnection().close());
        assertTrue(mentions(viaDataSource, "'quantum'"), kind + " through the data source: "
                + chain(viaDataSource));
    }

    private static boolean mentions(Throwable failure, String text) {
        return chain(failure).contains(text);
    }

    private static String chain(Throwable failure) {
        StringBuilder all = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            all.append(t).append(" <- ");
        }
        return all.toString();
    }

    private interface Setter {
        void run() throws SQLException;
    }

    private static void set(Setter setter) {
        try {
            setter.run();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
