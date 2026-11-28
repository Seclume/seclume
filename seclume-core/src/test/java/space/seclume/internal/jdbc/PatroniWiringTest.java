package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ServerSocket;
import java.sql.SQLException;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import space.seclume.internal.JdbcUrl;

/**
 * patroni= read by every driver's URL - they all parse through JdbcUrl - and
 * an answer naming a host of its choosing: the connection tries the URL's
 * servers, never that one. What is dialled is recorded; nothing gets there.
 */
class PatroniWiringTest {

    private static final String STRANGER = "attacker.example";

    @ParameterizedTest(name = "{0}")
    @CsvSource({
        "jdbc:seclume:postgresql:, 5432",
        "jdbc:seclume:mysql:, 3306",
        "jdbc:seclume:sqlserver:, 1433",
        "jdbc:seclume:oracle:, 1521"})
    void aMemberOutsideTheUrlIsNeverDialled(String prefix, int port) throws Exception {
        String answer = PatroniTopologyTest.CLUSTER
                .replace("\"host\": \"10.0.0.2\"", "\"host\": \"" + STRANGER + "\"");
        try (ServerSocket patroni = PatroniTopologyTest.serve(answer, new AtomicInteger())) {
            String url = prefix + "//10.0.0.1:5432,10.0.0.4:5432/app?targetServerType=primary"
                    + "&patroni=http://127.0.0.1:" + patroni.getLocalPort();
            HostList hosts = JdbcUrl.parse(url, new Properties(), prefix, port).hosts();
            assertTrue(hosts.topology() != null, prefix + ": patroni= was not wired");
            List<String> dialled = new CopyOnWriteArrayList<>();
            assertThrows(SQLException.class, () -> hosts.open(host -> {
                dialled.add(host.host());
                throw new SQLException("not reachable in this test", "08001");
            }, new HostList.Roles<Object>() {
                @Override
                public ServerRole of(Object opened) {
                    return ServerRole.PRIMARY;
                }

                @Override
                public void giveBack(Object opened) {
                }
            }));
            assertFalse(dialled.contains(STRANGER), prefix + ": dialled " + dialled);
            assertTrue(!dialled.isEmpty() && List.of("10.0.0.1", "10.0.0.4").containsAll(dialled),
                    prefix + ": dialled " + dialled);
        }
    }
}
