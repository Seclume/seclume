package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.JdbcUrl;

/**
 * One check of what a host may be, for every driver and every list: names,
 * IPv4, IPv6 - and nothing that would end up in DNS, a TLS server name or a
 * log line as something else. Failover hosts are held to it like the first.
 */
class HostSyntaxTest {

    @ParameterizedTest
    @ValueSource(strings = {"db.example.com", "db-1", "10.0.0.1", "[::1]", "[fd00::1]", "fd00::1",
        "[fe80::1%eth0]", "_postgresql._tcp.example", "orders.cluster-abc.eu-central-1.rds.amazonaws.com"})
    void hostsAndAddressesAreTaken(String host) {
        assertEquals(host, new HostList.Host(host, 5432).host());
    }

    @ParameterizedTest
    @ValueSource(strings = {"db example", "db/evil", "user@db", "db?tls=off", "db#x", "db\nINFO x",
        "db\u001b[2J", "", "[db.example]", "dbé.example", "db;drop"})
    void anythingElseIsRefused(String host) {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> new HostList.Host(host, 5432), host);
        assertTrue(!refused.getMessage().contains("\n") && !refused.getMessage().contains("\u001b"),
                "the refusal carries the control character: " + refused.getMessage());
    }

    @Test
    void portsAreChecked() {
        assertThrows(IllegalArgumentException.class, () -> new HostList.Host("db", 0));
        assertThrows(IllegalArgumentException.class, () -> new HostList.Host("db", 65536));
    }

    /** A failover host is held to the same check as the first one, in every driver's URL. */
    @ParameterizedTest
    @ValueSource(strings = {"jdbc:seclume:postgresql:", "jdbc:seclume:mysql:",
        "jdbc:seclume:sqlserver:", "jdbc:seclume:oracle:"})
    void aFailoverHostIsCheckedToo(String prefix) {
        assertThrows(IllegalArgumentException.class, () -> JdbcUrl.parse(
                prefix + "//db1:5432,user@evil:5432/app", new Properties(), prefix, 5432));
        assertEquals(2, JdbcUrl.parse(prefix + "//db1:5432,db2.example:5433/app",
                new Properties(), prefix, 5432).hosts().size());
    }
}
