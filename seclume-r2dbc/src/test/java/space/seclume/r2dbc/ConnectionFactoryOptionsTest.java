package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import io.r2dbc.spi.ConnectionFactoryOptions;

/**
 * Host, port and database go into the JDBC URL as they are, every other
 * option encoded. A database of {@code tenant_a?user=app&sts-endpoint=...}
 * was a query of its own: the login name, the STS endpoint and any option the
 * application had not set came from whoever chose the database.
 */
class ConnectionFactoryOptionsTest {

    private static ConnectionFactoryOptions.Builder options() {
        return ConnectionFactoryOptions.builder()
                .option(ConnectionFactoryOptions.DRIVER, "seclume")
                .option(ConnectionFactoryOptions.PROTOCOL, "postgresql")
                .option(ConnectionFactoryOptions.HOST, "db.example.com")
                .option(ConnectionFactoryOptions.PORT, 5432)
                .option(ConnectionFactoryOptions.USER, "app");
    }

    @Test
    void aDatabaseWithAQueryOfItsOwnIsRefused() {
        for (String database : new String[] {"tenant_a?user=postgres&x", "tenant_a&tls=off",
                "tenant_a#frag", "a/b", "a%3Fb", "a b"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> SeclumeConnectionFactoryProvider.jdbcUrl(options()
                            .option(ConnectionFactoryOptions.DATABASE, database).build()),
                    database);
        }
    }

    @Test
    void aHostWithAPathOrQueryIsRefused() {
        for (String host : new String[] {"db.example.com/x", "db.example.com?tls=off",
                "user@db.example.com", "db example"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> SeclumeConnectionFactoryProvider.jdbcUrl(options()
                            .option(ConnectionFactoryOptions.HOST, host).build()), host);
        }
    }

    @Test
    void aPortThatIsNotDigitsIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> SeclumeConnectionFactoryProvider.jdbcUrl(ConnectionFactoryOptions.builder()
                        .from(options().build())
                        .option(io.r2dbc.spi.Option.valueOf("port"), "5432&tls=off").build()));
    }

    @Test
    void ordinaryValuesMakeTheUrl() {
        assertEquals("jdbc:seclume:postgresql://db.example.com:5432/orders_eu-1?user=app",
                SeclumeConnectionFactoryProvider.jdbcUrl(options()
                        .option(ConnectionFactoryOptions.DATABASE, "orders_eu-1").build()));
        assertEquals("jdbc:seclume:postgresql://db1.example.com,db2.example.com:5432/x?user=app",
                SeclumeConnectionFactoryProvider.jdbcUrl(options()
                        .option(ConnectionFactoryOptions.HOST, "db1.example.com,db2.example.com")
                        .option(ConnectionFactoryOptions.DATABASE, "x").build()));
    }
}
