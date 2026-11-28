package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Two transports of one name: the first on the class path won without a
 * word, so class path order decided which of them saw every byte of every
 * connection. Two are an error now, and the message names both.
 */
class DuplicateTransportTest {

    private static TransportProvider named(String name) {
        return new TransportProvider() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public Transport connect(String host, int port, int connectTimeoutMillis) {
                throw new UnsupportedOperationException();
            }
        };
    }

    @Test
    void twoOfOneNameAreRefused() {
        IOException refused = assertThrows(IOException.class, () -> Transports.only("tcp-core",
                List.of(named("tcp-core"), named("other"), named("TCP-CORE"))));
        assertTrue(refused.getMessage().contains("two transports"), refused.getMessage());
    }

    @Test
    void oneIsTakenAndNoneIsNull() throws IOException {
        TransportProvider one = named("tcp-core");
        assertSame(one, Transports.only("tcp-core", List.of(named("other"), one)));
        assertNull(Transports.only("tcp-core", List.of(named("other"))));
    }
}
