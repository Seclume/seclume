package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * A transport found as an application's jar would offer it - a
 * META-INF/services entry - is used by its name, and the log says once which
 * class from which place carries the connections. Where
 * seclume.transport.allowed is set, a name it does not list opens nothing.
 */
@Isolated
class ServiceLoadedTransportTest {

    /** Offered under the name "loopback-test"; it opens nothing real. */
    public static final class Offered implements TransportProvider {
        static volatile int opened;

        @Override
        public String name() {
            return "loopback-test";
        }

        @Override
        public Transport connect(String host, int port, int connectTimeoutMillis) {
            opened++;
            return new Transport() {
                @Override
                public int read(ByteBuffer into) {
                    return -1;
                }

                @Override
                public int write(ByteBuffer from) {
                    int n = from.remaining();
                    from.position(from.limit());
                    return n;
                }

                @Override
                public boolean isOpen() {
                    return true;
                }

                @Override
                public void close() {
                }
            };
        }
    }

    private static <T> T withServices(Path directory, IoCall<T> call) throws Exception {
        Path services = directory.resolve("META-INF/services/" + TransportProvider.class.getName());
        Files.createDirectories(services.getParent());
        Files.writeString(services, Offered.class.getName() + "\n");
        Thread thread = Thread.currentThread();
        ClassLoader before = thread.getContextClassLoader();
        try (URLClassLoader loader = new URLClassLoader(new URL[] {directory.toUri().toURL()},
                ServiceLoadedTransportTest.class.getClassLoader())) {
            thread.setContextClassLoader(loader);
            return call.call();
        } finally {
            thread.setContextClassLoader(before);
        }
    }

    @FunctionalInterface
    private interface IoCall<T> {
        T call() throws Exception;
    }

    @Test
    void aServiceEntryIsUsedByNameAndNamedInTheLogOnce(@TempDir Path directory) throws Exception {
        List<String> said = new ArrayList<>();
        Logger log = Logger.getLogger(Transports.class.getName());
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                said.add(record.getMessage());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        log.addHandler(handler);
        try {
            int before = Offered.opened;
            withServices(directory, () -> {
                Transports.open("loopback-test", "db.example", 5432, 0).close();
                Transports.open("LOOPBACK-TEST", "db.example", 5432, 0).close();
                return null;
            });
            assertEquals(before + 2, Offered.opened, "the service entry was not used");
            List<String> naming = said.stream().filter(m -> m.contains("loopback-test")).toList();
            assertEquals(1, naming.size(), "said once, not per connection: " + said);
            assertTrue(naming.get(0).contains(Offered.class.getName()), naming.get(0));
            assertTrue(naming.get(0).contains(" from "), "the place it came from: " + naming.get(0));
        } finally {
            log.removeHandler(handler);
        }
    }

    @Test
    void aNameTheAllowListDoesNotHoldOpensNothing(@TempDir Path directory) throws Exception {
        String previous = System.getProperty(Transports.ALLOWED);
        System.setProperty(Transports.ALLOWED, "fd-transport, other");
        try {
            int before = Offered.opened;
            IOException refused = assertThrows(IOException.class, () -> withServices(directory,
                    () -> Transports.open("loopback-test", "db.example", 5432, 0)));
            assertTrue(refused.getMessage().contains(Transports.ALLOWED), refused.getMessage());
            assertEquals(before, Offered.opened, "a transport the list leaves out was opened");
            System.setProperty(Transports.ALLOWED, "other, Loopback-Test");
            withServices(directory, () -> {
                Transports.open("loopback-test", "db.example", 5432, 0).close();
                return null;
            });
            assertEquals(before + 1, Offered.opened, "a listed transport was refused");
            Transports.allowed(Transports.DEFAULT);
        } finally {
            if (previous == null) {
                System.clearProperty(Transports.ALLOWED);
            } else {
                System.setProperty(Transports.ALLOWED, previous);
            }
        }
    }
}
