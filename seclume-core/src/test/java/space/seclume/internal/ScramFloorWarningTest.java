package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * A lowered SCRAM floor is a weakened login and is said - once, with the
 * value, however many logins read it.
 */
@Isolated
class ScramFloorWarningTest {

    @Test
    void aLoweredFloorIsSaidOnceWithItsValue() throws Exception {
        java.lang.reflect.Field said = Scram.class.getDeclaredField("WEAKENED_SAID");
        said.setAccessible(true);
        java.util.concurrent.atomic.AtomicBoolean flag =
                (java.util.concurrent.atomic.AtomicBoolean) said.get(null);
        boolean before = flag.getAndSet(false);
        String property = System.getProperty(Scram.MIN_ITERATIONS_PROPERTY);
        Logger logger = Logger.getLogger(Scram.class.getName());
        List<LogRecord> records = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        logger.addHandler(handler);
        try {
            System.setProperty(Scram.MIN_ITERATIONS_PROPERTY, "1");
            for (int i = 0; i < 5; i++) {
                assertEquals(1, Scram.configuredMinimum());
            }
            List<LogRecord> warnings = records.stream()
                    .filter(r -> r.getLevel() == java.util.logging.Level.WARNING).toList();
            assertEquals(1, warnings.size(), "said " + warnings.size() + " times");
            assertTrue(warnings.get(0).getMessage().contains(Scram.MIN_ITERATIONS_PROPERTY + "=1"),
                    warnings.get(0).getMessage());
            System.setProperty(Scram.MIN_ITERATIONS_PROPERTY, "4096");
            assertEquals(4096, Scram.configuredMinimum());
            assertEquals(1, records.size(), "the default was warned about");
        } finally {
            logger.removeHandler(handler);
            if (property == null) {
                System.clearProperty(Scram.MIN_ITERATIONS_PROPERTY);
            } else {
                System.setProperty(Scram.MIN_ITERATIONS_PROPERTY, property);
            }
            flag.set(before);
        }
    }
}
