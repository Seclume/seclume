package space.seclume.quarkus.deployment;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import space.seclume.quarkus.SeclumeCracRegistration;

/**
 * In a Quarkus application - its pool is Agroal - nothing loaded SeclumeCrac,
 * and its process part was never registered. The extension's start-up bean
 * does it when seclume-crac is on the class path, and nothing without it.
 */
class CracRegistrationTest {

    @Test
    void withSeclumeCracTheProcessIsRegistered() {
        assertTrue(SeclumeCracRegistration.register(getClass().getClassLoader()));
        assertTrue(space.seclume.crac.SeclumeCrac.isProcessRegistered());
    }

    @Test
    void withoutItNothingHappens() {
        assertFalse(SeclumeCracRegistration.register(new ClassLoader(null) {
        }));
    }
}
