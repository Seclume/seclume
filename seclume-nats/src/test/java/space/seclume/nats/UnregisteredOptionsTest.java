package space.seclume.nats;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.nats.client.Options;

import org.junit.jupiter.api.Test;

/**
 * SeclumeNats.configure() names seclume's data port; only build() registers
 * the trust and the credentials it needs. Options built with the builder's
 * own build() went out with neither the pin nor the root CA, the login line
 * unfilled. Such a data port refuses now.
 */
class UnregisteredOptionsTest {

    private static final String URL = "tls://bus.example.com?user=orders&provider=file"
            + "&path=/run/secrets/nats";

    @Test
    void optionsBuiltWithoutSeclumeAreRefused() {
        Options unregistered = SeclumeNats.configure(new Options.Builder(), URL).build();
        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> new SeclumeNatsDataPort().afterConstruct(unregistered));
        assertTrue(refused.getMessage().contains("SeclumeNats.build"), refused.getMessage());
    }

    @Test
    void optionsBuiltBySeclumeAreTaken() {
        Options registered = SeclumeNats.build(new Options.Builder(), URL);
        new SeclumeNatsDataPort().afterConstruct(registered);
    }
}
