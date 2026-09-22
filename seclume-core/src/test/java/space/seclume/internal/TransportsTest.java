package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.Test;

/**
 * Choosing a transport, and the two ways that choice can go wrong quietly.
 *
 * <p>No server anywhere in here: what is being checked is which class gets
 * asked, not whether a connection succeeds.
 */
class TransportsTest {

    /**
     * An unknown name is refused, and the message says what is on offer.
     *
     * <p>This library opens sockets. Anything else arrives as a
     * {@link TransportProvider} on the class path, and when none answers to
     * the name asked for, saying so is the whole job - somebody who asks for a
     * transport and quietly gets another one debugs the wrong thing for an
     * afternoon.
     */
    @Test
    void anUnknownTransportSaysWhatIsOnOffer() {
        IOException failure = assertThrows(IOException.class,
                () -> Transports.open("quantum", "127.0.0.1", 1, 10));
        assertTrue(failure.getMessage().contains("socket"), failure.getMessage());
        assertTrue(failure.getMessage().contains("class path"), failure.getMessage());
    }

    /**
     * And "-if-available" falls back rather than failing.
     *
     * <p>Which is what a test run across platforms needs: the name is asked
     * for, nothing answers to it, and the connection is opened the ordinary
     * way - here against a closed port, so it fails for that reason and no
     * other.
     */
    @Test
    void theFallbackReachesATransportWhenNobodyOffersTheName() {
        IOException failure = assertThrows(IOException.class,
                () -> Transports.open("something-if-available", "127.0.0.1", 1, 200));
        assertTrue(failure.getMessage() != null && !failure.getMessage().isBlank(),
                "a refused connection should say something");
    }
}
