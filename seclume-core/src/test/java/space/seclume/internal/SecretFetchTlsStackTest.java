package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import space.seclume.internal.jdbc.TlsStack;

/**
 * Which TLS a secret manager is asked over.
 *
 * <p>The default is seclume's own TLS 1.3 client. Over the JDK's
 * {@code SSLEngine}, AES-GCM decrypts a direct buffer through short-lived heap
 * arrays, so a secret manager's answer - the password in clear text - passed
 * through the heap on its way into native memory (external audit,
 * 28.09.2026). JSSE stays available, by name, for a server that cannot do
 * TLS 1.3 with P-256.
 */
@org.junit.jupiter.api.parallel.Isolated
class SecretFetchTlsStackTest {

    @AfterEach
    void reset() {
        System.clearProperty(SecretFetch.TLS_STACK_PROPERTY);
    }

    @Test
    void theOwnStackIsTheDefault() throws IOException {
        System.clearProperty(SecretFetch.TLS_STACK_PROPERTY);
        assertEquals(TlsStack.SECLUME, SecretFetch.stack());
    }

    @Test
    void jsseCanStillBeChosenByName() throws IOException {
        System.setProperty(SecretFetch.TLS_STACK_PROPERTY, "jsse");
        assertEquals(TlsStack.JSSE, SecretFetch.stack());
    }

    @Test
    void anUnknownStackIsRefusedRatherThanGuessed() {
        System.setProperty(SecretFetch.TLS_STACK_PROPERTY, "openssl");
        IOException refused = assertThrows(IOException.class, SecretFetch::stack);
        assertEquals(true, refused.getMessage().contains(SecretFetch.TLS_STACK_PROPERTY),
                refused.getMessage());
    }
}
