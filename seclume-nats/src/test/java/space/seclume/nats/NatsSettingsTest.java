package space.seclume.nats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class NatsSettingsTest {

    private static final String FILE_PROVIDER = "provider=file&path=/run/secrets/nats";

    @Test
    void parsesAllModesAndDefaults() {
        NatsSettings pw = NatsSettings.of("tls://bus.example.com?user=orders&" + FILE_PROVIDER);
        assertEquals("bus.example.com", pw.host);
        assertEquals(4222, pw.port);
        assertTrue(pw.tls);
        assertEquals(NatsSettings.AuthMode.PASSWORD, pw.mode);
        assertEquals("orders", pw.user);

        NatsSettings token = NatsSettings.of("tls://bus.example.com:4443?auth=token&" + FILE_PROVIDER);
        assertEquals(4443, token.port);
        assertEquals(NatsSettings.AuthMode.TOKEN, token.mode);

        NatsSettings nkey = NatsSettings.of("nats://bus.example.com?auth=nkey&" + FILE_PROVIDER);
        assertFalse(nkey.tls);
        assertEquals(NatsSettings.AuthMode.NKEY, nkey.mode);

        NatsSettings creds = NatsSettings.of("tls://bus.example.com?auth=creds&" + FILE_PROVIDER);
        assertTrue(creds.tls);
        assertEquals(NatsSettings.AuthMode.CREDS, creds.mode);
    }

    @Test
    void refusals() {
        assertMessage("tls:// or nats://",
                () -> NatsSettings.of("http://bus.example.com?user=a&" + FILE_PROVIDER));
        assertMessage("in front of the host",
                () -> NatsSettings.of("tls://app:pw@bus.example.com?user=a&" + FILE_PROVIDER));
        assertMessage("requires tls://",
                () -> NatsSettings.of("nats://bus.example.com?user=a&" + FILE_PROVIDER));
        assertMessage("requires tls://",
                () -> NatsSettings.of("nats://bus.example.com?auth=token&" + FILE_PROVIDER));
        assertMessage("needs user=",
                () -> NatsSettings.of("tls://bus.example.com?auth=password&" + FILE_PROVIDER));
        assertMessage("only for password logins",
                () -> NatsSettings.of("tls://bus.example.com?auth=token&user=a&" + FILE_PROVIDER));
        assertMessage("no secret named",
                () -> NatsSettings.of("tls://bus.example.com?user=a"));
        assertMessage("connectTimeout",
                () -> NatsSettings.of("tls://bus.example.com?connectTimeout=abc&user=a&" + FILE_PROVIDER));
    }

    private static void assertMessage(String part, Executable action) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, action);
        assertTrue(ex.getMessage().contains(part), ex.getMessage());
    }
}
