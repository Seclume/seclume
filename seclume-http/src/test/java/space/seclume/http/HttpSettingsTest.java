package space.seclume.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HttpSettingsTest {

    private static final String SECRET = "&provider=file&path=/run/secrets/token";

    @Test
    void defaults() {
        HttpSettings s = HttpSettings.of("https://api.example.com/v1/?x=1" + SECRET);
        assertEquals("api.example.com", s.host);
        assertEquals(443, s.port);
        assertEquals("/v1", s.basePath);
        assertEquals(HttpSettings.Auth.BEARER, s.auth);
        assertEquals("Authorization", s.headerName);
        assertEquals("Bearer ", s.prefix);
        assertEquals("api.example.com", s.authority());
        assertEquals("api.example.com:8443",
                HttpSettings.of("https://api.example.com:8443?y=1" + SECRET).authority());
    }

    @Test
    void refusals() {
        assertMessage("https://", () -> HttpSettings.of("http://api.example.com?x=1" + SECRET));
        assertMessage("in front of the host",
                () -> HttpSettings.of("https://u:p@api.example.com?x=1" + SECRET));
        assertMessage("no secret named", () -> HttpSettings.of("https://api.example.com"));
        assertMessage("needs user=",
                () -> HttpSettings.of("https://api.example.com?auth=basic" + SECRET));
        assertMessage("needs header=",
                () -> HttpSettings.of("https://api.example.com?auth=header" + SECRET));
        assertMessage("needs header=", () -> HttpSettings.of(
                "https://api.example.com?auth=header&header=X%20Key" + SECRET));
        assertMessage("cannot hold ':'", () -> HttpSettings.of(
                "https://api.example.com?auth=basic&user=a:b" + SECRET));
        assertMessage("control", () -> HttpSettings.of(
                "https://api.example.com?auth=header&header=X-Key&prefix=a%0D%0Ab" + SECRET));
        assertMessage("bearer, basic or header",
                () -> HttpSettings.of("https://api.example.com?auth=digest" + SECRET));
        assertMessage("timeout",
                () -> HttpSettings.of("https://api.example.com?timeout=-1" + SECRET));
    }

    private static void assertMessage(String part, org.junit.jupiter.api.function.Executable e) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, e);
        assertTrue(thrown.getMessage().contains(part), thrown.getMessage());
    }
}
