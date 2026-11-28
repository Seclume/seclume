package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;

/**
 * A URL that says nothing about TLS gets verify-full: the server's
 * certificate and name are checked. Every weaker mode is a word in the URL.
 */
class TlsModeDefaultTest {

    @Test
    void notGivenIsVerifyFull() throws SQLException {
        assertEquals(TlsMode.VERIFY_FULL, TlsMode.of(null));
        assertEquals(TlsMode.VERIFY_FULL, TlsMode.of(""));
    }

    @Test
    void everySpellingStillMeansWhatItSays() throws SQLException {
        assertEquals(TlsMode.OFF, TlsMode.of("off"));
        assertEquals(TlsMode.OFF, TlsMode.of("disable"));
        assertEquals(TlsMode.PREFER, TlsMode.of("prefer"));
        assertEquals(TlsMode.REQUIRE, TlsMode.of("require"));
        assertEquals(TlsMode.VERIFY_FULL, TlsMode.of("verify-full"));
        assertEquals(TlsMode.VERIFY_FULL, TlsMode.of("VERIFY_FULL"));
        assertThrows(SQLException.class, () -> TlsMode.of("maybe"));
    }
}
