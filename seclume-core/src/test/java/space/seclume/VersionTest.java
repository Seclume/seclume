package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** Outside a jar there is no manifest, and the version says so rather than guessing. */
class VersionTest {

    @Test
    void outsideAJarItSaysDevelopment() {
        assertEquals("development", Version.current());
    }
}
