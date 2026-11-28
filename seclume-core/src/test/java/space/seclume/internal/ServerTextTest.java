package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * A server's error text, often holding the application's input, went into
 * SQLException messages as it came: a CR LF forged a log line of its own, an
 * ESC drove the terminal that showed it. Control characters but the tab are
 * written as \xNN now, and the text is bounded.
 */
class ServerTextTest {

    @Test
    void controlCharactersCannotForgeALine() {
        String forged = "invalid input syntax: \"x\r\n2026-11-25 INFO login ok\u001b[2J\"";
        String printable = ServerText.printable(forged);
        assertFalse(printable.contains("\n") || printable.contains("\r")
                || printable.contains("\u001b"), printable);
        assertTrue(printable.contains("\\x0d\\x0a") && printable.contains("\\x1b"), printable);
    }

    @Test
    void ordinaryTextIsLeftAsItIs() {
        String plain = "relation \"orders\" does not exist\tat character 15 - äöü";
        assertSame(plain, ServerText.printable(plain));
        assertNull(ServerText.printable(null));
    }

    @Test
    void anEndlessMessageIsCut() {
        String endless = "x".repeat(100_000);
        String cut = ServerText.printable(endless);
        assertEquals(ServerText.MAX + "... (cut)".length(), cut.length());
    }
}
