package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import org.junit.jupiter.api.Test;

/**
 * The server name a ClientHello carries, at the edges of each character
 * range it allows: {@code a} and {@code z}, {@code A} and {@code Z},
 * {@code 0} and {@code 9} are in a DNS label; the character just before or
 * after each range is not. PIT left a shifted range boundary alive here in
 * every run.
 */
class ClientHelloNameTest {

    private static int write(String name) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(1024);
            MemorySegment input = arena.allocate(32);
            return ClientHello.write(out, 0, input, input, input, name);
        }
    }

    @Test
    void theFirstAndLastOfEachRangeAreAllowed() {
        int without = write(null);
        String name = "az.AZ.a0.a9.example";
        assertEquals(without + 9 + name.length(), write(name), "the name went into the hello");
    }

    @Test
    void theCharacterJustOutsideEachRangeIsRefused() {
        for (char c : new char[] {'`', '{', '@', '[', '/', ':'}) {
            String name = "db" + c + "x.example";
            assertThrows(IllegalArgumentException.class, () -> write(name), name);
        }
    }
}
