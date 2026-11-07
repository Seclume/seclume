package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.crypto.HashAlgorithm;

/**
 * The fewest PBKDF2 iterations a SCRAM server may ask for. The count is the
 * server's to choose, and the client's proof is a PBKDF2 of the password with
 * it: a server - or whoever sits between - that asks for one iteration gets a
 * proof that costs one hash per guess to test offline. 4096 by default, as RFC
 * 7677 asks; {@code seclume.scram.minIterations} for a server that is set
 * lower on purpose. {@link Isolated}: it sets a system property every SCRAM
 * login of the process reads.
 */
@Isolated
class ScramMinimumIterationsTest {

    private static final String SALT = "YSBzYWx0IG9mIHNpeHRlZW4=";

    @AfterEach
    void clearTheProperty() {
        System.clearProperty(Scram.MIN_ITERATIONS_PROPERTY);
    }

    private static MemorySegment ascii(Arena arena, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    /** The server's first message, asking for {@code count} iterations. */
    private static void serverAsks(Scram scram, Arena arena, int count) {
        MemorySegment out = arena.allocate(256);
        int length = scram.clientFirst(out, "app");
        String first = new String(out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE),
                StandardCharsets.US_ASCII);
        String nonce = first.substring(first.indexOf(",r=") + 3);
        String serverFirst = "r=" + nonce + "srv,s=" + SALT + ",i=" + count;
        scram.serverFirst(ascii(arena, serverFirst), 0, serverFirst.length());
    }

    private static void accepted(Supplier<Scram> client, int count) {
        try (Arena arena = Arena.ofConfined(); Scram scram = client.get()) {
            serverAsks(scram, arena, count);
            assertEquals(count, scram.iterations());
        }
    }

    private static IllegalStateException refused(Supplier<Scram> client, int count) {
        try (Arena arena = Arena.ofConfined(); Scram scram = client.get()) {
            return assertThrows(IllegalStateException.class, () -> serverAsks(scram, arena, count));
        }
    }

    private static Scram sha256() {
        return new Scram(HashAlgorithm.SHA_256);
    }

    @Test
    void byDefaultRfc7677s4096AndNoFewer() {
        assertEquals(4096, Scram.DEFAULT_MIN_ITERATIONS);
        assertEquals(4096, sha256().minimumIterations());
        accepted(ScramMinimumIterationsTest::sha256, 4096);
        accepted(ScramMinimumIterationsTest::sha256, 15000);       // MongoDB's default
        IllegalStateException e = refused(ScramMinimumIterationsTest::sha256, 4095);
        assertTrue(e.getMessage().startsWith("the server asks for 4095 PBKDF2 iterations, fewer "
                + "than the 4096 this client accepts"), e.getMessage());
        assertTrue(e.getMessage().endsWith("-Dseclume.scram.minIterations=4095 accepts it"),
                e.getMessage());
        assertEquals("the server asks for 1", refused(ScramMinimumIterationsTest::sha256, 1)
                .getMessage().substring(0, 21));
    }

    @Test
    void sha512AndSha1AreHeldToTheSameFloor() {
        refused(() -> new Scram(HashAlgorithm.SHA_512), 4095);
        accepted(() -> new Scram(HashAlgorithm.SHA_512), 4096);
        refused(() -> new Scram(HashAlgorithm.SHA_1), 1000);
    }

    @Test
    void thePropertyLowersItForEveryLoginAfterwards() {
        System.setProperty(Scram.MIN_ITERATIONS_PROPERTY, "1000");
        assertEquals(1000, sha256().minimumIterations());
        accepted(ScramMinimumIterationsTest::sha256, 1000);
        IllegalStateException e = refused(ScramMinimumIterationsTest::sha256, 999);
        assertTrue(e.getMessage().contains("fewer than the 1000 this client accepts"),
                e.getMessage());
        System.setProperty(Scram.MIN_ITERATIONS_PROPERTY, " 1 ");
        accepted(ScramMinimumIterationsTest::sha256, 1);
    }

    @Test
    void thePropertyCanRaiseItToo() {
        System.setProperty(Scram.MIN_ITERATIONS_PROPERTY, "10000");
        refused(ScramMinimumIterationsTest::sha256, 9999);
        accepted(ScramMinimumIterationsTest::sha256, 10000);
    }

    @Test
    void aBlankPropertyIsTheDefault() {
        System.setProperty(Scram.MIN_ITERATIONS_PROPERTY, "  ");
        assertEquals(4096, sha256().minimumIterations());
    }

    @Test
    void aPropertyThatIsNotACountIsSaidAtTheLogin() {
        for (String wrong : new String[] {"0", "-1", "4k", "10000001", "123456789", "1e4",
                "4096.0"}) {
            System.setProperty(Scram.MIN_ITERATIONS_PROPERTY, wrong);
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    ScramMinimumIterationsTest::sha256, wrong);
            assertEquals("seclume.scram.minIterations is a number of 1 to 10000000, not " + wrong,
                    e.getMessage());
        }
    }

    @Test
    void aModuleCanSetItForOneLogin() {
        accepted(() -> sha256().minimumIterations(100), 100);
        refused(() -> sha256().minimumIterations(100), 99);
        // Over the property, in either direction.
        System.setProperty(Scram.MIN_ITERATIONS_PROPERTY, "100");
        refused(() -> sha256().minimumIterations(8192), 4096);
        for (int wrong : new int[] {0, -5, 10_000_001}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> sha256().minimumIterations(wrong));
            assertEquals("a minimum of 1 to 10000000 iterations, not " + wrong, e.getMessage());
        }
    }

    @Test
    void theCountIsRefusedBeforeAnyProofIsMade() {
        // The point of the floor is the proof: refused at serverFirst, before
        // clientFinal is reached, nothing derived from the password exists.
        try (Arena arena = Arena.ofConfined(); Scram scram = sha256()) {
            assertThrows(IllegalStateException.class, () -> serverAsks(scram, arena, 1));
            MemorySegment password = ascii(arena, "pencil");
            assertThrows(IllegalStateException.class,
                    () -> scram.clientFinal(arena.allocate(512), password));
        }
    }
}
