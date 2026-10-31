package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.List;

import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * A share file comes from a person, a mount, a copy and paste: whatever is in
 * it, it is read or refused with {@link SecretUnavailableException}, nothing is
 * written outside the space given, and combined with two good shares of the
 * golden split it gives the secret only if it is one of the golden shares.
 *
 * <p>The ordinary build replays the seed corpus
 * ({@code ShamirShareFuzzTestInputs}); {@code JAZZER_FUZZ=1} searches, and
 * CI's {@code parser-fuzz} job does that for a minute on every pull request.
 */
class ShamirShareFuzzTest {

    private static final byte GUARD = 0x5a;

    @FuzzTest(maxDuration = "60s")
    void anyShareIsReadOrRefused(byte[] input) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = arena.allocate(Math.max(1, input.length));
            MemorySegment.copy(input, 0, text, ValueLayout.JAVA_BYTE, 0, input.length);
            int capacity = ShamirShares.MAX_SECRET + ShamirShares.CHECK;
            MemorySegment guarded = arena.allocate(capacity + 16);
            guarded.fill(GUARD);
            MemorySegment y = guarded.asSlice(0, capacity);
            ShamirShares.Share share;
            try {
                share = ShamirShares.parse(text, input.length, y);
            } catch (SecretUnavailableException refused) {
                assertGuard(guarded, capacity);
                return;
            } catch (RuntimeException e) {
                fail("not a refusal: " + e, e);
                return;
            }
            assertGuard(guarded, capacity);
            assertTrue(share.length() > ShamirShares.CHECK && share.length() <= capacity);
            assertTrue(share.x() >= 1 && share.x() <= 255 && share.threshold() >= 2);

            List<String> golden = ShamirSharesTest.GOLDEN;
            MemorySegment target = arena.allocate(64);
            try {
                int n = ShamirShares.combine(List.of(parseGolden(arena, golden.get(0)),
                        parseGolden(arena, golden.get(1)), share), target);
                assertEquals(32, n);
                for (int i = 0; i < 32; i++) {
                    assertEquals((byte) i, target.get(ValueLayout.JAVA_BYTE, i));
                }
                boolean isGolden = false;
                for (String line : golden.subList(2, 5)) {
                    byte[] bytes = line.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                    MemorySegment expected = arena.allocate(capacity);
                    MemorySegment lineText = arena.allocate(bytes.length);
                    MemorySegment.copy(bytes, 0, lineText, ValueLayout.JAVA_BYTE, 0, bytes.length);
                    ShamirShares.Share g = ShamirShares.parse(lineText, bytes.length, expected);
                    if (g.x() == share.x()) {
                        assertArrayEquals(expected.asSlice(0, g.length()).toArray(ValueLayout.JAVA_BYTE),
                                y.asSlice(0, share.length()).toArray(ValueLayout.JAVA_BYTE));
                        isGolden = true;
                    }
                }
                assertTrue(isGolden, "a share that is not one of the split's opened it");
            } catch (SecretUnavailableException refused) {
                for (int i = 0; i < 64; i++) {
                    assertEquals(0, target.get(ValueLayout.JAVA_BYTE, i), "a refused combination left bytes");
                }
            } catch (RuntimeException e) {
                fail("not a refusal: " + e, e);
            }
        }
    }

    private static ShamirShares.Share parseGolden(Arena arena, String line) {
        byte[] bytes = line.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        MemorySegment text = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, text, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return ShamirShares.parse(text, bytes.length,
                arena.allocate(ShamirShares.MAX_SECRET + ShamirShares.CHECK));
    }

    private static void assertGuard(MemorySegment guarded, int capacity) {
        for (int i = capacity; i < capacity + 16; i++) {
            assertEquals(GUARD, guarded.get(ValueLayout.JAVA_BYTE, i), "written past the space given");
        }
    }
}
