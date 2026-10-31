package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import space.seclume.field.BlindIndex.Transform;

/**
 * Blind indexes: known answers from an independent implementation (Python's
 * hmac and hashlib), each transform, the bits and the buckets they make, one
 * key per name, transform, size and ring key - and the rotation.
 */
class BlindIndexTest {

    private static final byte[] KEY = new byte[32];
    private static final byte[] OTHER = new byte[32];

    static {
        for (int i = 0; i < 32; i++) {
            KEY[i] = (byte) i;
            OTHER[i] = (byte) (255 - i);
        }
    }

    private static MemorySegment text(String value) {
        return MemorySegment.ofArray(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String transformed(Transform transform, String value) {
        MemorySegment in = text(value);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(Math.max(1, in.byteSize()));
            int n = BlindIndex.apply(transform, in, out);
            return new String(out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
        }
    }

    @Test
    void knownAnswersFromAnIndependentImplementation() {
        try (FieldKeys keys = FieldEncryptionTest.ring(1, KEY)) {
            assertEquals(13115729L, keys.blindIndex("customer.email", 24, Transform.CASE_INSENSITIVE)
                    .term(text("Alice@Example.ORG")));
            assertEquals(28424L, keys.blindIndex("card.number", 16, Transform.suffix(4))
                    .term(text("4111222233331234")));
            assertEquals(45975L, keys.blindIndex("customer.name", 20, Transform.prefix(3))
                    .term(text("Müller")));
            assertEquals(3168714609L, keys.blindIndex("customer.phone", 32, Transform.DIGITS)
                    .term(text("030 / 123 45-67")));
            // 64 bits: all of them, as Java's signed long - 17624942459740689079 unsigned.
            assertEquals(Long.parseUnsignedLong("17624942459740689079"),
                    keys.blindIndex("x", 64, Transform.EXACT).term(text("")));
        }
    }

    @Test
    void theTransforms() {
        assertEquals("Ab-1", transformed(Transform.EXACT, "Ab-1"));
        assertEquals("ab-1 ü", transformed(Transform.CASE_INSENSITIVE, "AB-1 ü"));
        assertEquals("491701234", transformed(Transform.DIGITS, "+49 (170) 1234"));
        assertEquals("Mül", transformed(Transform.prefix(3), "Müller"));
        assertEquals("mül", transformed(Transform.prefix(3).caseInsensitive(), "MÜller".replace("Ü", "ü")));
        assertEquals("Mü", transformed(Transform.prefix(3), "Mü"), "shorter than the prefix: whole");
        assertEquals("ler", transformed(Transform.suffix(3), "Müller"));
        assertEquals("ßü€", transformed(Transform.suffix(3), "aßü€"), "code points, not bytes");
        assertEquals("1234", transformed(Transform.suffix(4), "1234"));
        assertEquals("12", transformed(Transform.suffix(4), "12"));
        assertEquals("", transformed(Transform.DIGITS, "no digits"));
    }

    @Test
    void aPrefixSearchFindsEveryValueThatStartsSo() {
        try (FieldKeys keys = FieldEncryptionTest.ring(1, KEY)) {
            BlindIndex names = keys.blindIndex("customer.name", 32, Transform.prefix(3).caseInsensitive());
            long query = names.term(text("mül"));
            assertEquals(query, names.term(text("Müller")));
            assertEquals(query, names.term(text("MÜLLER".replace("Ü", "ü"))));
            assertEquals(query, names.term(text("Mülheim")));
            assertNotEquals(query, names.term(text("Meier")));
        }
    }

    @Test
    void theBitsAreTheBitsAndMakeEvenBuckets() {
        try (FieldKeys keys = FieldEncryptionTest.ring(1, KEY)) {
            for (int bits : new int[] {1, 8, 16, 31, 32, 63}) {
                BlindIndex index = keys.blindIndex("b" + bits, bits, Transform.EXACT);
                for (int i = 0; i < 200; i++) {
                    long term = index.term(text("value " + i));
                    assertEquals(0, term >>> bits, bits + " bits: " + term);
                }
            }
            // 8 bits over 25600 values: every bucket about 100, none far off.
            BlindIndex eight = keys.blindIndex("even", 8, Transform.EXACT);
            Map<Long, Integer> buckets = new HashMap<>();
            for (int i = 0; i < 25_600; i++) {
                buckets.merge(eight.term(text("customer-" + i)), 1, Integer::sum);
            }
            assertEquals(256, buckets.size());
            double chiSquare = 0;
            for (int count : buckets.values()) {
                chiSquare += Math.pow(count - 100, 2) / 100;
            }
            // 255 degrees of freedom: the 99.99th percentile is about 350.
            assertTrue(chiSquare < 350, "chi-square " + chiSquare);
        }
    }

    @Test
    void bitsForATableAndACandidateCount() {
        // At least as many candidates as asked for: 2^9 buckets leave about 1953 each.
        assertEquals(9, BlindIndex.bitsFor(1_000_000, 1000));
        assertEquals(13, BlindIndex.bitsFor(1_000_000, 100));
        assertEquals(1, BlindIndex.bitsFor(10, 100));
        assertEquals(32, BlindIndex.bitsFor(Long.MAX_VALUE, 1));
        assertThrows(IllegalArgumentException.class, () -> BlindIndex.bitsFor(0, 1));
        assertThrows(IllegalArgumentException.class, () -> BlindIndex.bitsFor(1, 0));
    }

    @Test
    void everyNameTransformSizeAndKeyHasItsOwnKey() {
        try (FieldKeys keys = FieldEncryptionTest.ring(1, KEY); FieldKeys other = FieldEncryptionTest.ring(1, OTHER)) {
            MemorySegment value = text("4711");
            Set<Long> seen = new HashSet<>();
            seen.add(keys.blindIndex("a", 32, Transform.EXACT).term(value));
            seen.add(keys.blindIndex("b", 32, Transform.EXACT).term(value));
            seen.add(keys.blindIndex("a", 32, Transform.CASE_INSENSITIVE).term(value));
            seen.add(keys.blindIndex("a", 32, Transform.DIGITS).term(value));
            seen.add(keys.blindIndex("a", 32, Transform.suffix(4)).term(value));
            seen.add(keys.blindIndex("a", 31, Transform.EXACT).term(value) << 1);
            seen.add(other.blindIndex("a", 32, Transform.EXACT).term(value));
            assertEquals(7, seen.size(), "an index says nothing about another");
            assertEquals(keys.blindIndex("a", 32, Transform.EXACT), keys.blindIndex("a", 32, Transform.EXACT),
                    "made once, then shared");
        }
    }

    @Test
    void duringARotationBothKeysAreSearched() {
        byte[] stored;
        try (FieldKeys one = FieldEncryptionTest.ring(1, KEY)) {
            stored = new byte[0];
            long old = one.blindIndex("ssn", 32, Transform.EXACT).term(text("123-45-6789"));
            try (FieldKeys both = FieldKeys.builder().key(1, FieldEncryptionTest.provider(KEY))
                    .key(2, FieldEncryptionTest.provider(OTHER)).primary(2).build()) {
                BlindIndex index = both.blindIndex("ssn", 32, Transform.EXACT);
                List<Long> terms = index.searchTerms(text("123-45-6789"));
                assertEquals(2, terms.size());
                assertEquals(index.term(text("123-45-6789")), terms.get(0), "the primary's first");
                assertEquals(old, terms.get(1), "the old rows are found too");
            }
        }
        assertEquals(0, stored.length);
    }

    @Test
    void closedRingsAndNonsenseAreRefused() {
        FieldKeys keys = FieldEncryptionTest.ring(1, KEY);
        BlindIndex index = keys.blindIndex("n", 16, Transform.EXACT);
        assertThrows(IllegalArgumentException.class, () -> index.term(null));
        keys.close();
        assertThrows(IllegalStateException.class, () -> index.term(text("x")));
        try (FieldKeys open = FieldEncryptionTest.ring(1, KEY)) {
            assertThrows(IllegalArgumentException.class, () -> open.blindIndex("", 16, Transform.EXACT));
            assertThrows(IllegalArgumentException.class, () -> open.blindIndex("n", 0, Transform.EXACT));
            assertThrows(IllegalArgumentException.class, () -> open.blindIndex("n", 65, Transform.EXACT));
            assertThrows(IllegalArgumentException.class, () -> open.blindIndex("n", 16, null));
        }
        assertThrows(IllegalArgumentException.class, () -> Transform.prefix(0));
        assertThrows(IllegalArgumentException.class, () -> Transform.suffix(65));
        assertThrows(IllegalArgumentException.class, () -> new Transform("regex", 0, false));
        assertThrows(IllegalArgumentException.class, () -> new Transform("exact", 3, false));
        assertEquals("BlindIndex[n, exact, 16 bits]", index.toString());
    }

    @Test
    void matchesIsEqualityAfterTheTransform() {
        try (FieldKeys keys = FieldEncryptionTest.ring(1, KEY)) {
            BlindIndex email = keys.blindIndex("customer.email", 24, Transform.CASE_INSENSITIVE);
            assertTrue(email.matches(text("Alice@Example.ORG"), text("alice@example.org")));
            assertTrue(!email.matches(text("alice@example.org"), text("alice@example.com")));
            assertTrue(!email.matches(text("alice@example.org"), text("alice@example.or")),
                    "a prefix is not the value");

            BlindIndex card = keys.blindIndex("card.number", 16, Transform.suffix(4));
            assertTrue(card.matches(text("4111222233331234"), text("1234")));
            assertTrue(card.matches(text("5500000000001234"), text("4111222233331234")));
            assertTrue(!card.matches(text("4111222233331235"), text("1234")));

            BlindIndex name = keys.blindIndex("customer.name", 20, Transform.prefix(3).caseInsensitive());
            assertTrue(name.matches(text("Müller"), text("MÜLLER-Lüdenscheidt")) == false,
                    "case folding is ASCII's: ü and Ü differ");
            assertTrue(name.matches(text("Müller"), text("müllerin")));
            assertTrue(name.matches(text("MÜller"), text("mÜ")) == false, "mÜ is two characters, not three");
            assertTrue(name.matches(text("MÜ"), text("mÜ")), "shorter than the prefix: the whole value");

            BlindIndex phone = keys.blindIndex("customer.phone", 20, Transform.DIGITS);
            assertTrue(phone.matches(text("+49 (30) 1234-567"), text("4930 1234567")));
            assertTrue(!phone.matches(text("+49 30 1234 568"), text("4930 1234567")));

            BlindIndex exact = keys.blindIndex("ssn", 32, Transform.EXACT);
            assertTrue(exact.matches(text(""), text("")));
            assertTrue(!exact.matches(text(""), text("x")));
            assertTrue(!exact.matches(null, text("x")));
            assertTrue(!exact.matches(text("x"), null));
            assertTrue(!exact.matches(null, null), "NULL matches nothing");
        }
    }

    /**
     * What a search does: every value that shares the index value is a
     * candidate, and matches keeps exactly those that are the value searched
     * for - with few bits, many share it.
     */
    @Test
    void matchesKeepsExactlyTheRightCandidates() {
        try (FieldKeys keys = FieldEncryptionTest.ring(1, KEY)) {
            BlindIndex index = keys.blindIndex("customer.email", 3, Transform.CASE_INSENSITIVE);
            String wanted = "Bob@Example.org";
            long term = index.term(text(wanted));
            int candidates = 0;
            int kept = 0;
            for (int i = 0; i < 400; i++) {
                String value = i % 50 == 0 ? (i % 100 == 0 ? "bob@example.ORG" : "BOB@EXAMPLE.ORG")
                        : "user" + i + "@example.org";
                if (index.term(text(value)) == term) {
                    candidates++;
                    if (index.matches(text(value), text(wanted))) {
                        kept++;
                        assertTrue(value.equalsIgnoreCase(wanted), value);
                    }
                }
            }
            assertEquals(8, kept, "every spelling of the address, and nothing else");
            assertTrue(candidates > 20, "three bits: about one in eight shares the value, " + candidates);
        }
    }
}
