package space.seclume.field;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.field.BlindIndex.Transform;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * What a ring does around its use: every scope it opened is wiped when it
 * closes - the data keys, every column's keys, every blind index's - and a
 * closed ring says so, by name, wherever it is asked; the providers it read
 * its keys from are closed once they are read; and what it accepts as a key,
 * byte by byte at the edges of the Base64 alphabet and of the whitespace it
 * trims. Written against the mutants PIT left alive in this package.
 *
 * <p>Isolated: the count of open secret scopes is the JVM's.
 */
@Isolated
class FieldKeysLifecycleTest {

    private static final byte[] KEY = new byte[32];

    static {
        for (int i = 0; i < KEY.length; i++) {
            KEY[i] = (byte) (0x90 + i);
        }
    }

    private static MemorySegment text(String value) {
        return MemorySegment.ofArray(value.getBytes(StandardCharsets.UTF_8));
    }

    /** A provider of fixed bytes that counts its closes. */
    static final class Counted implements SecretProvider {
        final byte[] bytes;
        final AtomicInteger closes = new AtomicInteger();

        Counted(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public int writeSecret(MemorySegment target) {
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        }

        @Override
        public int maxSecretLength() {
            return Math.max(1, bytes.length);
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }
    }

    private static FieldKeys ring(byte[] key) {
        return FieldKeys.builder().key(1, new Counted(key)).build();
    }

    @Test
    void closingWipesEveryScopeTheRingOpened() {
        long before = SecretScope.open();
        FieldKeys keys = ring(KEY);
        long withKeys = SecretScope.open();
        keys.column("t.a", Mode.RANDOMIZED);
        keys.column("t.b", Mode.DETERMINISTIC);
        long withColumns = SecretScope.open();
        keys.blindIndex("t.a", 16, Transform.EXACT);
        keys.blindIndex("t.a", 16, Transform.CASE_INSENSITIVE);
        long withIndexes = SecretScope.open();
        assertTrue(withKeys > before, "the data key is in a scope of its own");
        assertTrue(withColumns > withKeys, "each column's keys are");
        assertTrue(withIndexes > withColumns, "and each blind index's");
        keys.close();
        assertEquals(before, SecretScope.open(),
                "the data key, the columns' keys and the blind indexes' keys are all wiped on close");
        keys.close();
        assertEquals(before, SecretScope.open(), "a second close changes nothing");
    }

    @Test
    void aClosedRingSaysSoWhereverItIsAsked() {
        FieldKeys keys = ring(KEY);
        EncryptedColumn column = keys.column("t.a", Mode.RANDOMIZED);
        BlindIndex index = keys.blindIndex("t.a", 16, Transform.EXACT);
        byte[] stored = column.encrypt(text("x"));
        keys.close();
        for (Runnable call : List.<Runnable>of(
                () -> keys.column("t.a", Mode.RANDOMIZED),
                () -> keys.column("t.new", Mode.RANDOMIZED),
                () -> keys.blindIndex("t.a", 16, Transform.EXACT),
                () -> keys.blindIndex("t.new", 16, Transform.EXACT),
                () -> index.term(text("x")),
                () -> column.encrypt(text("x")),
                () -> column.decrypt(stored, MemorySegment.ofArray(new byte[8])))) {
            IllegalStateException e = assertThrows(IllegalStateException.class, call::run);
            assertTrue(e.getMessage().contains("field keys are closed"),
                    "the ring's own words, not a scope's somewhere underneath: " + e.getMessage());
        }
        assertTrue(keys.toString().endsWith(", closed]"), keys.toString());
    }

    @Test
    void toStringNamesTheKeysAndThePrimaryOnly() {
        try (FieldKeys keys = FieldKeys.builder().key(3, new Counted(KEY)).key(7, new Counted(KEY.clone()))
                .primary(7).build()) {
            assertEquals("FieldKeys[keys=[3, 7], primary=7]", keys.toString());
        }
    }

    @Test
    void theProvidersAreClosedOnceTheirKeysAreRead() {
        Counted one = new Counted(KEY);
        Counted two = new Counted(KEY.clone());
        try (FieldKeys keys = FieldKeys.builder().key(1, one).key(2, two).build()) {
            assertEquals(1, one.closes.get(), "a key is read once and its source closed");
            assertEquals(1, two.closes.get());
            assertEquals(List.of(1, 2), keys.keyIds());
        }
        Counted good = new Counted(KEY);
        Counted bad = new Counted(new byte[] {1, 2, 3});
        assertThrows(IllegalArgumentException.class, () -> FieldKeys.builder().key(1, good).key(2, bad).build());
        assertEquals(1, good.closes.get(), "closed even when another key fails");
        assertEquals(1, bad.closes.get());
    }

    /** 32 bytes that are all one character: text, refused as a raw key. */
    private static byte[] repeated(char c) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) c);
        return bytes;
    }

    @Test
    void thirtyTwoCharactersOfBase64TextAreNoKeyAtEveryEdgeOfTheAlphabet() {
        for (char c : new char[] {'A', 'Z', 'a', 'z', '0', '9', '+', '/', '=', '-', '_'}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ring(repeated(c)),
                    "32 times '" + c + "'");
            assertTrue(e.getMessage().contains("32 characters of text"), e.getMessage());
        }
        // One byte just outside the alphabet, and the 32 bytes are a key: random bytes, not text.
        for (char outside : new char[] {'@', '[', '`', '{', ':', '.', ',', '*', ' '}) {
            byte[] bytes = repeated('A');
            bytes[31] = (byte) outside;
            assertDoesNotThrow(() -> ring(bytes).close(), "'A' * 31 + '" + outside + "'");
        }
        byte[] high = repeated('A');
        high[0] = (byte) 0xC0;
        assertDoesNotThrow(() -> ring(high).close(), "a byte above ASCII is not Base64 text");
    }

    @Test
    void base64WithATrailingLineBreakOrBlankIsTheSameKey() {
        String encoded = Base64.getEncoder().encodeToString(KEY);
        byte[] reference;
        try (FieldKeys keys = ring(encoded.getBytes(StandardCharsets.US_ASCII))) {
            reference = keys.column("t.d", Mode.DETERMINISTIC).encrypt(text("same"));
        }
        for (String tail : List.of("\n", "\r\n", " ", "\t", " \n\t\r", "\n\n")) {
            try (FieldKeys keys = ring((encoded + tail).getBytes(StandardCharsets.US_ASCII))) {
                assertTrue(Arrays.equals(reference, keys.column("t.d", Mode.DETERMINISTIC).encrypt(text("same"))),
                        "Base64 followed by " + tail.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"));
            }
        }
    }

    @Test
    void onlyBlanksAreAKeyOfNoBytes() {
        for (String blanks : List.of("\n", "  \t\r\n")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> ring(blanks.getBytes(StandardCharsets.US_ASCII)));
            assertTrue(e.getMessage().contains("is 0 bytes"), e.getMessage());
        }
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ring(("x" + Base64.getEncoder().encodeToString(KEY) + "\n").getBytes(StandardCharsets.US_ASCII)));
        assertNotEquals(-1, e.getMessage().indexOf("key 1"), e.getMessage());
    }
}
