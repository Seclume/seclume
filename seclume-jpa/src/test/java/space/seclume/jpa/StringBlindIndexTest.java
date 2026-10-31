package space.seclume.jpa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.field.BlindIndex.Transform;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;

/**
 * The blind index for a String attribute, without a persistence provider: the
 * value an entity stores, the terms a search asks for, what is kept of the
 * candidates, a rotation, and the same values as the core's index gives.
 * {@code JakartaDataCase} in seclume-spring-test runs it through Hibernate's
 * Jakarta Data repositories against the four databases.
 *
 * <p>Isolated: the installed ring is global.
 */
@Isolated
class StringBlindIndexTest {

    /** A row as a repository would hold it: the attribute and its index value. */
    record Row(int id, String name, Long index) {
    }

    /** A table of rows and a query by index value - what a repository method is. */
    static final class Table {
        final List<Row> rows = new ArrayList<>();
        final AtomicReference<List<Long>> asked = new AtomicReference<>();

        void add(int id, String name, StringBlindIndex index) {
            rows.add(new Row(id, name, index.term(name)));
        }

        List<Row> byIndex(List<Long> terms) {
            asked.set(terms);
            return rows.stream().filter(row -> row.index() != null && terms.contains(row.index())).toList();
        }
    }

    @AfterEach
    void uninstall() {
        FieldKeys.install(null);
    }

    static SecretProvider key(int seed) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                for (int i = 0; i < 32; i++) {
                    target.set(ValueLayout.JAVA_BYTE, i, (byte) (seed * 31 + i));
                }
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
    }

    static FieldKeys ring(int seed) {
        return FieldKeys.builder().key(1, key(seed)).build();
    }

    private static MemorySegment utf8(String value) {
        return MemorySegment.ofArray(value.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void theTermIsTheCoreIndexOfTheUtf8Value() {
        try (FieldKeys keys = ring(1)) {
            StringBlindIndex name = StringBlindIndex.of(keys, "patient.name", 20, Transform.prefix(3));
            for (String value : List.of("Müller", "李小龍", "", "a", "Ørsted-Hansen")) {
                assertEquals(keys.blindIndex("patient.name", 20, Transform.prefix(3)).term(utf8(value)),
                        name.term(value), value);
                assertTrue(name.term(value) >= 0 && name.term(value) < (1L << 20), value);
            }
            assertNull(name.term(null), "NULL is stored as NULL");
            assertSame(keys.blindIndex("patient.name", 20, Transform.prefix(3)), name.index());
        }
    }

    @Test
    void theInstalledRingIsLookedUpOnUse() {
        StringBlindIndex email = StringBlindIndex.of("customer.email", 24, Transform.CASE_INSENSITIVE);
        assertThrows(IllegalStateException.class, () -> email.term("a@b.c"),
                "no ring installed, and it says so when used - not when defined");
        try (FieldKeys first = ring(1); FieldKeys second = ring(2)) {
            FieldKeys.install(first);
            long underFirst = email.term("Alice@Example.org");
            assertEquals(underFirst, email.term("alice@example.ORG"), "case-insensitive");
            FieldKeys.install(second);
            assertNotEquals(underFirst, email.term("Alice@Example.org"), "another ring, another key");
        }
    }

    @Test
    void findAsksForTheTermsAndKeepsWhatMatches() {
        try (FieldKeys keys = ring(3)) {
            // Two bits: a quarter of all rows share any index value.
            StringBlindIndex name = StringBlindIndex.of(keys, "patient.name", 2,
                    Transform.prefix(3).caseInsensitive());
            Table table = new Table();
            List<String> names = List.of("Müller", "MÜLLER", "mülheim", "Mueller", "Meyer", "Schmidt",
                    "Schneider", "Fischer", "Weber", "Wagner", "Becker", "Schulz", "Hoffmann", "Mül",
                    "Koch", "Richter", "Klein", "Wolf", "Schröder", "Neumann");
            for (int i = 0; i < names.size(); i++) {
                table.add(i, names.get(i), name);
            }
            table.add(99, null, name);

            List<Row> found = name.find("MÜL", table::byIndex, Row::name);
            assertEquals(List.of(1), found.stream().map(Row::id).toList(),
                    "case folding is ASCII's: only MÜLLER begins with MÜL");
            found = name.find("mül", table::byIndex, Row::name);
            assertEquals(List.of(0, 2, 13), found.stream().map(Row::id).toList());
            assertEquals(List.of(name.term("mül")), table.asked.get(), "one key, one term");

            List<Row> candidates = table.byIndex(name.searchTerms("mül"));
            assertTrue(candidates.size() > found.size(),
                    "with two bits the query returns rows that only share the index value: " + candidates);
            assertEquals(found, name.keep(candidates, Row::name, "mül"));
            assertEquals(List.of(), name.find("Zz", table::byIndex, Row::name));
        }
    }

    @Test
    void duringARotationRowsUnderEitherKeyAreFound() {
        StringBlindIndex ssn = StringBlindIndex.of("patient.ssn", 32, Transform.EXACT);
        Table table = new Table();
        try (FieldKeys old = ring(4)) {
            FieldKeys.install(old);
            table.add(1, "078-05-1120", ssn);
        }
        try (FieldKeys both = FieldKeys.builder().key(1, key(4)).key(2, key(5)).primary(2).build()) {
            FieldKeys.install(both);
            table.add(2, "078-05-1120", ssn);
            table.add(3, "219-09-9999", ssn);
            assertNotEquals(table.rows.get(0).index(), table.rows.get(1).index(),
                    "the new row is indexed under the new primary key");
            List<Long> terms = ssn.searchTerms("078-05-1120");
            assertEquals(2, terms.size());
            assertEquals(table.rows.get(1).index(), terms.get(0), "the primary's first");
            assertEquals(List.of(1, 2), ssn.find("078-05-1120", table::byIndex, Row::name).stream()
                    .map(Row::id).toList());
        }
        try (FieldKeys rotated = FieldKeys.builder().key(2, key(5)).build()) {
            FieldKeys.install(rotated);
            assertEquals(List.of(2), ssn.find("078-05-1120", table::byIndex, Row::name).stream()
                    .map(Row::id).toList(), "the old key retired: rows not reindexed are not found");
        }
    }

    @Test
    void matchesIsTheTransformsEquality() {
        try (FieldKeys keys = ring(6)) {
            StringBlindIndex card = StringBlindIndex.of(keys, "card.number", 16, Transform.suffix(4));
            assertTrue(card.matches("4111222233331234", "1234"));
            assertFalse(card.matches("4111222233331234", "1235"));
            StringBlindIndex phone = StringBlindIndex.of(keys, "customer.phone", 16, Transform.DIGITS);
            assertTrue(phone.matches("+49 (30) 1234-567", "4930 1234567"));
            assertFalse(phone.matches(null, "1"));
            assertFalse(phone.matches("1", null));
            assertFalse(phone.matches(null, null));
        }
    }

    @Test
    void theIndexesOfOneValueSayNothingOfEachOther() {
        try (FieldKeys keys = ring(7)) {
            Map<String, Long> terms = new HashMap<>();
            terms.put("name exact", StringBlindIndex.of(keys, "patient.name", 32, Transform.EXACT).term("Ann"));
            terms.put("name ci", StringBlindIndex.of(keys, "patient.name", 32, Transform.CASE_INSENSITIVE).term("Ann"));
            terms.put("other column", StringBlindIndex.of(keys, "doctor.name", 32, Transform.EXACT).term("Ann"));
            terms.put("other size", StringBlindIndex.of(keys, "patient.name", 31, Transform.EXACT).term("Ann") << 1);
            assertEquals(4, terms.values().stream().distinct().count(), terms.toString());
        }
    }

    @Test
    void nonsenseIsRefusedWhenDefined() {
        assertThrows(IllegalArgumentException.class, () -> StringBlindIndex.of("", 16, Transform.EXACT));
        assertThrows(IllegalArgumentException.class, () -> StringBlindIndex.of(" ", 16, Transform.EXACT));
        assertThrows(IllegalArgumentException.class, () -> StringBlindIndex.of("n", 0, Transform.EXACT));
        assertThrows(IllegalArgumentException.class, () -> StringBlindIndex.of("n", 65, Transform.EXACT));
        assertThrows(IllegalArgumentException.class, () -> StringBlindIndex.of("n", 16, null));
        assertThrows(IllegalArgumentException.class, () -> StringBlindIndex.of(null, "n", 16, Transform.EXACT));
        try (FieldKeys keys = ring(8)) {
            StringBlindIndex index = StringBlindIndex.of(keys, "n", 16, Transform.EXACT);
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> index.searchTerms(null));
            assertTrue(e.getMessage().contains("is null"), e.getMessage());
            assertEquals("StringBlindIndex[n, 16 bits]", index.toString());
        }
        FieldKeys closed = ring(9);
        StringBlindIndex index = StringBlindIndex.of(closed, "n", 16, Transform.EXACT);
        closed.close();
        assertThrows(IllegalStateException.class, () -> index.term("x"), "a closed ring");
    }

    /** Rows of patients by birth date, ISO: what a month bucket is searched over. */
    private static Table births(StringBlindIndex months) {
        Table table = new Table();
        String[] dates = {"2025-12-31", "2026-01-01", "2026-01-17", "2026-02-28", "2026-03-01",
            "2026-03-31", "2026-04-01", "2026-06-15", "2027-01-05", "1926-02-11"};
        for (int i = 0; i < dates.length; i++) {
            table.add(i, dates[i], months);
        }
        return table;
    }

    @Test
    void aRangeIsSearchedAsTheBucketsItCovers() {
        try (FieldKeys keys = ring(10)) {
            // Two bits: most months share an index value with others.
            StringBlindIndex months = StringBlindIndex.of(keys, "patient.birth_month", 2, Transform.prefix(7));
            Table table = births(months);
            int[] calls = {0};
            List<Row> firstQuarter = months.findAny(List.of("2026-01", "2026-02", "2026-03"), terms -> {
                calls[0]++;
                return table.byIndex(terms);
            }, Row::name);
            assertEquals(List.of(1, 2, 3, 4, 5), firstQuarter.stream().map(Row::id).toList(),
                    "January to March 2026, in the table's order");
            assertEquals(1, calls[0], "one query for all the buckets");
            assertTrue(table.asked.get().size() <= 3, "a term per bucket at most: " + table.asked.get());
            assertEquals(List.of(7), months.findAny(List.of("2026-06"), table::byIndex, Row::name)
                    .stream().map(Row::id).toList());
            assertEquals(List.of(), months.findAny(List.of("2030-01", "2030-02"), table::byIndex, Row::name));
        }
    }

    @Test
    void theBucketsCanRepeatAndEachRowComesOnce() {
        try (FieldKeys keys = ring(11)) {
            StringBlindIndex months = StringBlindIndex.of(keys, "patient.birth_month", 1, Transform.prefix(7));
            Table table = births(months);
            List<Row> found = months.findAny(List.of("2026-03", "2026-03", "2026-01", "2026-03-15"),
                    table::byIndex, Row::name);
            assertEquals(List.of(1, 2, 4, 5), found.stream().map(Row::id).toList(),
                    "a value longer than the prefix is its bucket; a row matching two values comes once");
            assertEquals(new java.util.HashSet<>(table.asked.get()).size(), table.asked.get().size(),
                    "each term asked for once");
        }
    }

    @Test
    void findAnyDuringARotationAsksForEveryKeysTerms() {
        StringBlindIndex months = StringBlindIndex.of("patient.birth_month", 32, Transform.prefix(7));
        Table table = new Table();
        try (FieldKeys old = ring(12)) {
            FieldKeys.install(old);
            table.add(1, "2026-01-10", months);
        }
        try (FieldKeys both = FieldKeys.builder().key(1, key(12)).key(2, key(13)).primary(2).build()) {
            FieldKeys.install(both);
            table.add(2, "2026-02-10", months);
            assertEquals(List.of(1, 2), months.findAny(List.of("2026-01", "2026-02"), table::byIndex, Row::name)
                    .stream().map(Row::id).toList(), "old and new rows");
            assertEquals(4, table.asked.get().size(), "two buckets, two keys");
        }
    }

    @Test
    void findAnyNeedsSomethingToFind() {
        try (FieldKeys keys = ring(14)) {
            StringBlindIndex months = StringBlindIndex.of(keys, "m", 8, Transform.prefix(7));
            Table table = new Table();
            assertThrows(IllegalArgumentException.class, () -> months.findAny(List.of(), table::byIndex, Row::name));
            assertThrows(IllegalArgumentException.class, () -> months.findAny(null, table::byIndex, Row::name));
            assertThrows(IllegalArgumentException.class, () -> months.findAny(
                    java.util.Arrays.asList("2026-01", null), table::byIndex, Row::name));
        }
    }
}
