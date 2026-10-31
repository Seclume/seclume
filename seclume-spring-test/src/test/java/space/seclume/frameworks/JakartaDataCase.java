package space.seclume.frameworks;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;

import javax.sql.DataSource;

import org.hibernate.SessionFactory;
import org.hibernate.StatelessSession;
import org.hibernate.Transaction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.PersistenceConfiguration;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.FieldKeys;
import space.seclume.secret.FileSecretProvider;

/**
 * Jakarta Data on the seclume drivers: a repository that Hibernate's
 * annotation processor implements ({@code Patients_}), over a stateless
 * session, with encrypted attributes - a deterministic SSN found by
 * {@code @Find} and {@code in}, a randomized name and e-mail address found
 * through blind indexes with {@link space.seclume.jpa.StringBlindIndex#find}.
 *
 * <p>What a search returns is checked against an implementation of the
 * transforms written here, apart from the library's; the rows a two-bit
 * index returns are more than those that match, and the ones kept are
 * exactly those. The table is read with plain JDBC as well: ciphertext and
 * small numbers, never a name.
 *
 * <p>Isolated: the installed key ring is global.
 */
@Isolated
abstract class JakartaDataCase {

    private static final String TABLE = "zl_indexed_patient";

    /** Forty names: shared prefixes, case, umlauts, other scripts, short ones. */
    private static final List<String> NAMES = List.of(
            "Müller", "MÜLLER", "mülheim", "Mueller", "Muller", "Meyer", "Meier", "Mey",
            "Schmidt", "Schmitt", "SCHMIDT-Rottluff", "schmal", "Schneider", "Fischer", "Fisch",
            "Weber", "Wagner", "WAGNER", "Becker", "Schulz", "Hoffmann", "Hof", "Koch", "Richter",
            "Klein", "Wolf", "Wolfram", "Schröder", "Schroeder", "Neumann", "Ørsted", "ørsted",
            "李小龍", "李小", "Ана", "Анатолий", "Al", "AL", "al-Rashid", "Zoë");

    @TempDir
    Path directory;

    private FieldKeys keys;
    private EntityManagerFactory factory;
    private SessionFactory sessions;

    /** The shared pool for this server. */
    abstract DataSource dataSource() throws Exception;

    private Path keyFile(String name, int seed) throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (seed * 37 + i * 7 + 1);
        }
        return Files.writeString(directory.resolve(name), Base64.getEncoder().encodeToString(key));
    }

    private FieldKeys ring(int... seeds) throws Exception {
        FieldKeys.Builder builder = FieldKeys.builder();
        for (int seed : seeds) {
            builder.key(seed, new FileSecretProvider(keyFile("key-" + seed, seed), 128));
        }
        return builder.primary(seeds[seeds.length - 1]).build();
    }

    private void open(String action) throws Exception {
        factory = new PersistenceConfiguration("zl-jakarta-data")
                .managedClass(IndexedPatient.class)
                .property(PersistenceConfiguration.SCHEMAGEN_DATABASE_ACTION, action)
                .property("hibernate.connection.datasource", dataSource())
                .createEntityManagerFactory();
        sessions = factory.unwrap(SessionFactory.class);
    }

    private void close() {
        if (factory != null) {
            factory.close();
            factory = null;
        }
    }

    @BeforeEach
    void keysAndASchema() throws Exception {
        keys = ring(1);
        FieldKeys.install(keys);
        open("drop-and-create");
    }

    @AfterEach
    void tidyUp() throws Exception {
        close();
        if (keys != null) {
            keys.close();
        }
        FieldKeys.install(null);
        try (Connection connection = dataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("drop table " + TABLE);
        } catch (java.sql.SQLException alreadyGone) {
            // the schema action may have dropped it
        }
    }

    /**
     * The repository in a transaction of its own, as an application uses it.
     * With Spring on the class path, Hibernate's processor writes a repository
     * that takes its session from an {@code ObjectProvider} - here one that
     * holds this transaction's session and nothing else.
     */
    private <R> R inTransaction(Function<Patients, R> work) {
        try (StatelessSession session = sessions.openStatelessSession()) {
            Transaction transaction = session.beginTransaction();
            try {
                StaticListableBeanFactory beans = new StaticListableBeanFactory();
                beans.addBean("session", session);
                R result = work.apply(new Patients_(beans.getBeanProvider(StatelessSession.class)));
                transaction.commit();
                return result;
            } catch (RuntimeException e) {
                if (transaction.isActive()) {
                    transaction.rollback();
                }
                throw e;
            }
        }
    }

    private void run(Consumer<Patients> work) {
        inTransaction(patients -> {
            work.accept(patients);
            return null;
        });
    }

    private <R> R read(Function<Patients, R> query) {
        return inTransaction(query);
    }

    private static List<Long> ids(List<IndexedPatient> patients) {
        return patients.stream().map(IndexedPatient::id).toList();
    }

    private void everyone() {
        List<IndexedPatient> all = new ArrayList<>();
        for (int i = 0; i < NAMES.size(); i++) {
            all.add(new IndexedPatient(i + 1, NAMES.get(i),
                    "Person." + i + "@Example.ORG", String.format(Locale.ROOT, "%03d-%02d-%04d", i, i, i * 7)));
        }
        run(patients -> patients.addAll(all));
    }

    /**
     * The name transform as written here, apart from the library: the first
     * three code points, ASCII letters folded to lower case.
     */
    private static String firstThree(String value) {
        int end = value.offsetByCodePoints(0, Math.min(3, value.codePointCount(0, value.length())));
        StringBuilder folded = new StringBuilder();
        for (char c : value.substring(0, end).toCharArray()) {
            folded.append(c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c);
        }
        return folded.toString();
    }

    private static List<Long> expectedByName(String wanted) {
        List<Long> ids = new ArrayList<>();
        for (int i = 0; i < NAMES.size(); i++) {
            if (firstThree(NAMES.get(i)).equals(firstThree(wanted))) {
                ids.add((long) i + 1);
            }
        }
        return ids;
    }

    @Test
    void attributesComeBackThroughTheRepository() {
        everyone();
        IndexedPatient one = read(patients -> patients.byId(1L)).orElseThrow();
        assertEquals("Müller", one.name());
        assertEquals("Person.0@Example.ORG", one.email());
        assertEquals("000-00-0000", one.ssn());
        assertEquals(IndexedPatient.NAME.term("Müller"), one.nameIndex());
        assertEquals("李小龍", read(patients -> patients.byId(33L)).orElseThrow().name());
        assertEquals("Анатолий", read(patients -> patients.byId(36L)).orElseThrow().name());
        assertEquals(NAMES, read(Patients::all).stream().map(IndexedPatient::name).toList());
        assertTrue(read(patients -> patients.byId(999L)).isEmpty());
    }

    @Test
    void theServerHoldsCiphertextAndSmallNumbers() throws Exception {
        everyone();
        Set<Long> nameIndexes = new HashSet<>();
        int rows = 0;
        try (Connection connection = dataSource().getConnection();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select id, name, name_index, email, email_index, ssn from " + TABLE)) {
            while (result.next()) {
                rows++;
                int i = (int) result.getLong(1) - 1;
                byte[] name = result.getBytes(2);
                byte[] email = result.getBytes(4);
                byte[] ssn = result.getBytes(6);
                assertEquals(NAMES.get(i).getBytes(StandardCharsets.UTF_8).length + EncryptedColumn.OVERHEAD,
                        name.length, "row " + (i + 1));
                assertEquals(("Person." + i + "@Example.ORG").length() + EncryptedColumn.OVERHEAD, email.length);
                assertEquals(11 + EncryptedColumn.OVERHEAD, ssn.length);
                String stored = new String(name, StandardCharsets.UTF_8) + new String(email, StandardCharsets.UTF_8)
                        + new String(name, StandardCharsets.ISO_8859_1) + new String(email, StandardCharsets.ISO_8859_1)
                        + new String(ssn, StandardCharsets.ISO_8859_1);
                // Two or three bytes turn up in random ciphertext by chance - "Al" did,
                // once in about a hundred runs - so the search is for names of four
                // bytes and more; the lengths above hold for every row.
                if (NAMES.get(i).getBytes(StandardCharsets.UTF_8).length >= 4) {
                    assertFalse(stored.contains(NAMES.get(i)), "a name is in the database: row " + (i + 1));
                }
                assertFalse(stored.contains("Example"), "an address is in the database");
                assertFalse(stored.contains(String.format(Locale.ROOT, "%03d-", i)), "an SSN is in the database");
                assertEquals(0, name[1], "the name is randomized");
                assertEquals(1, ssn[1], "the SSN is deterministic");
                long nameIndex = result.getLong(3);
                long emailIndex = result.getLong(5);
                assertTrue(nameIndex >= 0 && nameIndex < (1L << IndexedPatient.NAME_BITS), "name_index " + nameIndex);
                assertTrue(emailIndex >= 0 && emailIndex < (1L << 16), "email_index " + emailIndex);
                nameIndexes.add(nameIndex);
            }
        }
        assertEquals(NAMES.size(), rows);
        assertTrue(nameIndexes.size() <= 4, "two bits are four values: " + nameIndexes);
    }

    @Test
    void aRandomizedNameIsStoredDifferentlyEachTime() throws Exception {
        run(patients -> {
            patients.add(new IndexedPatient(1, "Twin", "a@x.org", "111-11-1111"));
            patients.add(new IndexedPatient(2, "Twin", "b@x.org", "222-22-2222"));
        });
        try (Connection connection = dataSource().getConnection();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select name, name_index from " + TABLE + " order by id")) {
            assertTrue(result.next());
            byte[] first = result.getBytes(1);
            long firstIndex = result.getLong(2);
            assertTrue(result.next());
            assertFalse(java.util.Arrays.equals(first, result.getBytes(1)), "a randomized name repeated");
            assertEquals(firstIndex, result.getLong(2), "an index is the same for the same value");
        }
    }

    @Test
    void aDeterministicAttributeIsFoundByFind() {
        everyone();
        IndexedPatient found = read(patients -> patients.bySsn("007-07-0049")).orElseThrow();
        assertEquals(8L, found.id());
        assertEquals("Mey", found.name());
        assertTrue(read(patients -> patients.bySsn("999-99-9999")).isEmpty());
        assertTrue(read(patients -> patients.bySsn("007-07-004")).isEmpty(), "equality, not a prefix");
        assertEquals(List.of(1L, 3L, 40L), ids(read(patients -> patients.bySsns(
                List.of("039-39-0273", "000-00-0000", "002-02-0014", "nobody")))));
    }

    @Test
    void theUniqueConstraintHoldsOnTheCiphertext() {
        everyone();
        assertThrows(RuntimeException.class, () -> run(patients -> patients.add(
                new IndexedPatient(100, "Doppelt", "d@x.org", "000-00-0000"))),
                "the same SSN went in twice");
        assertEquals(NAMES.size(), read(Patients::all).size(), "and the failed insert was rolled back");
        run(patients -> patients.add(new IndexedPatient(100, "Einmal", "e@x.org", "100-00-0000")));
        assertEquals(NAMES.size() + 1, read(Patients::all).size());
    }

    @Test
    void aBlindIndexSearchKeepsExactlyTheMatches() {
        everyone();
        int candidates = 0;
        int matches = 0;
        for (String wanted : NAMES) {
            List<IndexedPatient> found = read(patients -> IndexedPatient.NAME.find(wanted,
                    patients::byNameIndex, IndexedPatient::name));
            assertEquals(expectedByName(wanted), ids(found), "searching for " + wanted);
            for (IndexedPatient patient : found) {
                assertEquals(firstThree(wanted), firstThree(patient.name()));
            }
            candidates += read(patients -> patients.byNameIndex(IndexedPatient.NAME.searchTerms(wanted))).size();
            matches += found.size();
        }
        // Forty names, more than four distinct prefixes, four index values:
        // some prefixes share one, and the query returns their rows as well.
        assertTrue(candidates > matches, candidates + " candidates, " + matches + " matches");
    }

    @Test
    void searchesByPrefixAndCase() {
        everyone();
        assertEquals(List.of(1L, 3L), ids(read(patients -> IndexedPatient.NAME.find("mül",
                patients::byNameIndex, IndexedPatient::name))));
        assertEquals(List.of(2L), ids(read(patients -> IndexedPatient.NAME.find("MÜLLERIN",
                patients::byNameIndex, IndexedPatient::name))), "folding is ASCII's: Ü is not ü");
        assertEquals(List.of(9L, 10L, 11L, 12L, 13L, 20L, 28L, 29L), ids(read(patients ->
                IndexedPatient.NAME.find("sch", patients::byNameIndex, IndexedPatient::name))));
        assertEquals(List.of(37L, 38L), ids(read(patients -> IndexedPatient.NAME.find("AL",
                patients::byNameIndex, IndexedPatient::name))),
                "shorter than the prefix: the whole value - al-Rashid begins with al-, not al");
        assertEquals(List.of(39L), ids(read(patients -> IndexedPatient.NAME.find("AL-Bakri",
                patients::byNameIndex, IndexedPatient::name))));
        assertEquals(List.of(33L), ids(read(patients -> IndexedPatient.NAME.find("李小龍他",
                patients::byNameIndex, IndexedPatient::name))), "three code points, not three bytes");
        assertEquals(List.of(34L), ids(read(patients -> IndexedPatient.NAME.find("李小",
                patients::byNameIndex, IndexedPatient::name))));
        assertEquals(List.of(), ids(read(patients -> IndexedPatient.NAME.find("ана",
                patients::byNameIndex, IndexedPatient::name))), "Cyrillic is not folded");
        assertEquals(List.of(32L), ids(read(patients -> IndexedPatient.NAME.find("ørs",
                patients::byNameIndex, IndexedPatient::name))), "Ø is not folded either");
        assertEquals(List.of(35L, 36L), ids(read(patients -> IndexedPatient.NAME.find("Ана",
                patients::byNameIndex, IndexedPatient::name))));
        assertEquals(List.of(), ids(read(patients -> IndexedPatient.NAME.find("Xyz",
                patients::byNameIndex, IndexedPatient::name))));
    }

    @Test
    void anEmailIsFoundWhateverItsCase() {
        everyone();
        for (String spelling : List.of("person.17@example.org", "PERSON.17@EXAMPLE.ORG", "Person.17@Example.ORG")) {
            assertEquals(List.of(18L), ids(read(patients -> IndexedPatient.EMAIL.find(spelling,
                    patients::byEmailIndex, IndexedPatient::email))), spelling);
        }
        assertEquals(List.of(), ids(read(patients -> IndexedPatient.EMAIL.find("person.17@example.or",
                patients::byEmailIndex, IndexedPatient::email))));
        assertEquals(List.of(), ids(read(patients -> IndexedPatient.EMAIL.find("person.170@example.org",
                patients::byEmailIndex, IndexedPatient::email))));
    }

    @Test
    void anUpdateMovesTheIndex() {
        everyone();
        IndexedPatient koch = read(patients -> patients.byId(23L)).orElseThrow();
        koch.name("Kochanowski");
        koch.email("New.Address@Example.ORG");
        run(patients -> patients.update(koch));
        assertEquals("Kochanowski", read(patients -> patients.byId(23L)).orElseThrow().name());
        assertEquals(List.of(23L), ids(read(patients -> IndexedPatient.NAME.find("koc",
                patients::byNameIndex, IndexedPatient::name))));
        assertEquals(List.of(23L), ids(read(patients -> IndexedPatient.EMAIL.find("new.address@example.org",
                patients::byEmailIndex, IndexedPatient::email))));
        assertEquals(List.of(), ids(read(patients -> IndexedPatient.EMAIL.find("person.22@example.org",
                patients::byEmailIndex, IndexedPatient::email))), "the old address is gone");
    }

    @Test
    void aRemovedRowIsNotFound() {
        everyone();
        IndexedPatient wolf = read(patients -> patients.byId(26L)).orElseThrow();
        run(patients -> patients.remove(wolf));
        assertEquals(List.of(27L), ids(read(patients -> IndexedPatient.NAME.find("wol",
                patients::byNameIndex, IndexedPatient::name))));
        assertTrue(read(patients -> patients.bySsn("025-25-0175")).isEmpty());
        assertEquals(NAMES.size() - 1, read(Patients::all).size());
    }

    @Test
    void nullsHaveNoIndexAndAreNotCandidates() throws Exception {
        everyone();
        run(patients -> patients.add(new IndexedPatient(50, null, null, null)));
        IndexedPatient nobody = read(patients -> patients.byId(50L)).orElseThrow();
        assertNull(nobody.name());
        assertNull(nobody.email());
        assertNull(nobody.ssn());
        assertNull(nobody.nameIndex());
        assertEquals(List.of(50L), ids(read(Patients::withoutName)));
        try (Connection connection = dataSource().getConnection();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "select name, name_index, email_index, ssn from " + TABLE + " where id = 50")) {
            assertTrue(result.next());
            assertNull(result.getBytes(1));
            result.getLong(2);
            assertTrue(result.wasNull(), "a NULL name has a NULL index");
            result.getLong(3);
            assertTrue(result.wasNull());
            assertNull(result.getBytes(4));
        }
        for (String wanted : NAMES) {
            assertFalse(ids(read(patients -> IndexedPatient.NAME.find(wanted, patients::byNameIndex,
                    IndexedPatient::name))).contains(50L), wanted);
        }
        assertThrows(IllegalArgumentException.class, () -> IndexedPatient.NAME.searchTerms(null));
    }

    @Test
    void aRotationFindsRowsUnderEitherKey() throws Exception {
        everyone();
        long oldTerm = IndexedPatient.NAME.term("Wagner");
        close();
        FieldKeys old = keys;
        keys = ring(1, 2);
        FieldKeys.install(keys);
        old.close();
        open("none");

        run(patients -> patients.add(new IndexedPatient(60, "Wagenknecht", "w@x.org", "600-60-6000")));
        IndexedPatient added = read(patients -> patients.byId(60L)).orElseThrow();
        assertEquals(IndexedPatient.NAME.term("Wagenknecht"), added.nameIndex());
        List<Long> terms = IndexedPatient.NAME.searchTerms("Wag");
        assertEquals(oldTerm, (long) terms.get(terms.size() - 1), "the old key's term is searched too");

        assertEquals(List.of(17L, 18L, 60L), ids(read(patients -> IndexedPatient.NAME.find("wag",
                patients::byNameIndex, IndexedPatient::name))), "old rows and the new one");
        assertEquals("Wagner", read(patients -> patients.byId(17L)).orElseThrow().name(),
                "an old row is still read");
        assertTrue(read(patients -> patients.bySsn("600-60-6000")).isPresent(), "a new SSN under the primary");

        // Rewrite every row: read under either key, written - ciphertext and
        // index - under the primary. Then the old key can go.
        for (IndexedPatient patient : read(Patients::all)) {
            patient.name(patient.name());
            patient.email(patient.email());
            run(patients -> patients.update(patient));
        }
        IndexedPatient wagner = read(patients -> patients.byId(17L)).orElseThrow();
        assertEquals(IndexedPatient.NAME.term("Wagner"), wagner.nameIndex(), "reindexed under the primary");
        assertEquals((long) IndexedPatient.NAME.searchTerms("Wagner").get(0), wagner.nameIndex());
        close();
        FieldKeys both = keys;
        keys = ring(2);
        FieldKeys.install(keys);
        both.close();
        open("none");
        assertEquals(List.of(17L, 18L, 60L), ids(read(patients -> IndexedPatient.NAME.find("wag",
                patients::byNameIndex, IndexedPatient::name))), "after the old key retired");
    }

    @Test
    void manyRowsAtOnce() {
        List<IndexedPatient> many = new ArrayList<>();
        for (int i = 0; i < 300; i++) {
            many.add(new IndexedPatient(1000 + i, (i % 3 == 0 ? "Bulk" : "Other") + i,
                    "bulk" + i + "@x.org", String.format(Locale.ROOT, "9%02d-%02d-%04d", i % 100, i / 100, i)));
        }
        run(patients -> patients.addAll(many));
        assertEquals(100, read(patients -> IndexedPatient.NAME.find("BUL", patients::byNameIndex,
                IndexedPatient::name)).size());
        assertEquals(List.of(1123L), ids(read(patients -> IndexedPatient.EMAIL.find("BULK123@X.ORG",
                patients::byEmailIndex, IndexedPatient::email))));
        assertEquals(300, read(Patients::all).size());
    }
}
