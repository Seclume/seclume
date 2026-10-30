package space.seclume.frameworks;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.function.Consumer;

import javax.sql.DataSource;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.PersistenceConfiguration;
import jakarta.persistence.PersistenceException;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldKeys;
import space.seclume.field.Sealed;
import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.tck.ChildJvm;
import space.seclume.tck.HeapDumpScanner;

/**
 * seclume-jpa's converters in Hibernate, against a real database: the schema
 * Hibernate generates for encrypted attributes, values that reach the server
 * only as ciphertext, a JPQL query on a deterministic attribute and its unique
 * constraint, NULLs, a {@link Sealed} token opened into native memory, and a
 * heap dump of a process that loaded the entity - the sealed token is not in
 * it, the {@code String} attribute is (as documented: a String attribute is
 * kept from the database, not from the heap).
 *
 * <p>Hibernate is started through Jakarta Persistence 3.2's
 * {@link PersistenceConfiguration}, as any application without Spring would.
 * Isolated: the installed key ring is global.
 */
@Isolated
abstract class JpaFieldEncryptionCase {

    private static final Random RANDOM = new Random();
    private static final String TOKEN = "ghp_zlFieldToken0123456789abcdefABCDEF";
    private static final String NAME = "Zl-Patient-Name-7e41c9a2";

    @TempDir
    Path directory;

    private Path keyFile;
    private FieldKeys keys;
    private EntityManagerFactory factory;

    /** The shared pool for this server. */
    abstract DataSource dataSource() throws Exception;

    /** The JDBC URL of the same server, with its password file - for the child JVM. */
    abstract String url();

    static EntityManagerFactory factory(Object connection, String action) {
        PersistenceConfiguration configuration = new PersistenceConfiguration("zl-field")
                .managedClass(EncryptedPatient.class)
                .property(PersistenceConfiguration.SCHEMAGEN_DATABASE_ACTION, action);
        if (connection instanceof DataSource source) {
            configuration.property("hibernate.connection.datasource", source);
        } else {
            configuration.property(PersistenceConfiguration.JDBC_URL, connection);
        }
        return configuration.createEntityManagerFactory();
    }

    @BeforeEach
    void keysAndASchema() throws Exception {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        keyFile = Files.writeString(directory.resolve("field-key"),
                Base64.getEncoder().encodeToString(key));
        keys = FieldKeys.builder().key(1, new FileSecretProvider(keyFile, 128)).build();
        FieldKeys.install(keys);
        factory = factory(dataSource(), "drop-and-create");
    }

    @AfterEach
    void tidyUp() throws Exception {
        if (factory != null) {
            factory.close();
        }
        if (keys != null) {
            keys.close();
        }
        try (var connection = dataSource().getConnection();
             var statement = connection.createStatement()) {
            statement.execute("drop table zl_patient");
        } catch (java.sql.SQLException alreadyGone) {
            // the schema action may have dropped it
        }
    }

    private void inTransaction(Consumer<EntityManager> work) {
        EntityManager em = factory.createEntityManager();
        try {
            em.getTransaction().begin();
            work.accept(em);
            em.getTransaction().commit();
        } finally {
            if (em.getTransaction().isActive()) {
                em.getTransaction().rollback();
            }
            em.close();
        }
    }

    private Sealed sealedToken() {
        try (SecretScope token = SecretScope.allocate(64)) {
            byte[] bytes = TOKEN.getBytes(StandardCharsets.US_ASCII);
            java.lang.foreign.MemorySegment.copy(bytes, 0, token.segment(),
                    ValueLayout.JAVA_BYTE, 0, bytes.length);
            token.length(bytes.length);
            return keys.column("zl_patient.api_token", Mode.RANDOMIZED).seal(token.secret());
        }
    }

    private void three() {
        inTransaction(em -> {
            EncryptedPatient one = new EncryptedPatient(1, NAME, "078-05-1120");
            one.apiToken(sealedToken());
            one.scan(new byte[] {1, 2, 3, 0, (byte) 0xff});
            em.persist(one);
            em.persist(new EncryptedPatient(2, "Brigitte Ørsted", "219-09-9999"));
            em.persist(new EncryptedPatient(3, "李小龍", "457-55-5462"));
        });
    }

    @Test
    void attributesComeBackAsTheyWent() {
        three();
        EntityManager em = factory.createEntityManager();
        try {
            EncryptedPatient one = em.find(EncryptedPatient.class, 1L);
            assertEquals(NAME, one.name());
            assertEquals("078-05-1120", one.ssn());
            assertArrayEquals(new byte[] {1, 2, 3, 0, (byte) 0xff}, one.scan());
            assertEquals("李小龍", em.find(EncryptedPatient.class, 3L).name());
        } finally {
            em.close();
        }
    }

    @Test
    void theServerHoldsOnlyCiphertext() throws Exception {
        three();
        try (var connection = dataSource().getConnection();
             var statement = connection.createStatement();
             var rows = statement.executeQuery(
                     "select name, ssn, api_token, scan from zl_patient where id = 1")) {
            assertTrue(rows.next());
            byte[] name = rows.getBytes(1);
            byte[] ssn = rows.getBytes(2);
            byte[] token = rows.getBytes(3);
            byte[] scan = rows.getBytes(4);
            assertEquals(NAME.length() + EncryptedColumn.OVERHEAD, name.length);
            assertEquals(11 + EncryptedColumn.OVERHEAD, ssn.length);
            assertEquals(TOKEN.length() + EncryptedColumn.OVERHEAD, token.length);
            assertEquals(5 + EncryptedColumn.OVERHEAD, scan.length);
            String all = new String(name, StandardCharsets.ISO_8859_1)
                    + new String(ssn, StandardCharsets.ISO_8859_1)
                    + new String(token, StandardCharsets.ISO_8859_1);
            assertFalse(all.contains("Zl-Patient"), "the name is in the database");
            assertFalse(all.contains("078-05"), "the SSN is in the database");
            assertFalse(all.contains("ghp_"), "the token is in the database");
            assertEquals(1, name[0]);
            assertEquals(1, ssn[1], "the SSN is deterministic");
        }
    }

    @Test
    void aDeterministicAttributeIsQueriedAndUnique() {
        three();
        EntityManager em = factory.createEntityManager();
        try {
            List<EncryptedPatient> found = em.createQuery(
                    "select p from EncryptedPatient p where p.ssn = :ssn", EncryptedPatient.class)
                    .setParameter("ssn", "219-09-9999").getResultList();
            assertEquals(1, found.size());
            assertEquals(2L, found.get(0).id());
            assertEquals("Brigitte Ørsted", found.get(0).name());
            List<EncryptedPatient> two = em.createQuery(
                    "select p from EncryptedPatient p where p.ssn in :ssns order by p.id",
                    EncryptedPatient.class)
                    .setParameter("ssns", List.of("078-05-1120", "457-55-5462", "000-00-0000"))
                    .getResultList();
            assertEquals(List.of(1L, 3L), two.stream().map(EncryptedPatient::id).toList());
            assertTrue(em.createQuery("select p from EncryptedPatient p where p.ssn = :ssn",
                    EncryptedPatient.class).setParameter("ssn", "000-00-0000")
                    .getResultList().isEmpty());
        } finally {
            em.close();
        }
        assertThrows(PersistenceException.class, () -> inTransaction(dup -> dup.persist(
                new EncryptedPatient(4, "someone else", "078-05-1120"))),
                "the unique constraint let the same SSN in twice");
    }

    @Test
    void aSealedTokenIsOpenedIntoNativeMemory() {
        three();
        EntityManager em = factory.createEntityManager();
        try {
            EncryptedPatient one = em.find(EncryptedPatient.class, 1L);
            Sealed token = one.apiToken();
            assertNotNull(token);
            assertFalse(token.toString().contains("ghp_"), token.toString());
            try (SecretScope value = SecretScope.allocate(token.plaintextLength())) {
                value.length(keys.column("zl_patient.api_token", Mode.RANDOMIZED)
                        .open(token, value.segment()));
                assertArrayEquals(TOKEN.getBytes(StandardCharsets.US_ASCII),
                        value.secret().toArray(ValueLayout.JAVA_BYTE));
            }
            List<EncryptedPatient> byToken = em.createQuery(
                    "select p from EncryptedPatient p where p.apiToken = :token",
                    EncryptedPatient.class).setParameter("token", token).getResultList();
            assertEquals(1, byToken.size(), "a sealed value as a query parameter");
        } finally {
            em.close();
        }
    }

    @Test
    void nullsStayNull() {
        inTransaction(em -> em.persist(new EncryptedPatient(9, null, null)));
        EntityManager em = factory.createEntityManager();
        try {
            EncryptedPatient nine = em.find(EncryptedPatient.class, 9L);
            assertNull(nine.name());
            assertNull(nine.ssn());
            assertNull(nine.apiToken());
            assertNull(nine.scan());
        } finally {
            em.close();
        }
    }

    @Test
    void anUpdateIsEncryptedAgain() {
        three();
        inTransaction(em -> {
            EncryptedPatient two = em.find(EncryptedPatient.class, 2L);
            em.remove(two);
            em.flush();
            em.persist(new EncryptedPatient(2, "Brigitte Ørsted-Hansen", "219-09-9998"));
        });
        EntityManager em = factory.createEntityManager();
        try {
            assertEquals("Brigitte Ørsted-Hansen", em.find(EncryptedPatient.class, 2L).name());
            assertEquals(1, em.createQuery("select p from EncryptedPatient p where p.ssn = :s",
                    EncryptedPatient.class).setParameter("s", "219-09-9998")
                    .getResultList().size());
        } finally {
            em.close();
        }
    }

    /**
     * A child JVM loads patient 1 with Hibernate, opens the sealed token into
     * native memory and dumps its heap. The token and the key are not in it;
     * the name - a {@code String} attribute - is, which is the control and
     * the documented difference between the two.
     */
    @Test
    void aHeapDumpAfterLoadingHoldsNeitherTheTokenNorTheKey() throws Exception {
        three();
        Path dump = directory.resolve("jpa.hprof");
        ChildJvm.Result result = ChildJvm.run(JpaSealedProbe.class,
                List.of(url(), keyFile.toString(), dump.toString()), 300);
        assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
        assertTrue(result.output().contains("opened " + TOKEN.length() + " bytes"),
                result.output());
        assertTrue(HeapDumpScanner.scan(dump, TOKEN).isEmpty(),
                "the sealed token is in the heap of a process that opened it into native memory");
        assertFalse(HeapDumpScanner.scan(dump, NAME).isEmpty(),
                "the control: the String attribute has to be found, or the search proves nothing");
        String keyText = Files.readString(keyFile).trim();
        assertTrue(HeapDumpScanner.scan(dump, keyText).isEmpty(), "the key's Base64 is in the heap");
        assertTrue(HeapDumpScanner.scanBytes(dump, Base64.getDecoder().decode(keyText)).isEmpty(),
                "the key is in the heap");
    }
}
