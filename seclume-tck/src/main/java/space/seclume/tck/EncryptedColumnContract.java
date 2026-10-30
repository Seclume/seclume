package space.seclume.tck;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
// seclume-allow: test code: the control's String, the test's own key file, or ciphertext
import java.util.Base64;
// seclume-allow: test code: the control's String, the test's own key file, or ciphertext
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldKeys;
import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Field encryption against a real database, written once and run by every
 * driver ({@code LocalEncryptedColumnTest} in each): the server holds nothing
 * but ciphertext, a deterministic column is searched through a unique index, a
 * rotation runs while the table is in use, a value copied into another row is
 * refused, and a heap dump of a process that read a value holds neither the
 * value nor the key - with the control that finds the value when it is read as
 * a {@code String}.
 *
 * <p>A driver gives its URL and its binary type; the rest is the same SQL on
 * all four. The keys come from files through {@link FileSecretProvider}, as
 * they would in production from Vault.
 */
public abstract class EncryptedColumnContract {

    private static final String TABLE = "zl_encrypted";
    /** Long and unmistakable, so that a hit in a dump is a hit. */
    private static final String STORED = "zl-field-secret-91c4e7a0b25d6f83-zl";

    @TempDir
    protected Path directory;

    private Path key1;
    private Path key2;

    /** The JDBC URL, with the login; the subclass skips the class when there is no server. */
    protected abstract String url();

    /** A variable-length binary column of {@code length} bytes: bytea, varbinary(n), raw(n). */
    protected abstract String binary(int length);

    protected Connection connect() throws SQLException {
        return DriverManager.getConnection(url());
    }

    @BeforeEach
    void aTableAndTwoKeys() throws Exception {
        Random random = new Random();
        key1 = keyFile("key1", random);
        key2 = keyFile("key2", random);
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            drop(statement);
            statement.execute("create table " + TABLE + " (id int primary key, secret "
                    + binary(300) + ", ssn " + binary(300) + ", note " + binary(1000) + ")");
            statement.execute("create unique index zl_encrypted_ssn on " + TABLE + " (ssn)");
        }
    }

    @AfterEach
    void tidyUp() throws Exception {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            drop(statement);
        }
    }

    private static void drop(Statement statement) {
        try {
            statement.execute("drop table " + TABLE);
        } catch (SQLException itWasNotThere) {
            // the first run, or the last one tidied up
        }
    }

    private Path keyFile(String name, Random random) throws Exception {
        byte[] key = new byte[32];
        random.nextBytes(key);
        // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
        return Files.writeString(directory.resolve(name), Base64.getEncoder().encodeToString(key)
                + "\n");
    }

    private static SecretProvider file(Path key) {
        return new FileSecretProvider(key, 128);
    }

    private FieldKeys ring1() {
        return FieldKeys.builder().key(1, file(key1)).build();
    }

    private FieldKeys ring12() {
        return FieldKeys.builder().key(1, file(key1)).key(2, file(key2)).primary(2).build();
    }

    private FieldKeys ring2() {
        return FieldKeys.builder().key(2, file(key2)).build();
    }

    private static MemorySegment bytes(String text) {
        // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
        return MemorySegment.ofArray(text.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] context(int id) {
        // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
        return Integer.toString(id).getBytes(StandardCharsets.US_ASCII);
    }

    private void insert(Connection connection, EncryptedColumn secret, EncryptedColumn ssn,
            int id, String secretValue, String ssnValue) throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement("insert into " + TABLE
                + " (id, secret, ssn) values (?, ?, ?)")) {
            insert.setInt(1, id);
            secret.set(insert, 2, secretValue == null ? null : bytes(secretValue), context(id));
            ssn.set(insert, 3, ssnValue == null ? null : bytes(ssnValue));
            assertEquals(1, insert.executeUpdate());
        }
    }

    private static String readSecret(Connection connection, EncryptedColumn secret, int id)
            throws SQLException {
        try (PreparedStatement select = connection.prepareStatement(
                "select secret from " + TABLE + " where id = ?")) {
            select.setInt(1, id);
            try (ResultSet rows = select.executeQuery();
                 SecretScope out = SecretScope.allocate(512)) {
                assertTrue(rows.next(), "no row " + id);
                int length = secret.readInto(rows, 1, context(id), out.segment());
                if (length < 0) {
                    return null;
                }
                out.length(length);
                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                return new String(out.secret().toArray(ValueLayout.JAVA_BYTE),
                        StandardCharsets.UTF_8);
            }
        }
    }

    private static List<Integer> find(Connection connection, EncryptedColumn ssn, String value)
            throws SQLException {
        List<byte[]> terms = ssn.searchTerms(bytes(value));
        StringBuilder sql = new StringBuilder("select id from " + TABLE + " where ssn in (");
        for (int i = 0; i < terms.size(); i++) {
            sql.append(i == 0 ? "?" : ", ?");
        }
        List<Integer> ids = new ArrayList<>();
        try (PreparedStatement select = connection.prepareStatement(sql + ") order by id")) {
            for (int i = 0; i < terms.size(); i++) {
                select.setBytes(i + 1, terms.get(i));
            }
            try (ResultSet rows = select.executeQuery()) {
                while (rows.next()) {
                    ids.add(rows.getInt(1));
                }
            }
        }
        return ids;
    }

    // ------------------------------------------------------------------ tests

    @Test
    void theDatabaseHoldsOnlyCiphertext() throws Exception {
        try (FieldKeys keys = ring1();
             Connection connection = connect()) {
            EncryptedColumn secret = keys.column("zl.secret", Mode.RANDOMIZED);
            EncryptedColumn ssn = keys.column("zl.ssn", Mode.DETERMINISTIC);
            insert(connection, secret, ssn, 1, STORED, "078-05-1120");
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "select secret, ssn from " + TABLE + " where id = 1")) {
                assertTrue(rows.next());
                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                byte[] stored = rows.getBytes(1);
                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                byte[] storedSsn = rows.getBytes(2);
                assertEquals(STORED.length() + EncryptedColumn.OVERHEAD, stored.length);
                assertEquals(11 + EncryptedColumn.OVERHEAD, storedSsn.length);
                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                String hex = HexFormat.of().formatHex(stored) + HexFormat.of().formatHex(storedSsn);
                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                assertFalse(hex.contains(HexFormat.of().formatHex(
                        // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                        STORED.getBytes(StandardCharsets.UTF_8)).substring(0, 16)),
                        "the plaintext is in the database");
                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                assertFalse(new String(stored, StandardCharsets.ISO_8859_1).contains("zl-field"));
                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                assertFalse(new String(storedSsn, StandardCharsets.ISO_8859_1).contains("078"));
                assertEquals(1, stored[0], "format version");
            }
            assertEquals(STORED, readSecret(connection, secret, 1));
        }
    }

    @Test
    void nullStaysNullAndTextRoundTrips() throws Exception {
        try (FieldKeys keys = ring1();
             Connection connection = connect()) {
            EncryptedColumn secret = keys.column("zl.secret", Mode.RANDOMIZED);
            EncryptedColumn ssn = keys.column("zl.ssn", Mode.DETERMINISTIC);
            EncryptedColumn note = keys.column("zl.note", Mode.RANDOMIZED);
            insert(connection, secret, ssn, 1, null, null);
            assertNull(readSecret(connection, secret, 1));
            String text = "Grüße, 東京, Ωμέγα - and a line\nbreak" + "x".repeat(400);
            try (PreparedStatement update = connection.prepareStatement(
                    "update " + TABLE + " set note = ? where id = 1")) {
                note.setString(update, 1, text);
                assertEquals(1, update.executeUpdate());
            }
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "select note, secret from " + TABLE + " where id = 1")) {
                assertTrue(rows.next());
                assertEquals(text, note.getString(rows, 1));
                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                assertEquals(text.getBytes(StandardCharsets.UTF_8).length, note.length(rows, 1));
                assertNull(secret.getString(rows, 2));
                assertEquals(-1, secret.length(rows, 2));
            }
        }
    }

    @Test
    void aDeterministicColumnIsSearchedThroughAUniqueIndex() throws Exception {
        try (FieldKeys keys = ring1();
             Connection connection = connect()) {
            EncryptedColumn secret = keys.column("zl.secret", Mode.RANDOMIZED);
            EncryptedColumn ssn = keys.column("zl.ssn", Mode.DETERMINISTIC);
            insert(connection, secret, ssn, 1, "a", "111-11-1111");
            insert(connection, secret, ssn, 2, "b", "222-22-2222");
            insert(connection, secret, ssn, 3, "c", "333-33-3333");
            assertEquals(List.of(2), find(connection, ssn, "222-22-2222"));
            assertEquals(List.of(), find(connection, ssn, "444-44-4444"));
            assertThrows(SQLException.class,
                    () -> insert(connection, secret, ssn, 4, "d", "111-11-1111"),
                    "the unique index lets the same number in twice");
        }
    }

    @Test
    void aRotationRunsWhileTheTableIsInUse() throws Exception {
        try (Connection connection = connect()) {
            try (FieldKeys before = ring1()) {
                for (int id = 1; id <= 5; id++) {
                    insert(connection, before.column("zl.secret", Mode.RANDOMIZED),
                            before.column("zl.ssn", Mode.DETERMINISTIC), id, "secret " + id,
                            "ssn " + id);
                }
            }
            try (FieldKeys during = ring12()) {
                EncryptedColumn secret = during.column("zl.secret", Mode.RANDOMIZED);
                EncryptedColumn ssn = during.column("zl.ssn", Mode.DETERMINISTIC);
                // New rows under key 2 next to old ones under key 1; both found and read.
                insert(connection, secret, ssn, 6, "secret 6", "ssn 6");
                assertEquals(List.of(3), find(connection, ssn, "ssn 3"));
                assertEquals(List.of(6), find(connection, ssn, "ssn 6"));
                assertEquals("secret 2", readSecret(connection, secret, 2));

                // Moving every row over, the plaintext in native memory only.
                int moved = 0;
                try (Statement statement = connection.createStatement();
                     ResultSet rows = statement.executeQuery(
                             "select id, secret, ssn from " + TABLE + " order by id");
                     PreparedStatement update = connection.prepareStatement(
                             "update " + TABLE + " set secret = ?, ssn = ? where id = ?")) {
                    List<Object[]> pending = new ArrayList<>();
                    while (rows.next()) {
                        // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                        pending.add(new Object[] {rows.getInt(1), rows.getBytes(2),
                                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                                rows.getBytes(3)});
                    }
                    for (Object[] row : pending) {
                        int id = (Integer) row[0];
                        byte[] oldSecret = (byte[]) row[1];
                        byte[] oldSsn = (byte[]) row[2];
                        if (secret.needsReencryption(oldSecret)
                                || ssn.needsReencryption(oldSsn)) {
                            update.setBytes(1, secret.reencrypt(oldSecret, context(id)));
                            update.setBytes(2, ssn.reencrypt(oldSsn));
                            update.setInt(3, id);
                            assertEquals(1, update.executeUpdate());
                            moved++;
                        }
                    }
                }
                assertEquals(5, moved);
            }
            // Key 1 can go: everything is under key 2.
            try (FieldKeys after = ring2()) {
                EncryptedColumn secret = after.column("zl.secret", Mode.RANDOMIZED);
                EncryptedColumn ssn = after.column("zl.ssn", Mode.DETERMINISTIC);
                for (int id = 1; id <= 6; id++) {
                    assertEquals("secret " + id, readSecret(connection, secret, id));
                    assertEquals(List.of(id), find(connection, ssn, "ssn " + id));
                }
            }
        }
    }

    @Test
    void aValueCopiedIntoAnotherRowIsRefusedThere() throws Exception {
        try (FieldKeys keys = ring1();
             Connection connection = connect()) {
            EncryptedColumn secret = keys.column("zl.secret", Mode.RANDOMIZED);
            EncryptedColumn ssn = keys.column("zl.ssn", Mode.DETERMINISTIC);
            insert(connection, secret, ssn, 1, "alice's token", "1");
            insert(connection, secret, ssn, 2, "mallory's token", "2");
            byte[] alices;
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "select secret from " + TABLE + " where id = 1")) {
                assertTrue(rows.next());
                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                alices = rows.getBytes(1);
            }
            try (PreparedStatement update = connection.prepareStatement(
                    "update " + TABLE + " set secret = ? where id = 2")) {
                update.setBytes(1, alices);
                assertEquals(1, update.executeUpdate());
            }
            SQLException refused = assertThrows(SQLException.class,
                    () -> readSecret(connection, secret, 2));
            assertEquals("22000", refused.getSQLState());
            assertEquals("alice's token", readSecret(connection, secret, 1));
        }
    }

    @Test
    void aStoredValueTamperedWithIsRefused() throws Exception {
        try (FieldKeys keys = ring1();
             Connection connection = connect()) {
            EncryptedColumn secret = keys.column("zl.secret", Mode.RANDOMIZED);
            insert(connection, secret, keys.column("zl.ssn", Mode.DETERMINISTIC), 1, STORED, "1");
            byte[] stored;
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "select secret from " + TABLE + " where id = 1")) {
                assertTrue(rows.next());
                // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
                stored = rows.getBytes(1);
            }
            stored[stored.length / 2] ^= 0x20;
            try (PreparedStatement update = connection.prepareStatement(
                    "update " + TABLE + " set secret = ? where id = 1")) {
                update.setBytes(1, stored);
                update.executeUpdate();
            }
            assertEquals("22000", assertThrows(SQLException.class,
                    () -> readSecret(connection, secret, 1)).getSQLState());
        }
    }

    /**
     * The value and the keys are not in the heap of a process that read the
     * value into native memory - and the value is, when the same process
     * reads it as a {@code String}: a searcher that never finds anything
     * proves nothing.
     */
    @Test
    void neitherTheValueNorTheKeyIsInAHeapDump() throws Exception {
        try (FieldKeys keys = ring1();
             Connection connection = connect()) {
            insert(connection, keys.column("zl.secret", Mode.RANDOMIZED),
                    keys.column("zl.ssn", Mode.DETERMINISTIC), 1, STORED, "1");
        }
        // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
        String keyText = Files.readString(key1).trim();
        // seclume-allow: test code: the control's String, the test's own key file, or ciphertext
        byte[] keyBytes = Base64.getDecoder().decode(keyText);
        for (String mode : List.of("native", "string")) {
            Path dump = directory.resolve(mode + ".hprof");
            ChildJvm.Result result = ChildJvm.run(EncryptedColumnProbe.class,
                    List.of(url(), TABLE, key1.toString(), dump.toString(), mode), 180);
            assertEquals(0, result.exitCode(), "the probe failed:\n" + result.output());
            assertTrue(result.output().contains("read " + STORED.length() + " bytes"),
                    result.output());
            List<HeapDumpScanner.Finding> value = HeapDumpScanner.scan(dump, STORED);
            if (mode.equals("native")) {
                assertTrue(value.isEmpty(), "a value read into native memory is in the heap: "
                        + value);
            } else {
                assertFalse(value.isEmpty(), "the control: read as a String, the value has to "
                        + "be found, or the search proves nothing");
            }
            assertTrue(HeapDumpScanner.scan(dump, keyText).isEmpty(),
                    mode + ": the key's Base64 is in the heap");
            assertTrue(HeapDumpScanner.scanBytes(dump, keyBytes).isEmpty(),
                    mode + ": the key is in the heap");
            Files.delete(dump);
        }
    }
}
