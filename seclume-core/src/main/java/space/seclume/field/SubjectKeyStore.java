package space.seclume.field;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import javax.sql.DataSource;

/**
 * Where {@link SubjectKeys} keeps each subject's data key - wrapped, never in
 * the clear: encrypted under the ring, bound to the subject's name.
 *
 * <p>Deleting an entry is the shredding: without it the subject's values are
 * noise. Whatever keeps a copy of the entries - a backup, a replica, a dump -
 * keeps the subject readable for as long as the ring's key that wrapped it
 * exists; see {@link SubjectKeys} on how rotating that key ends it.
 */
public interface SubjectKeyStore {

    /** The subject's wrapped key, or {@code null} when it has none - never had, or was shredded. */
    byte[] load(String subject);

    /**
     * Stores a wrapped key for a subject that has none. Returns {@code false}
     * when another writer was first - then {@link #load} has theirs, and theirs
     * is the one to use.
     */
    boolean insert(String subject, byte[] wrapped);

    /** Removes the subject's key; returns whether there was one. */
    boolean delete(String subject);

    /** In memory - for tests, and nothing else: a restart shreds everyone. */
    static SubjectKeyStore inMemory() {
        Map<String, byte[]> keys = new ConcurrentHashMap<>();
        return new SubjectKeyStore() {
            @Override
            public byte[] load(String subject) {
                byte[] wrapped = keys.get(subject);
                return wrapped == null ? null : wrapped.clone();
            }

            @Override
            public boolean insert(String subject, byte[] wrapped) {
                return keys.putIfAbsent(subject, wrapped.clone()) == null;
            }

            @Override
            public boolean delete(String subject) {
                return keys.remove(subject) != null;
            }
        };
    }

    /**
     * A table: {@code subject} (a string, the primary key) and {@code wrapped}
     * (variable-length binary, 128 bytes is enough), as in
     *
     * <pre>
     *   create table subject_keys (subject varchar(200) primary key, wrapped bytea)        -- PostgreSQL
     *   create table subject_keys (subject varchar(200) primary key, wrapped varbinary(128)) -- MySQL, SQL Server
     *   create table subject_keys (subject varchar2(200) primary key, wrapped raw(128))    -- Oracle
     * </pre>
     *
     * Each operation is its own short transaction on a connection of its own.
     */
    static SubjectKeyStore jdbc(DataSource dataSource, String table) {
        if (table == null || !Pattern.matches("[A-Za-z_][A-Za-z0-9_$]*(\\.[A-Za-z_][A-Za-z0-9_$]*)?", table)) {
            throw new IllegalArgumentException("the key table is a plain SQL identifier, not " + table);
        }
        return new SubjectKeyStore() {
            @Override
            public byte[] load(String subject) {
                try (Connection connection = dataSource.getConnection();
                     PreparedStatement select = connection.prepareStatement( // nosemgrep - the table name is checked above to be a plain identifier
                             "select wrapped from " + table + " where subject = ?")) {
                    select.setString(1, subject);
                    try (ResultSet rows = select.executeQuery()) {
                        return rows.next() ? rows.getBytes(1) : null; // seclume-allow: a wrapped key, ciphertext
                    }
                } catch (SQLException e) {
                    throw new FieldEncryptionException("the subject key table " + table
                            + " cannot be read: " + e.getMessage(), e);
                }
            }

            @Override
            public boolean insert(String subject, byte[] wrapped) {
                try (Connection connection = dataSource.getConnection();
                     PreparedStatement insert = connection.prepareStatement( // nosemgrep - the table name is checked above to be a plain identifier
                             "insert into " + table + " (subject, wrapped) values (?, ?)")) {
                    insert.setString(1, subject);
                    insert.setBytes(2, wrapped);
                    return insert.executeUpdate() == 1;
                } catch (SQLException e) {
                    // Someone else was first, and the primary key said so - by SQLSTATE 23xxx,
                    // or, from a driver that does not set it, by the key now being there.
                    String state = e.getSQLState();
                    if (state != null && state.startsWith("23") || load(subject) != null) {
                        return false;
                    }
                    throw new FieldEncryptionException("the subject key table " + table
                            + " cannot be written: " + e.getMessage(), e);
                }
            }

            @Override
            public boolean delete(String subject) {
                try (Connection connection = dataSource.getConnection();
                     PreparedStatement delete = connection.prepareStatement( // nosemgrep - the table name is checked above to be a plain identifier
                             "delete from " + table + " where subject = ?")) {
                    delete.setString(1, subject);
                    return delete.executeUpdate() > 0;
                } catch (SQLException e) {
                    throw new FieldEncryptionException("the subject key table " + table
                            + " cannot be written: " + e.getMessage(), e);
                }
            }
        };
    }
}
