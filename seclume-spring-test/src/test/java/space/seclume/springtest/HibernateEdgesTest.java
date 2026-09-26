package space.seclume.springtest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.hibernate.Session;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Hibernate's edges: JSON, LOBs as values and as streams, {@code @Formula},
 * and bulk HQL - on all four.
 *
 * <p>Each of these reaches a part of the driver the ordinary entity tests do
 * not. JSON is a type the four servers spell four ways. A {@code Blob} written
 * from a stream goes through {@code setBinaryStream} with a length, and read
 * back through {@code getBinaryStream} - on PostgreSQL through the large-object
 * API. A formula is text Hibernate splices into the select list and the where
 * clause. A bulk update or delete returns the server's own count, which
 * Spring Data hands to the caller.
 */
abstract class HibernateEdgesTest {

    @Autowired
    private NoteRepository notes;

    @Autowired
    private PlatformTransactionManager transactions;

    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entities;

    private TransactionTemplate tx;

    @BeforeEach
    void empty() {
        tx = new TransactionTemplate(transactions);
        notes.deleteAllInBatch();
    }

    /** A nested map in a JSON column, and the same map back. */
    @Test
    void aJsonColumnHoldsANestedMap() {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("lang", "de");
        attributes.put("stars", 4);
        attributes.put("tags", List.of("a", "b"));
        attributes.put("author", Map.of("name", "Ada", "active", true));
        attributes.put("umlaut", "Grüße, 東京");

        Long id = tx.execute(status -> {
            Note note = new Note("json", 1);
            note.setAttributes(attributes);
            return notes.save(note).getId();
        });
        Map<String, Object> back = tx.execute(status -> {
            entities.clear();
            return notes.findById(id).orElseThrow().getAttributes();
        });
        assertEquals("de", back.get("lang"));
        assertEquals(4, ((Number) back.get("stars")).intValue());
        assertEquals(List.of("a", "b"), back.get("tags"));
        assertEquals(Map.of("name", "Ada", "active", true), back.get("author"));
        assertEquals("Grüße, 東京", back.get("umlaut"));
    }

    /** {@code @Lob String} and {@code @Lob byte[]} - values, well past a page. */
    @Test
    void lobValuesSurviveTheRoundTrip() {
        // Latin-1 only: SQL Server maps a @Lob String to varchar(max), whose code
        // page has no CJK - a property of the column, not of the driver.
        String body = "Zeile mit Umlauten äöü\n".repeat(30_000);   // ~0.7 MB of text
        byte[] data = new byte[700_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 31 + 7);
        }
        Long id = tx.execute(status -> {
            Note note = new Note("lobs", 2);
            note.setBody(body);
            note.setData(data);
            return notes.save(note).getId();
        });
        tx.executeWithoutResult(status -> {
            entities.clear();
            Note back = notes.findById(id).orElseThrow();
            assertEquals(body, back.getBody());
            assertArrayEquals(data, back.getData());
        });
    }

    /**
     * {@code Clob} and {@code Blob} written from a stream and read back as
     * one - the path for content too large to hold as a value.
     */
    @Test
    void streamedLobsAreWrittenAndReadAsStreams() throws Exception {
        int size = 3 * 1024 * 1024;
        byte[] picture = new byte[size];
        new java.util.Random(23).nextBytes(picture);
        String script = "select 1 from dual; -- ÄÖÜ\n".repeat(40_000);

        Long id = tx.execute(status -> {
            Session session = entities.unwrap(Session.class);
            Note note = new Note("streams", 3);
            note.setPicture(session.getLobHelper().createBlob(
                    new ByteArrayInputStream(picture), picture.length));
            note.setScript(session.getLobHelper().createClob(
                    new StringReader(script), script.length()));
            return notes.save(note).getId();
        });

        byte[][] digests = tx.execute(status -> {
            entities.clear();
            Note back = notes.findById(id).orElseThrow();
            try (InputStream in = back.getPicture().getBinaryStream();
                 Reader reader = back.getScript().getCharacterStream()) {
                assertEquals(size, back.getPicture().length());
                StringBuilder text = new StringBuilder();
                char[] chunk = new char[8192];
                for (int n; (n = reader.read(chunk)) > 0; ) {
                    text.append(chunk, 0, n);
                }
                assertEquals(script, text.toString());
                return new byte[][] {sha(in.readAllBytes()), sha(picture)};
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
        assertArrayEquals(digests[1], digests[0], "the picture came back different");
    }

    /** The formula in the select list and in a where clause. */
    @Test
    void aFormulaIsReadAndFilteredOn() {
        tx.executeWithoutResult(status -> {
            notes.save(new Note("f-short", 3));
            notes.save(new Note("f-long", 30));
        });
        tx.executeWithoutResult(status -> {
            entities.clear();
            List<Note> long_ = notes.findByDoubledAbove(10);
            assertEquals(1, long_.size());
            assertEquals("f-long", long_.get(0).getTitle());
            assertEquals(60, long_.get(0).getDoubled());
        });
    }

    /** Bulk update and delete: the server's counts, and the rows really changed. */
    @Test
    void bulkHqlReturnsTheServersCounts() {
        tx.executeWithoutResult(status -> {
            for (int i = 0; i < 5; i++) {
                notes.save(new Note("bulk-" + i, i));
            }
            notes.save(new Note("other", 100));
        });
        int updated = tx.execute(status -> notes.addWords(10, "bulk-%"));
        assertEquals(5, updated);
        int deleted = tx.execute(status -> notes.deleteShorterThan(12));
        assertEquals(2, deleted, "words 10 and 11 after the update");
        tx.executeWithoutResult(status -> {
            entities.clear();
            assertEquals(4, notes.count());
            assertNotNull(notes.findAll().stream()
                    .filter(note -> note.getWords() == 14).findFirst().orElse(null));
        });
    }

    private static byte[] sha(byte[] bytes) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(bytes);
    }
}
