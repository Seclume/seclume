package space.seclume.mongodb.driver;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.bson.Document;
import org.bson.types.Binary;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldEncryptionException;
import space.seclume.field.FieldKeys;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.tck.TestHosts;

/**
 * Field encryption in MongoDB documents, against the real server: the
 * fields are BSON binary of subtype 0x80 holding ciphertext only, a
 * deterministic field is found by {@link EncryptedFields#eq} - also while a
 * rotation is under way - and values read back into native memory.
 */
class LocalEncryptedFieldsTest {

    private static final String TOKEN = "zl-mongo-field-token-0e9a";
    private static String url;

    @BeforeAll
    static void needsTheFixture() {
        String host = System.getProperty("seclume.mongo.host", TestHosts.database());
        int port = Integer.getInteger("seclume.mongo.port", 27017);
        Path password = find(".local-mongo-password");
        Path ca = find(".local-mongo-ca.pem");
        assumeTrue(password != null && ca != null, "no MongoDB fixture files");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(host, port), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no MongoDB on " + host + ":" + port);
        }
        url = "mongodb://seclume_test@" + host + ":" + port + "/?authSource=admin&provider=file"
                + "&path=" + password.toString().replace('\\', '/')
                + "&tlsRootCert=" + ca.toString().replace('\\', '/');
    }

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static SecretProvider key(byte fill) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                target.asSlice(0, 32).fill(fill);
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        };
    }

    private static MemorySegment text(String value) {
        return MemorySegment.ofArray(value.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void fieldsAreCiphertextOnTheServerAndFoundByEquality() {
        try (MongoClient client = SeclumeMongoClients.create(url);
             FieldKeys before = FieldKeys.builder().key(1, key((byte) 1)).build();
             SecretScope out = SecretScope.allocate(64)) {
            MongoCollection<Document> patients = client.getDatabase("seclume_test")
                    .getCollection("zl_fields_" + new ObjectId().toHexString());
            try {
                EncryptedColumn token = before.column("patients.token", Mode.RANDOMIZED);
                EncryptedColumn ssn = before.column("patients.ssn", Mode.DETERMINISTIC);
                for (int id = 1; id <= 3; id++) {
                    patients.insertOne(new Document("_id", id)
                            .append("token", EncryptedFields.encrypt(token, text(TOKEN)))
                            .append("ssn", EncryptedFields.encrypt(ssn, text("ssn-" + id))));
                }
                Document raw = patients.find(new Document("_id", 2)).first();
                Binary stored = (Binary) raw.get("token");
                assertEquals(EncryptedFields.SUBTYPE, stored.getType());
                assertEquals(TOKEN.length() + EncryptedColumn.OVERHEAD, stored.getData().length);
                assertFalse(raw.toJson().contains("zl-mongo"), "the token is on the server");

                Document found = patients.find(EncryptedFields.eq("ssn", ssn, text("ssn-3")))
                        .first();
                assertEquals(3, found.getInteger("_id"));
                out.length(EncryptedFields.readInto(found, "token", token, out.segment()));
                assertArrayEquals(TOKEN.getBytes(StandardCharsets.US_ASCII),
                        out.secret().toArray(ValueLayout.JAVA_BYTE));
                assertEquals(-1, EncryptedFields.readInto(found, "absent", token,
                        out.segment()));

                // A new primary key: old documents are still found.
                try (FieldKeys during = FieldKeys.builder().key(1, key((byte) 1))
                        .key(2, key((byte) 2)).build()) {
                    EncryptedColumn ssn2 = during.column("patients.ssn", Mode.DETERMINISTIC);
                    patients.insertOne(new Document("_id", 4)
                            .append("ssn", EncryptedFields.encrypt(ssn2, text("ssn-4"))));
                    assertEquals(1, patients.find(EncryptedFields.eq("ssn", ssn2,
                            text("ssn-1"))).into(new java.util.ArrayList<>()).size());
                    assertEquals(4, patients.find(EncryptedFields.eq("ssn", ssn2,
                            text("ssn-4"))).first().getInteger("_id"));
                }

                patients.insertOne(new Document("_id", 9).append("token", "plain text"));
                Document wrong = patients.find(new Document("_id", 9)).first();
                assertThrows(FieldEncryptionException.class,
                        () -> EncryptedFields.readInto(wrong, "token", token, out.segment()));
            } finally {
                patients.drop();
            }
        }
    }
}
