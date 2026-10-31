package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.Result;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.EncryptedColumn.Mode;
import space.seclume.field.FieldKeys;
import space.seclume.r2dbc.LocalR2dbcFourDatabasesTest.Db;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Field encryption over R2DBC against the real databases: values bound with
 * {@link EncryptedValues} are ciphertext on the server, a deterministic
 * column is searched with its search term, and both read back into native
 * memory. The databases of {@link LocalR2dbcFourDatabasesTest}; in CI the
 * PostgreSQL job runs it against its TLS server.
 */
@org.junit.jupiter.api.parallel.Isolated
class LocalEncryptedR2dbcTest {

    private static final Duration WAIT = Duration.ofSeconds(60);
    private static final String TOKEN = "zl-r2dbc-field-token-7c21";

    static List<Db> databases() {
        return LocalR2dbcFourDatabasesTest.databases();
    }

    private static String binary(Db db) {
        return switch (db.protocol()) {
            case "postgresql" -> "bytea";
            case "oracle" -> "raw(200)";
            default -> "varbinary(200)";
        };
    }

    private static void run(ConnectionFactory factory, String sql) {
        Mono.usingWhen(factory.create(),
                c -> Flux.from(c.createStatement(sql).execute())
                        .concatMap(Result::getRowsUpdated).then(),
                Connection::close).block(WAIT);
    }

    private static FieldKeys ring() {
        return FieldKeys.builder().key(1, new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                target.asSlice(0, 32).fill((byte) 0x2a);
                return 32;
            }

            @Override
            public int maxSecretLength() {
                return 32;
            }
        }).build();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("databases")
    void valuesGoInEncryptedAndComeBackIntoNativeMemory(Db db) {
        ConnectionFactory factory = db.factory();
        String table = "zl_r2dbc_field_" + db.protocol();
        run(factory, String.format(db.drop(), table));
        run(factory, "create table " + table + " (id int primary key, token " + binary(db)
                + ", ssn " + binary(db) + ")");
        try (FieldKeys keys = ring();
             SecretScope out = SecretScope.allocate(64)) {
            EncryptedColumn token = keys.column(table + ".token", Mode.RANDOMIZED);
            EncryptedColumn ssn = keys.column(table + ".ssn", Mode.DETERMINISTIC);
            byte[] tokenBytes = TOKEN.getBytes(StandardCharsets.US_ASCII);
            for (int id = 1; id <= 2; id++) {
                int row = id;
                Mono.usingWhen(factory.create(),
                        c -> Mono.from(EncryptedValues.bind(EncryptedValues.bind(
                                        c.createStatement("insert into " + table
                                                + " (id, token, ssn) values (" + row + ", "
                                                + db.p1() + ", " + db.p2() + ")"),
                                        0, token, MemorySegment.ofArray(tokenBytes)),
                                        1, ssn, MemorySegment.ofArray(("ssn-" + row)
                                                .getBytes(StandardCharsets.US_ASCII)))
                                .execute()).flatMap(r -> Mono.from(r.getRowsUpdated())),
                        Connection::close).block(WAIT);
            }

            byte[] term = ssn.searchTerms(MemorySegment.ofArray("ssn-2".getBytes(
                    StandardCharsets.US_ASCII))).get(0);
            List<byte[]> stored = Flux.usingWhen(factory.create(),
                    c -> Flux.from(c.createStatement("select token from " + table
                                    + " where ssn = " + db.p1()).bind(0, ByteBuffer.wrap(term))
                                    .execute())
                            .concatMap(r -> r.map((row, meta) -> {
                                ByteBuffer value = row.get(0, ByteBuffer.class);
                                byte[] bytes = new byte[value.remaining()];
                                value.duplicate().get(bytes);
                                out.length(EncryptedValues.readInto(row, 0, token, out.segment()));
                                return bytes;
                            })),
                    Connection::close).collectList().block(WAIT);
            assertEquals(1, stored.size(), "the deterministic search found " + stored.size());
            assertArrayEquals(tokenBytes, out.secret().toArray(ValueLayout.JAVA_BYTE));
            assertEquals(tokenBytes.length + EncryptedColumn.OVERHEAD, stored.get(0).length);
            assertFalse(new String(stored.get(0), StandardCharsets.ISO_8859_1).contains("zl-r2dbc"),
                    "the token is on the server");
        } finally {
            run(factory, String.format(db.drop(), table));
        }
    }
}
