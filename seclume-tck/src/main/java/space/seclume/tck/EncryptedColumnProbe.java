package space.seclume.tck;

import java.lang.foreign.ValueLayout;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.FieldKeys;
import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The child of {@link EncryptedColumnContract}'s heap test: given the row and
 * where the key is, never the value. Reads the value into native memory
 * ({@code native}) or as a {@code String} ({@code string}, the control), then
 * dumps its own heap.
 *
 * <p>Arguments: the JDBC URL, the table, the key file, the dump, the mode.
 */
public final class EncryptedColumnProbe {

    private EncryptedColumnProbe() {
    }

    public static void main(String[] args) throws Exception {
        String url = args[0];
        String table = args[1];
        Path keyFile = Path.of(args[2]);
        Path dump = Path.of(args[3]);
        boolean nativeRead = "native".equals(args[4]);

        String kept = null;
        try (FieldKeys keys = FieldKeys.builder().key(1, new FileSecretProvider(keyFile, 128))
                .build();
             Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select secret from " + table + " where id = 1")) {
            EncryptedColumn secret = keys.column("zl.secret", EncryptedColumn.Mode.RANDOMIZED);
            if (!rows.next()) {
                throw new IllegalStateException("the row is not there");
            }
            if (nativeRead) {
                try (SecretScope value = SecretScope.allocate(512)) {
                    value.length(secret.readInto(rows, 1, new byte[] {'1'}, value.segment()));
                    long sum = 0;
                    for (int i = 0; i < value.length(); i++) {
                        sum += value.secret().get(ValueLayout.JAVA_BYTE, i) & 0xff;
                    }
                    System.out.println("read " + value.length() + " bytes natively, sum=" + sum);
                }
            } else {
                try (SecretScope value = SecretScope.allocate(512)) {
                    value.length(secret.readInto(rows, 1, new byte[] {'1'}, value.segment()));
                    // seclume-allow: the control run puts the value on the heap on purpose
                    kept = new String(value.secret().toArray(ValueLayout.JAVA_BYTE),
                            java.nio.charset.StandardCharsets.UTF_8);
                    System.out.println("read " + kept.length() + " bytes as a String");
                }
            }
            Heap.collect();
            Heap.dump(dump);
        }
        if (kept != null && kept.isEmpty()) {
            throw new IllegalStateException("unreachable, and keeps the String alive");
        }
    }
}
