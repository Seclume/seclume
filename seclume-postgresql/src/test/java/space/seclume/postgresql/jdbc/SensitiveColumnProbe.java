package space.seclume.postgresql.jdbc;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import space.seclume.Sensitive;
import space.seclume.secret.SecretScope;
import space.seclume.tck.Heap;

/**
 * Reads a secret out of a table without it becoming a {@code String}, and
 * dumps its own heap.
 *
 * <p>In a child JVM for the reason every proof here is: the value must not be
 * anywhere in this process, and a test that knows the value has it as a
 * constant in its own class file - interned, permanent, and found by every
 * search. The first version of this proof failed for exactly that reason,
 * which is the test working rather than the code failing.
 *
 * <p>So this process is told <b>which row to read</b> and never what is in it.
 * The only route the value takes into this JVM is the one under test.
 *
 * <p>Two modes, because a proof without its control proves nothing:
 *
 * <ul>
 *   <li>{@code native} - read through {@link Sensitive} into a
 *       {@link SecretScope}. The dump must be clean.</li>
 *   <li>{@code string} - read with {@code getString}, kept alive to the dump.
 *       The dump must contain it, or the searcher is broken and the clean
 *       result above means nothing.</li>
 * </ul>
 */
public final class SensitiveColumnProbe {

    private SensitiveColumnProbe() {
    }

    public static void main(String[] args) throws Exception {
        String url = args[0];
        Path dumpFile = Path.of(args[1]);
        boolean nativeRead = "native".equals(args[2]);

        String kept = null;
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select signing_key from zl_vault where id = 1")) {
            if (!rows.next()) {
                throw new IllegalStateException("the row is not there");
            }
            if (nativeRead) {
                try (SecretScope key = SecretScope.allocate(256)) {
                    key.length(Sensitive.of(rows).readInto(1, key.segment()));
                    // Used for something, so nothing can argue the read was
                    // optimised away: a checksum over native memory, which
                    // produces a number and not a copy.
                    long sum = 0;
                    for (int i = 0; i < key.length(); i++) {
                        sum += key.secret().get(java.lang.foreign.ValueLayout.JAVA_BYTE, i)
                                & 0xff;
                    }
                    System.out.println("read " + key.length() + " bytes natively, sum=" + sum);
                }
            } else {
                kept = rows.getString(1);
                System.out.println("read " + kept.length() + " characters as a String");
            }
            Heap.collect();
            Heap.dump(dumpFile);
        }
        // Held past the dump on purpose in the control run.
        if (kept != null && kept.isEmpty()) {
            throw new IllegalStateException("unreachable, and keeps the String alive");
        }
    }
}
