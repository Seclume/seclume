package space.seclume.sqlserver;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import space.seclume.internal.jdbc.HostList;
import space.seclume.secret.FileSecretProvider;
import space.seclume.sqlserver.tds.TdsSession;
import space.seclume.tck.Heap;

/**
 * The probe for the SQL Server heap dump test: logs in several times, does
 * work, keeps one connection open and then writes out its own heap.
 *
 * <p>A complete LOGIN7 runs through this process each time, which for SQL
 * Server means the password is re-encoded to UTF-16LE and obfuscated - nibbles
 * swapped, XOR {@code 0xA5}. Had any of those steps gone across the heap the
 * password would stand in the dump, in one form or the other.
 */
public final class TdsProbe {

    private TdsProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path secretFile = Path.of(args[0]);
        Path dumpFile = Path.of(args[1]);
        String host = args[2];
        int port = Integer.parseInt(args[3]);
        String marker = args[4];
        int cycles = Integer.parseInt(args[5]);

        FileSecretProvider provider = new FileSecretProvider(secretFile, 256);
        TdsSession.Settings settings = new TdsSession.Settings(host, port, "master", "sa",
                provider, "heap-probe", 10_000, true, HostList.of(host, port));

        List<String> results = new ArrayList<>();
        for (int i = 0; i < cycles; i++) {
            try (TdsSession session = TdsSession.open(settings)) {
                session.sqlBatch("select '" + marker + "' as label",
                        row -> results.add(row.text(0)));
            }
        }

        // One connection stays open - the way it would in a pool.
        try (TdsSession open = TdsSession.open(settings)) {
            open.sqlBatch("select 1 as n", row -> { });
            Heap.collect();
            Heap.dump(dumpFile);
            System.out.println("connected " + (cycles + 1) + " times, "
                    + results.size() + " values, marker seen "
                    + results.stream().filter(marker::equals).count() + " times");
        }
    }
}
