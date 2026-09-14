package space.seclume.postgresql;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import space.seclume.secret.FileSecretProvider;
import space.seclume.tck.Heap;

/**
 * The probe for the heap dump test with a <b>real</b> server: connects several
 * times, does work, keeps one connection open and then writes out its own heap.
 *
 * <p>Exactly the procedure the task calls for - only with the local server
 * instead of a container. The password comes from a file and appears in no
 * argument.
 */
public final class PgProbe {

    private PgProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path secretFile = Path.of(args[0]);
        Path dumpFile = Path.of(args[1]);
        int cycles = Integer.parseInt(args[2]);

        FileSecretProvider provider = new FileSecretProvider(secretFile, 256);
        PgSession.Settings settings = new PgSession.Settings(
                "127.0.0.1", 5432, "seclume_test", "seclume_test", provider);

        List<String> results = new ArrayList<>();
        for (int i = 0; i < cycles; i++) {
            try (PgSession session = PgSession.open(settings)) {
                session.simpleQuery("select current_user, 1 + 1", row -> {
                    results.add(row.getString(0));
                    results.add(row.getString(1));
                });
            }
        }

        // One connection stays open - the way it would in a pool.
        try (PgSession open = PgSession.open(settings)) {
            open.simpleQuery("select 42", row -> results.add(row.getString(0)));
            Heap.collect();
            Heap.dump(dumpFile);
            System.out.println("connected " + (cycles + 1) + " times, "
                    + results.size() + " values, auth=" + open.authenticationMethod());
        }
    }
}
