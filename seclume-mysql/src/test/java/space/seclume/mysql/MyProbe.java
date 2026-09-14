package space.seclume.mysql;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import space.seclume.secret.FileSecretProvider;
import space.seclume.tck.Heap;

/**
 * The probe for the heap dump test: connects several times, does work, keeps
 * one connection open and then writes out its own heap.
 *
 * <p>The server is the test server in the parent process. For the question
 * being checked here that makes no difference: the same handshake with the same
 * SHA-1 computations over the same password runs through this process. Had one
 * of them gone across the heap, the password would stand in the dump.
 */
public final class MyProbe {

    private MyProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path secretFile = Path.of(args[0]);
        Path dumpFile = Path.of(args[1]);
        int port = Integer.parseInt(args[2]);
        int cycles = Integer.parseInt(args[3]);

        FileSecretProvider provider = new FileSecretProvider(secretFile, 256);
        MySession.Settings settings = new MySession.Settings(
                "127.0.0.1", port, "testdb", "seclume_test", provider);

        List<String> results = new ArrayList<>();
        for (int i = 0; i < cycles; i++) {
            try (MySession session = MySession.open(settings)) {
                session.query("select id, label from t", row -> {
                    results.add(String.valueOf(row.getLong(0)));
                    results.add(row.getString(1));
                });
            }
        }

        // One connection stays open - the way it would in a pool.
        try (MySession open = MySession.open(settings)) {
            open.ping();
            Heap.collect();
            Heap.dump(dumpFile);
            System.out.println("connected " + (cycles + 1) + " times, "
                    + results.size() + " values, plugin=" + open.authenticationPlugin());
        }
    }
}
