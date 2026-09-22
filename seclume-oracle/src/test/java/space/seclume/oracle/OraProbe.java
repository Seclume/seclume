package space.seclume.oracle;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import space.seclume.secret.FileSecretProvider;
import space.seclume.tck.Heap;

/**
 * The probe for the Oracle heap dump test: logs in several times, does work,
 * keeps one connection open and then writes out its own heap.
 *
 * <p>A complete O5LOGON runs through this process each time: the password goes
 * into a key derivation, the derived key decrypts the server's challenge, and
 * the answer goes back encrypted. That is more handling than any of the other
 * three protocols does, and every step of it is a chance for the password to
 * reach a Java object.
 */
public final class OraProbe {

    private OraProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path secretFile = Path.of(args[0]);
        Path dumpFile = Path.of(args[1]);
        String host = args[2];
        int port = Integer.parseInt(args[3]);
        String service = args[4];
        String user = args[5];
        String marker = args[6];
        int cycles = Integer.parseInt(args[7]);

        FileSecretProvider provider = new FileSecretProvider(secretFile, 256);
        OracleSession.Settings settings = new OracleSession.Settings(
                host, port, service, user, provider, 10_000);

        List<String> results = new ArrayList<>();
        for (int i = 0; i < cycles; i++) {
            try (OracleSession session = OracleSession.open(settings)) {
                session.query("select '" + marker + "' from dual",
                        row -> results.add(row.text(0)));
            }
        }

        // One connection stays open - the way it would in a pool.
        try (OracleSession open = OracleSession.open(settings)) {
            open.query("select 1 from dual", row -> { });
            Heap.collect();
            Heap.dump(dumpFile);
            System.out.println("connected " + (cycles + 1) + " times, "
                    + results.size() + " values, marker seen "
                    + results.stream().filter(marker::equals).count() + " times");
        }
    }
}
