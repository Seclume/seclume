import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * A failover the Aurora way, against a stand-in (see proof/aurora.sh): the
 * cluster endpoint points at the old writer and stops answering; with
 * aurora=true the next connection finds the new writer from what the cluster
 * said before, without it the connection fails.
 */
public class AuroraProof {

    static final String BASE = "jdbc:seclume:postgresql://cluster.aur.test:5432/postgres"
            + "?user=postgres&tls=off&provider=file&path=/pw&connectTimeout=3000";
    static final String AURORA = "&aurora=true&auroraInstanceHost=?.aur.test";

    public static void main(String[] args) throws Exception {
        System.out.println("PROOF writer before: " + ask(BASE + AURORA + "&targetServerType=primary"));
        System.out.println("PROOF reader before: " + ask(BASE + AURORA + "&targetServerType=secondary"));
        Files.writeString(Path.of("/tmp/ready"), "ready");
        while (!Files.exists(Path.of("/tmp/go"))) {
            Thread.sleep(200);
        }
        long start = System.nanoTime();
        System.out.println("PROOF writer after, aurora=true: "
                + ask(BASE + AURORA + "&targetServerType=primary") + " in "
                + (System.nanoTime() - start) / 1_000_000 + " ms");
        System.out.println("PROOF writer after, without: " + ask(BASE + "&targetServerType=primary"));
    }

    static String ask(String url) {
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select current_setting('cluster_name'), "
                     + "pg_is_in_recovery()")) {
            r.next();
            return r.getString(1) + (r.getBoolean(2) ? " (reader)" : " (writer)");
        } catch (Exception e) {
            return "refused - " + e.getMessage();
        }
    }
}
