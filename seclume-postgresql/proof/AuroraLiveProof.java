import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Against a real Aurora PostgreSQL cluster: logged in with an IAM token built
 * off the heap (provider=rds-iam), TLS checked against the shipped RDS bundle,
 * the topology learnt; then a real failover, and how long a new connection
 * takes to reach the new writer with aurora=true and without it.
 *
 *   args: cluster endpoint, access key id, env file holding AWS_SECRET_ACCESS_KEY
 */
public class AuroraLiveProof {

    static String endpoint;
    static String keyId;
    static String envFile;

    public static void main(String[] args) throws Exception {
        endpoint = args[0];
        keyId = args[1];
        envFile = args[2];
        String before = ask(url(true, "primary"));
        System.out.println("PROOF writer before: " + before);
        System.out.println("PROOF reader before: " + ask(url(true, "secondary")));
        String oldWriter = before.split(" ")[0];
        Files.writeString(Path.of("/tmp/ready"), oldWriter);
        while (!Files.exists(Path.of("/tmp/go"))) {
            Thread.sleep(200);
        }
        long start = System.nanoTime();
        AtomicReference<String> aurora = new AtomicReference<>();
        AtomicReference<String> plain = new AtomicReference<>();
        Thread a = Thread.ofVirtual().start(() -> race(url(true, "primary"), oldWriter, start, aurora));
        Thread b = Thread.ofVirtual().start(() -> race(url(false, "primary"), oldWriter, start, plain));
        a.join();
        b.join();
        System.out.println("PROOF after the failover, aurora=true: " + aurora.get());
        System.out.println("PROOF after the failover, without:     " + plain.get());
    }

    /** Tries every half second until a connection lands on a writer that is not the old one. */
    static void race(String url, String oldWriter, long start, AtomicReference<String> result) {
        String last = "";
        int attempts = 0;
        while (System.nanoTime() - start < 300_000_000_000L) {
            attempts++;
            String answer = ask(url);
            last = answer;
            if (answer.contains("(writer)") && !answer.startsWith(oldWriter + " ")) {
                result.set(answer + " after " + (System.nanoTime() - start) / 1_000_000
                        + " ms, " + attempts + " attempt(s)");
                return;
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                return;
            }
        }
        result.set("not within 300 s - last: " + last);
    }

    static String url(boolean aurora, String target) {
        return "jdbc:seclume:postgresql://" + endpoint + ":5432/postgres?user=postgres"
                + "&tls=verify-full&connectTimeout=10000"
                + "&targetServerType=" + target + (aurora ? "&aurora=true" : "")
                + "&provider=rds-iam&access-key-id=" + keyId + "&region=eu-central-1"
                + "&host=" + endpoint + "&port=5432&db-user=postgres"
                + "&key-provider=env-file&key-path=" + envFile + "&key-key=AWS_SECRET_ACCESS_KEY";
    }

    static String ask(String url) {
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select aurora_db_instance_identifier(), "
                     + "pg_is_in_recovery()")) {
            r.next();
            return r.getString(1) + (r.getBoolean(2) ? " (reader)" : " (writer)") + " by "
                    + space.seclume.Secured.of(c).authenticationMethod();
        } catch (Exception e) {
            return "refused - " + e.getMessage();
        }
    }
}
