import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The usual way: the password comes from Vault as JSON, becomes a String
 * (as it does in Spring Cloud Vault, the Vault Java driver, or any HTTP
 * client), and goes to the vendor's JDBC driver - pgjdbc here.
 */
public class VendorApp {
    public static void main(String[] args) throws Exception {
        String token = Files.readString(Path.of("/shared/vault-token")).strip();
        HttpResponse<String> answer = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("https://127.0.0.1:8200/v1/secret/data/app"))
                        .header("X-Vault-Token", token).build(),
                HttpResponse.BodyHandlers.ofString());
        Matcher field = Pattern.compile("\"password\":\"([^\"]*)\"").matcher(answer.body());
        if (!field.find()) {
            throw new IllegalStateException("no password field in Vault's answer");
        }
        String password = field.group(1);
        Connection connection = DriverManager.getConnection(
                "jdbc:postgresql://127.0.0.1:5432/postgres", "postgres", password);
        try (ResultSet r = connection.createStatement().executeQuery("select 1")) {
            r.next();
        }
        // What a long-running application does: keep going, with its pool.
        password = null;
        token = null;
        System.gc();
        System.out.println("vendor app: connected, pid " + ProcessHandle.current().pid());
        Thread.sleep(Long.MAX_VALUE);
    }
}
