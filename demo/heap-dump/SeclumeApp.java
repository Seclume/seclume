import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;

/**
 * The same application with seclume: Vault is read by the driver's own
 * provider, the answer lands in native memory, and the password is used there
 * and wiped - it never becomes a String. The Vault token comes from a file
 * the same way.
 */
public class SeclumeApp {
    public static void main(String[] args) throws Exception {
        Connection connection = DriverManager.getConnection(
                "jdbc:seclume:postgresql://127.0.0.1:5432/postgres?user=postgres&tls=off"
                + "&provider=vault&address=https://127.0.0.1:8200&path=secret/data/app"
                + "&token-provider=file&token-path=/shared/vault-token");
        try (ResultSet r = connection.createStatement().executeQuery("select 1")) {
            r.next();
        }
        System.gc();
        System.out.println("seclume app: connected, pid " + ProcessHandle.current().pid());
        Thread.sleep(Long.MAX_VALUE);
    }
}
