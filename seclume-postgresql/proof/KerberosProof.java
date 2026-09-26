import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * A PostgreSQL login by Kerberos: no password anywhere, the ticket in the
 * system's credential cache. Run by proof/kerberos.sh.
 */
public class KerberosProof {
    public static void main(String[] args) throws Exception {
        String url = "jdbc:seclume:postgresql://pg.seclume.test:5432/postgres?user=alice"
                + "&tls=off&provider=none";
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select current_user")) {
            r.next();
            System.out.println("PROOF logged in as " + r.getString(1) + " by "
                    + space.seclume.Secured.of(c).authenticationMethod());
        } catch (Exception e) {
            System.out.println("PROOF refused: " + e.getMessage());
        }
    }
}
