import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * A PostgreSQL 18 login by OAuth bearer token (OAUTHBEARER), the token from a
 * secret provider. Run by proof/oauth.sh with the token file and the TLS options.
 */
public class OAuthProof {
    public static void main(String[] args) throws Exception {
        String url = "jdbc:seclume:postgresql://pg18.seclume.test:5432/postgres?user=alice"
                + "&" + args[1] + "&provider=file&path=" + args[0];
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select current_user, system_user")) {
            r.next();
            System.out.println("PROOF logged in as " + r.getString(1) + " (" + r.getString(2)
                    + ") by " + space.seclume.Secured.of(c).authenticationMethod());
        } catch (Exception e) {
            System.out.println("PROOF refused: " + e.getMessage());
        }
    }
}
