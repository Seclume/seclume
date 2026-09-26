import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * A SQL Server login by Kerberos against an Active Directory: no password
 * anywhere, the ticket in the system's credential cache. Run by
 * proof/kerberos.sh.
 */
public class KerberosProof {
    public static void main(String[] args) throws Exception {
        String url = "jdbc:seclume:sqlserver://sql.seclume.test:1433/master"
                + "?authentication=kerberos&trustServerCertificate=true";
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select suser_sname(), auth_scheme "
                     + "from sys.dm_exec_connections where session_id = @@spid")) {
            r.next();
            System.out.println("PROOF logged in as " + r.getString(1) + ", server says "
                    + r.getString(2) + ", driver says "
                    + space.seclume.Secured.of(c).authenticationMethod());
        } catch (Exception e) {
            System.out.println("PROOF refused: " + e.getMessage());
        }
    }
}
