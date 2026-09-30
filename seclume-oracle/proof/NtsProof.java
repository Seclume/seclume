import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * An Oracle login by Windows' native authentication (NTS): no user and no
 * password, the logon session's credentials through SSPI. Run inside the
 * Windows VM of proof/nts.sh, and what the server says about the session:
 * who it is, how it authenticated, and whether it is encrypted. Further URL
 * options as the first argument.
 */
public class NtsProof {
    public static void main(String[] args) throws Exception {
        String url = "jdbc:seclume:oracle://localhost:1521/FREEPDB1"
                + "?authentication=nts" + (args.length > 0 ? "&" + args[0] : "");
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select sys_context('USERENV', 'SESSION_USER'), "
                     + "sys_context('USERENV', 'AUTHENTICATION_METHOD'), "
                     + "sys_context('USERENV', 'AUTHENTICATED_IDENTITY'), "
                     + "(select listagg(network_service_banner, '; ') from v$session_connect_info "
                     + "where sid = sys_context('USERENV', 'SID') and network_service_banner "
                     + "like 'AES%') from dual")) {
            r.next();
            System.out.println("PROOF logged in as " + r.getString(1) + ", the server says "
                    + r.getString(2) + " for " + r.getString(3)
                    + (r.getString(4) == null ? "" : ", encrypted: " + r.getString(4)));
        } catch (Exception e) {
            System.out.println("PROOF refused: " + e.getMessage());
        }
    }
}
