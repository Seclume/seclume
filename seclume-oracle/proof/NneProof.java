import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * A login to an Oracle that requires Native Network Encryption (proof/nne.sh),
 * and what the server says the session runs under. Arguments: host, port,
 * password file, and further URL options.
 */
public class NneProof {
    public static void main(String[] args) throws Exception {
        String url = "jdbc:seclume:oracle://" + args[0] + ":" + args[1] + "/FREEPDB1"
                + "?user=seclume_test&provider=file&path=" + args[2].replace('\\', '/')
                + (args.length > 3 ? "&" + args[3] : "");
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select network_service_banner from v$session_connect_info"
                     + " where sid = sys_context('USERENV', 'SID')")) {
            StringBuilder banners = new StringBuilder();
            while (r.next()) {
                banners.append("\n  ").append(r.getString(1));
            }
            System.out.println("PROOF logged in; the server's view:" + banners);
        } catch (Exception e) {
            System.out.println("PROOF refused: " + e.getMessage());
        }
    }
}
