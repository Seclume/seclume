import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * RDS SQL Server over TDS 7.4: the certificate and host name checked against
 * the shipped RDS bundle - and what is refused without it.
 *   args: endpoint, its IP address, password file
 */
public class RdsTlsProof {
    public static void main(String[] a) throws Exception {
        String tail = "/master?user=admin&provider=file&path=" + a[2];
        ask("aws-rds bundle, by name      ", "jdbc:seclume:sqlserver://" + a[0] + ":1433" + tail
                + "&tlsRootCert=aws-rds");
        ask("JVM trust store only         ", "jdbc:seclume:sqlserver://" + a[0] + ":1433" + tail);
        ask("aws-rds bundle, by IP address", "jdbc:seclume:sqlserver://" + a[1] + ":1433" + tail
                + "&tlsRootCert=aws-rds");
        ask("trustServerCertificate=true  ", "jdbc:seclume:sqlserver://" + a[0] + ":1433" + tail
                + "&trustServerCertificate=true");
    }

    static void ask(String how, String url) {
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select suser_sname(), cast(serverproperty('ProductVersion') as varchar(20))")) {
            r.next();
            System.out.println("PROOF " + how + ": ok - " + r.getString(1) + " on SQL Server "
                    + r.getString(2) + ", " + space.seclume.Secured.of(c).tlsDescription());
        } catch (Exception e) {
            StringBuilder m = new StringBuilder(String.valueOf(e.getMessage()));
            if (e instanceof java.sql.SQLException q) {
                m.append(" [").append(q.getSQLState()).append("/").append(q.getErrorCode()).append("]");
            }
            for (Throwable c = e.getCause(); c != null; c = c.getCause()) {
                m.append(" <- ").append(c.getClass().getSimpleName()).append(": ").append(c.getMessage());
            }
            System.out.println("PROOF " + how + ": refused - " + m.substring(0, Math.min(400, m.length())));
        }
    }
}
