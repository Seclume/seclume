import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * seclume's own TLS 1.3 stack - key exchange, signatures and AES-GCM in the
 * operating system's OpenSSL through FFM - on whatever machine this runs on.
 *   args: PostgreSQL host, PostgreSQL password file, MySQL host, MySQL password file
 */
public class NativeTlsCheck {
    public static void main(String[] a) throws Exception {
        System.out.println("CHECK " + System.getProperty("os.arch") + ", AES-GCM through "
                + space.seclume.crypto.AesGcmCipher.of(
                        java.lang.foreign.Arena.ofAuto().allocate(32), 0, 32).implementation());
        ask("PostgreSQL", "jdbc:seclume:postgresql://" + a[0] + ":5432/seclume_test?user=seclume_test"
                + "&tls=require&tlsStack=seclume&provider=file&path=" + a[1], "select version()");
        ask("MySQL     ", "jdbc:seclume:mysql://" + a[2] + ":3306/seclume_test?user=seclume_test"
                + "&tls=verify-full&tlsRootCert=aws-rds&tlsStack=seclume&provider=file&path=" + a[3],
                "select @@version");
    }

    static void ask(String name, String url, String query) {
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery(query)) {
            r.next();
            String v = r.getString(1);
            System.out.println("CHECK " + name + ": ok - " + v.substring(0, Math.min(18, v.length()))
                    + " - " + space.seclume.Secured.of(c).tlsDescription());
        } catch (Exception e) {
            System.out.println("CHECK " + name + ": refused - " + e.getMessage());
        }
    }
}
