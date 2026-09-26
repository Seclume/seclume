import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * The password for RDS MySQL fetched from AWS Secrets Manager straight into
 * native memory (provider=aws-secrets-manager, field=password) - no SDK, no
 * String.
 *   args: endpoint, access key id, env file with AWS_SECRET_ACCESS_KEY, extra URL options
 */
public class SecretsManagerProof {
    public static void main(String[] a) throws Exception {
        String url = "jdbc:seclume:mysql://" + a[0] + ":3306/seclume_test?user=seclume_test"
                + "&tls=verify-full&tlsRootCert=aws-rds&provider=aws-secrets-manager"
                + "&region=eu-central-1&secret-id=seclume-test-mysql&field=password"
                + (a.length > 3 ? a[3] : "&access-key-id=" + a[1] + "&key-provider=env-file&key-path="
                        + a[2] + "&key-key=AWS_SECRET_ACCESS_KEY");
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select current_user()")) {
            r.next();
            System.out.println("PROOF Secrets Manager: logged in as " + r.getString(1) + " by "
                    + space.seclume.Secured.of(c).authenticationMethod() + ", "
                    + space.seclume.Secured.of(c).tlsDescription());
        } catch (Exception e) {
            System.out.println("PROOF Secrets Manager: refused - " + e.getMessage());
        }
    }
}
