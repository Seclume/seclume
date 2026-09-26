import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * RDS MySQL: a login with an IAM token built off the heap (provider=rds-iam),
 * TLS checked against the shipped RDS bundle - and a password login beside it.
 *   args: endpoint, access key id, env file with AWS_SECRET_ACCESS_KEY, password file
 */
public class MyIamProof {
    public static void main(String[] a) throws Exception {
        String base = "jdbc:seclume:mysql://" + a[0] + ":3306/seclume_test?tls=verify-full"
                + "&tlsRootCert=aws-rds";
        ask("IAM token", base + "&user=iamuser&provider=rds-iam&access-key-id=" + a[1]
                + "&region=eu-central-1&host=" + a[0] + "&port=3306&db-user=iamuser"
                + "&key-provider=env-file&key-path=" + a[2] + "&key-key=AWS_SECRET_ACCESS_KEY");
        ask("password ", base + "&user=seclume_test&provider=file&path=" + a[3]);
    }

    static void ask(String how, String url) {
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select current_user(), @@version")) {
            r.next();
            System.out.println("PROOF " + how + ": " + r.getString(1) + " on MySQL "
                    + r.getString(2) + " by " + space.seclume.Secured.of(c).authenticationMethod()
                    + ", " + space.seclume.Secured.of(c).tlsDescription());
        } catch (Exception e) {
            System.out.println("PROOF " + how + ": refused - " + e.getMessage());
        }
    }
}
