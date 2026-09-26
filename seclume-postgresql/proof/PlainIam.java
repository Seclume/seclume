import java.sql.Connection;
import java.sql.DriverManager;

/** The IAM login through the driver with as few options as possible - diagnosis. */
public class PlainIam {
    public static void main(String[] a) throws Exception {
        String base = "jdbc:seclume:postgresql://" + a[0] + ":5432/postgres?user=postgres"
                + "&tls=verify-full&provider=rds-iam&access-key-id=" + a[1]
                + "&region=eu-central-1&host=" + a[0] + "&port=5432&db-user=postgres"
                + "&key-provider=env-file&key-path=" + a[2] + "&key-key=AWS_SECRET_ACCESS_KEY";
        for (String extra : new String[] {"&tlsRootCert=aws-rds", "&tlsRootCert=aws-rds&targetServerType=secondary&aurora=true"}) {
            try (Connection c = DriverManager.getConnection(base + extra)) {
                System.out.println("IAM ok " + extra + " " + space.seclume.Secured.of(c).authenticationMethod());
            } catch (Exception e) {
                System.out.println("IAM refused " + extra + ": " + e.getMessage());
            }
        }
    }
}
