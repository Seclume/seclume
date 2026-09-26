import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Map;

/**
 * On an EC2 instance with a role and no key anywhere: credentials=instance for
 * the RDS IAM token (checked byte for byte against the AWS CLI's, which uses
 * the same role) and for Secrets Manager, then real logins with both.
 *   args: MySQL endpoint
 */
public class InstanceRoleProof {
    public static void main(String[] a) throws Exception {
        String ep = a[0];
        var ours = space.seclume.secret.SecretProviders.of(Map.of("provider", "rds-iam",
                "credentials", "instance", "region", "eu-central-1", "host", ep, "port", "3306",
                "db-user", "iamuser"));
        for (int attempt = 0; attempt < 5; attempt++) {
            long second = System.currentTimeMillis() / 1000;
            String mine;
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment out = arena.allocate(ours.maxSecretLength());
                int n = ours.writeSecret(out);
                mine = new String(out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE),
                        StandardCharsets.US_ASCII);
            }
            Process p = new ProcessBuilder("aws", "rds", "generate-db-auth-token", "--hostname",
                    ep, "--port", "3306", "--username", "iamuser", "--region", "eu-central-1")
                    .redirectErrorStream(true).start();
            String theirs = new String(p.getInputStream().readAllBytes(),
                    StandardCharsets.US_ASCII).trim();
            if (System.currentTimeMillis() / 1000 != second) {
                continue;
            }
            if (!mine.equals(theirs)) {
                int i = 0;
                while (i < Math.min(mine.length(), theirs.length()) && mine.charAt(i) == theirs.charAt(i)) {
                    i++;
                }
                int param = mine.lastIndexOf('&', i);
                String name = mine.substring(param + 1, mine.indexOf('=', param + 1));
                System.out.println("PROOF first difference at " + i + " inside parameter " + name
                        + "; equal ignoring case: " + mine.equalsIgnoreCase(theirs)
                        + "; equal once decoded: " + java.net.URLDecoder.decode(mine, StandardCharsets.UTF_8)
                                .equals(java.net.URLDecoder.decode(theirs, StandardCharsets.UTF_8)));
            }
            System.out.println("PROOF token with the role's session token: "
                    + (mine.equals(theirs) ? "identical to the AWS CLI's (" + mine.length()
                    + " chars, X-Amz-Security-Token inside: " + mine.contains("X-Amz-Security-Token")
                    + ")" : "DIFFERENT (" + mine.length() + " vs " + theirs.length() + ")"));
            break;
        }
        String tls = "&tls=verify-full&tlsRootCert=aws-rds";
        ask("IAM login, credentials=instance      ", "jdbc:seclume:mysql://" + ep
                + ":3306/seclume_test?user=iamuser" + tls + "&provider=rds-iam&credentials=instance"
                + "&region=eu-central-1&host=" + ep + "&port=3306&db-user=iamuser");
        ask("Secrets Manager, credentials=instance", "jdbc:seclume:mysql://" + ep
                + ":3306/seclume_test?user=seclume_test" + tls
                + "&provider=aws-secrets-manager&credentials=instance&region=eu-central-1"
                + "&secret-id=seclume-test-mysql&field=password");
    }

    static void ask(String how, String url) {
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery("select current_user()")) {
            r.next();
            System.out.println("PROOF " + how + ": ok - " + r.getString(1) + " by "
                    + space.seclume.Secured.of(c).authenticationMethod());
        } catch (Exception e) {
            System.out.println("PROOF " + how + ": refused - " + e.getMessage());
        }
    }
}
