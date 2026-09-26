import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * seclume's RDS IAM token against the AWS CLI's, made in the same second.
 * Prints only whether they match and, if not, the first differing position
 * and the unsigned part around it - never a token, never a key.
 *   args: endpoint, port, user, access key id, env file
 */
public class TokenCheck {
    public static void main(String[] a) throws Exception {
        SecretProvider ours = SecretProviders.of(Map.of("provider", "rds-iam",
                "access-key-id", a[3], "region", "eu-central-1", "host", a[0], "port", a[1],
                "db-user", a[2], "key-provider", "env-file", "key-path", a[4],
                "key-key", "AWS_SECRET_ACCESS_KEY"));
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
                    a[0], "--port", a[1], "--username", a[2], "--region", "eu-central-1")
                    .redirectErrorStream(true).start();
            String theirs = new String(p.getInputStream().readAllBytes(),
                    StandardCharsets.US_ASCII).trim();
            if (System.currentTimeMillis() / 1000 != second) {
                continue;                             // crossed a second: try again
            }
            if (mine.equals(theirs)) {
                System.out.println("CHECK tokens identical (" + mine.length() + " chars)");
                return;
            }
            int i = 0;
            while (i < Math.min(mine.length(), theirs.length())
                    && mine.charAt(i) == theirs.charAt(i)) {
                i++;
            }
            System.out.println("CHECK differ at " + i + " of " + mine.length() + "/"
                    + theirs.length());
            System.out.println("CHECK ours   unsigned: " + unsigned(mine));
            System.out.println("CHECK theirs unsigned: " + unsigned(theirs));
            return;
        }
        System.out.println("CHECK could not make both within one second");
    }

    /** Everything but the signature and the key id - what the server is told in the clear. */
    static String unsigned(String token) {
        int sig = token.indexOf("&X-Amz-Signature=");
        String head = sig < 0 ? token : token.substring(0, sig);
        return head.replaceAll("AKIA[A-Z0-9]+", "AKIA...");
    }
}
