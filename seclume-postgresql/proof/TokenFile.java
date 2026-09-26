import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Writes seclume's RDS IAM token to a file for a psql cross-check - diagnosis only. */
public class TokenFile {
    public static void main(String[] a) throws Exception {
        var p = space.seclume.secret.SecretProviders.of(Map.of("provider", "rds-iam",
                "access-key-id", a[3], "region", "eu-central-1", "host", a[0], "port", a[1],
                "db-user", a[2], "key-provider", "env-file", "key-path", a[4],
                "key-key", "AWS_SECRET_ACCESS_KEY"));
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(p.maxSecretLength());
            int n = p.writeSecret(out);
            Files.write(Path.of(a[5]), out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE));
        }
    }
}
