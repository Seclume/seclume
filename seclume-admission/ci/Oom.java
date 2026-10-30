import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * An application that holds its credential as a String - as most do - and
 * then runs out of memory: the JVM writes a heap dump with the credential in
 * it, which the injected sidecar has to redact where it lies.
 */
public class Oom {
    public static void main(String[] arguments) throws Exception {
        String credential = Files.readString(Path.of("/run/secrets/app/credential")).strip();
        System.out.println("ready, holding a credential of " + credential.length() + " characters");
        Thread.sleep(3000);
        List<long[]> hog = new ArrayList<>();
        while (true) {
            hog.add(new long[1 << 18]);
        }
    }
}
