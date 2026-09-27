package space.seclume.aws;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * A random AWS-style secret key in a file, written by a shell - the test JVM
 * never has it unless a test reads it on purpose.
 */
final class SecretKeyFile {

    private SecretKeyFile() {
    }

    static Path make(Path directory) throws IOException, InterruptedException {
        Path file = directory.resolve("aws-secret-key");
        Path script = directory.resolve("make-key.sh");
        java.nio.file.Files.writeString(script, "head -c 30 /dev/urandom | base64 "
                + "| tr -d '\\n' > '" + file + "'\n");
        Process process = new ProcessBuilder("/bin/sh", script.toString()).start();
        if (!process.waitFor(30, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("the key file could not be written");
        }
        return file;
    }

    static String spec(String accessKeyId, Path file) {
        return "access-key-id=" + accessKeyId + "&region=eu-central-1&provider=file&path=" + file;
    }
}
