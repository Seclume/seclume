package space.seclume.keys;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * A key and its self-signed certificate, made by the {@code openssl} command
 * line - and, beside them, the key's secret parts as files to search the heap
 * for: {@code key.der} (PKCS#8) and {@code secret.bin} (an RSA key's first
 * prime, an EC key's private scalar - what a {@code BigInteger} would hold).
 *
 * <p>Those files are written by a shell, not by this JVM, which never reads
 * them: the heap search is only worth something if the test itself does not
 * put the key there.
 */
record KeyFiles(Path directory, Path key, Path certificate, Path der, Path secret) {

    /** {@code rsa:2048}, {@code rsa:3072}, {@code ec:P-256}, {@code ec:P-384}. */
    static KeyFiles make(Path directory, String kind) throws IOException, InterruptedException {
        Files.createDirectories(directory);
        String generate = kind.startsWith("rsa:")
                ? "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:" + kind.substring(4)
                : "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:" + kind.substring(3);
        String part = kind.startsWith("rsa:") ? "prime1" : "priv";
        String script = String.join("\n",
                "set -e",
                "cd '" + directory + "'",
                generate + " -out key.pem 2>/dev/null",
                "openssl req -x509 -new -key key.pem -out cert.pem -days 2 -subj /CN=localhost"
                        + " -addext subjectAltName=DNS:localhost,IP:127.0.0.1 2>/dev/null",
                "openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out key.der",
                "openssl pkey -in key.pem -text -noout"
                        + " | sed -n '/^" + part + ":/,/^[a-zA-Z]/p' | sed '1d;$d'"
                        + " | tr -d ' :\\n' | sed 's/^00//' | perl -ne 'print pack(\"H*\", $_)' > secret.bin",
                "test -s secret.bin");
        Path file = directory.resolve("make-key.sh");
        Files.writeString(file, script);
        Process process = space.seclume.tck.Shell.builder(file.toString()).redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes());
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("openssl failed: " + output);
        }
        return new KeyFiles(directory, directory.resolve("key.pem"),
                directory.resolve("cert.pem"), directory.resolve("key.der"),
                directory.resolve("secret.bin"));
    }

    String spec() {
        return "provider=file&path=" + key;
    }
}
