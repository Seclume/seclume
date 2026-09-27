package space.seclume.ldap;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * An LDAPS server - UnboundID's in-memory directory - in a process of its own,
 * so that the service account's password is in its heap and never in the
 * test's. The password is made by a shell and written into the LDIF and a file
 * for seclume's provider; this JVM reads neither.
 */
final class LdapServer implements AutoCloseable {

    static final String BASE = "dc=example,dc=com";
    static final String SERVICE = "cn=app,ou=services," + BASE;
    static final String ALICE = "uid=alice,ou=people," + BASE;
    static final String ALICE_PASSWORD = "alice-typed-this";

    final Path directory;
    final Path certificate;
    final Path password;
    final int port;
    private final Process process;

    private LdapServer(Path directory, int port, Process process) {
        this.directory = directory;
        this.certificate = directory.resolve("cert.pem");
        this.password = directory.resolve("service-password");
        this.port = port;
        this.process = process;
    }

    static LdapServer start(Path directory) throws Exception {
        String script = String.join("\n",
                "set -e",
                "cd '" + directory + "'",
                "openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2"
                        + " -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null",
                "openssl pkcs12 -export -in cert.pem -inkey key.pem -out store.p12"
                        + " -passout pass:keystore -name server",
                "head -c 24 /dev/urandom | base64 | tr -d '/+=\\n' > service-password",
                "cat > data.ldif <<LDIF",
                "dn: " + BASE, "objectClass: top", "objectClass: domain", "dc: example", "",
                "dn: ou=services," + BASE, "objectClass: organizationalUnit", "ou: services", "",
                "dn: ou=people," + BASE, "objectClass: organizationalUnit", "ou: people", "",
                "dn: " + SERVICE, "objectClass: person", "cn: app", "sn: app",
                "userPassword: $(cat service-password)", "",
                "dn: " + ALICE, "objectClass: inetOrgPerson", "uid: alice", "cn: Alice",
                "sn: Liddell", "mail: alice@example.com", "userPassword: " + ALICE_PASSWORD,
                "LDIF");
        Path file = directory.resolve("prepare.sh");
        java.nio.file.Files.writeString(file, script + "\n");
        Process prepare = new ProcessBuilder("sh", file.toString()).redirectErrorStream(true)
                .start();
        String output = new String(prepare.getInputStream().readAllBytes());
        if (!prepare.waitFor(60, TimeUnit.SECONDS) || prepare.exitValue() != 0) {
            throw new IllegalStateException("the LDAP server could not be prepared: " + output);
        }
        int port;
        try (ServerSocket free = new ServerSocket(0)) {
            port = free.getLocalPort();
        }
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"),
                "com.unboundid.ldap.listener.InMemoryDirectoryServerTool",
                "--baseDN", BASE, "--port", String.valueOf(port), "--useSSL",
                "--keyStorePath", directory.resolve("store.p12").toString(),
                "--keyStorePassword", "keystore", "--keyStoreType", "PKCS12",
                "--ldifFile", directory.resolve("data.ldif").toString()));
        Process process = new ProcessBuilder(command).redirectErrorStream(true)
                .redirectOutput(directory.resolve("server.log").toFile()).start();
        LdapServer server = new LdapServer(directory, port, process);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (System.nanoTime() < deadline) {
            if (!process.isAlive()) {
                throw new IllegalStateException("the LDAP server ended, see "
                        + directory.resolve("server.log"));
            }
            try {
                new Socket("localhost", port).close();
                return server;
            } catch (IOException notYet) {
                Thread.sleep(100);
            }
        }
        server.close();
        throw new IllegalStateException("the LDAP server did not start in time");
    }

    String url(Path passwordFile) {
        return "ldaps://localhost:" + port + "/" + BASE + "?user=" + SERVICE
                + "&tlsRootCert=" + certificate + "&provider=file&path=" + passwordFile;
    }

    String url() {
        return url(password);
    }

    @Override
    public void close() {
        process.destroy();
        try {
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }
}
