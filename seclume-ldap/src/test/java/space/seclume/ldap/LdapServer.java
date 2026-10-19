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
    final int startTlsPort;
    private final Process process;
    private final Process startTlsProcess;

    private LdapServer(Path directory, int port, int startTlsPort, Process process,
                       Process startTlsProcess) {
        this.directory = directory;
        this.certificate = directory.resolve("cert.pem");
        this.password = directory.resolve("service-password");
        this.port = port;
        this.startTlsPort = startTlsPort;
        this.process = process;
        this.startTlsProcess = startTlsProcess;
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
        Process prepare = space.seclume.tck.Shell.builder(file.toString()).redirectErrorStream(true)
                .start();
        String output = new String(prepare.getInputStream().readAllBytes());
        if (!prepare.waitFor(60, TimeUnit.SECONDS) || prepare.exitValue() != 0) {
            throw new IllegalStateException("the LDAP server could not be prepared: " + output);
        }
        int port;
        int startTlsPort;
        try (ServerSocket free1 = new ServerSocket(0);
             ServerSocket free2 = new ServerSocket(0)) {
            port = free1.getLocalPort();
            startTlsPort = free2.getLocalPort();
        }
        Process process = startInstance(directory, port, "--useSSL", "server.log");
        Process startTlsProcess = startInstance(directory, startTlsPort, "--useStartTLS",
                "server-starttls.log");
        LdapServer server = new LdapServer(directory, port, startTlsPort, process, startTlsProcess);
        waitUntilListening(server, process, port, directory.resolve("server.log"));
        waitUntilListening(server, startTlsProcess, startTlsPort,
                directory.resolve("server-starttls.log"));
        return server;
    }

    private static Process startInstance(Path directory, int port, String tlsMode, String logName)
            throws IOException {
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"),
                "com.unboundid.ldap.listener.InMemoryDirectoryServerTool",
                "--baseDN", BASE, "--port", String.valueOf(port), tlsMode,
                "--keyStorePath", directory.resolve("store.p12").toString(),
                "--keyStorePassword", "keystore", "--keyStoreType", "PKCS12",
                "--ldifFile", directory.resolve("data.ldif").toString()));
        return new ProcessBuilder(command).redirectErrorStream(true)
                .redirectOutput(directory.resolve(logName).toFile()).start();
    }

    private static void waitUntilListening(LdapServer server, Process proc, int port, Path log)
            throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (System.nanoTime() < deadline) {
            if (!proc.isAlive()) {
                server.close();
                throw new IllegalStateException("the LDAP server ended, see " + log);
            }
            try {
                new Socket("localhost", port).close();
                return;
            } catch (IOException notYet) {
                Thread.sleep(100);
            }
        }
        server.close();
        throw new IllegalStateException("the LDAP server did not start in time");
    }

    String url(Path passwordFile) {
        return "ldaps://localhost:" + port + "/" + BASE + "?user=" + SERVICE
                + "&tlsRootCert=" + certificate.toString().replace('\\', '/')
                + "&provider=file&path=" + passwordFile.toString().replace('\\', '/');
    }

    String url() {
        return url(password);
    }

    String startTlsUrl(Path passwordFile) {
        return "ldap://localhost:" + startTlsPort + "/" + BASE + "?user=" + SERVICE
                + "&tlsRootCert=" + certificate.toString().replace('\\', '/')
                + "&provider=file&path=" + passwordFile.toString().replace('\\', '/');
    }

    String startTlsUrl() {
        return startTlsUrl(password);
    }

    @Override
    public void close() {
        stopProcess(process);
        stopProcess(startTlsProcess);
    }

    private static void stopProcess(Process proc) {
        if (proc == null) {
            return;
        }
        proc.destroy();
        try {
            if (!proc.waitFor(10, TimeUnit.SECONDS)) {
                proc.destroyForcibly();
            }
        } catch (InterruptedException e) {
            proc.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }
}
