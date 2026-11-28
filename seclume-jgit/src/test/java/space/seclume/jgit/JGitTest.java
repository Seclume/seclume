package space.seclume.jgit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.ref.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.TransportException;
import org.eclipse.jgit.transport.PushResult;
import org.eclipse.jgit.transport.RemoteRefUpdate;
import org.eclipse.jgit.transport.http.HttpConnectionFactory;
import org.eclipse.jgit.transport.HttpTransport;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.tck.NoSecretInHeap;

/** Clone and push over HTTPS, the password with the server - another process - and in native memory here. */
class JGitTest {

    @TempDir
    static Path directory;

    static Process server;
    static String url;
    static HttpConnectionFactory previous;

    @BeforeAll
    static void start() throws Exception {
        Path script = directory.resolve("setup.sh");
        Files.writeString(script, String.join("\n", "set -e", "cd '" + directory + "'",
                "openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2"
                        + " -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null",
                "openssl pkcs12 -export -in cert.pem -inkey key.pem -out store.p12 -passout pass:store",
                "head -c 30 /dev/urandom | base64 | tr -d '\\n' > password",
                "printf wrong-password > wrong", ""));
        assertEquals(0, space.seclume.tck.Shell.builder(script.toString()).start().waitFor());
        server = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java")
                .toString(), "-cp", System.getProperty("java.class.path"),
                GitServerProcess.class.getName(), directory.toString())
                .redirectErrorStream(true).redirectOutput(directory.resolve("server.log").toFile())
                .start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        while (!Files.exists(directory.resolve("port"))) {
            assertTrue(server.isAlive() && System.nanoTime() < deadline,
                    () -> "no Git server: " + log());
            Thread.sleep(100);
        }
        url = "https://localhost:" + Files.readString(directory.resolve("port")).trim()
                + "/app.git";
        previous = HttpTransport.getConnectionFactory();
        HttpTransport.setConnectionFactory(SeclumeGit.connections("tlsRootCert="
                + directory.resolve("cert.pem")));
    }

    @AfterAll
    static void stop() throws InterruptedException {
        if (previous != null) {
            HttpTransport.setConnectionFactory(previous);
        }
        if (server != null) {
            // Waited for: on Windows the process holds its log in the
            // temporary directory open, and that is deleted right after.
            server.destroy();
            if (!server.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
                server.destroyForcibly().waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            }
        }
    }

    private static String log() {
        try {
            return Files.readString(directory.resolve("server.log"));
        } catch (java.io.IOException e) {
            return e.toString();
        }
    }

    private static Git cloneInto(String name, String secretFile) throws Exception {
        return Git.cloneRepository().setURI(url).setDirectory(directory.resolve(name).toFile())
                .setCredentialsProvider(SeclumeGit.credentials("deploy",
                        "provider=file&path=" + directory.resolve(secretFile), url))
                .call();
    }

    @Test
    void cloneAndPush() throws Exception {
        try (Git git = cloneInto("work", "password")) {
            Path work = directory.resolve("work");
            // Line endings as the user's git config checks them out (core.autocrlf on Windows).
            assertEquals("hello from the server\n",
                    Files.readString(work.resolve("README")).replace("\r\n", "\n"));
            Files.writeString(work.resolve("CHANGES"), "pushed through seclume\n");
            git.add().addFilepattern("CHANGES").call();
            git.commit().setMessage("second").setAuthor("dev", "dev@example.com")
                    .setCommitter("dev", "dev@example.com").setSign(false).call();
            Iterable<PushResult> results = git.push().setCredentialsProvider(
                    SeclumeGit.credentials("deploy", "provider=file&path="
                            + directory.resolve("password"), url)).call();
            for (PushResult result : results) {
                for (RemoteRefUpdate update : result.getRemoteUpdates()) {
                    assertEquals(RemoteRefUpdate.Status.OK, update.getStatus());
                }
            }
        }
        try (Git again = cloneInto("again", "password")) {
            assertEquals("second", again.log().call().iterator().next().getShortMessage());
            assertEquals("pushed through seclume\n",
                    Files.readString(directory.resolve("again").resolve("CHANGES"))
                            .replace("\r\n", "\n"));
        }
    }

    @Test
    void aWrongPasswordIsRefused() {
        TransportException refused = assertThrows(TransportException.class,
                () -> cloneInto("refused", "wrong").close());
        assertTrue(refused.getMessage().toLowerCase().contains("auth")
                || refused.getMessage().contains("401"), refused.getMessage());
    }

    /**
     * Credentials named for the remote: its host and port get the secret,
     * and only they. Bound to another server - as a submodule's host or a
     * redirect would be - the same clone goes out with the placeholder and
     * is refused.
     */
    @Test
    @SuppressWarnings("try") // the clone is held for its working tree, read below
    void credentialsNamedForTheRemoteGoThereAndNowhereElse() throws Exception {
        String spec = "provider=file&path=" + directory.resolve("password");
        try (Git bound = Git.cloneRepository().setURI(url)
                .setDirectory(directory.resolve("bound").toFile())
                .setCredentialsProvider(SeclumeGit.credentials("deploy", spec, url)).call()) {
            assertEquals("hello from the server\n", Files.readString(
                    directory.resolve("bound").resolve("README")).replace("\r\n", "\n"));
        }
        String elsewhere = url.replaceFirst("localhost:\\d+", "git.attacker.example:443");
        TransportException refused = assertThrows(TransportException.class,
                () -> Git.cloneRepository().setURI(url)
                        .setDirectory(directory.resolve("elsewhere").toFile())
                        .setCredentialsProvider(SeclumeGit.credentials("deploy", spec, elsewhere))
                        .call().close());
        assertTrue(refused.getMessage().toLowerCase().contains("auth")
                || refused.getMessage().contains("401"), refused.getMessage());
    }

    @Test
    void aRemoteIsNamedByItsHostAndPort() {
        assertEquals("git.example.com:443", SeclumeGit.server("https://Git.Example.com/team/app.git"));
        assertEquals("git.example.com:8443", SeclumeGit.server("https://git.example.com:8443/a.git"));
        assertEquals("[::1]:443", SeclumeGit.server("https://[::1]/a.git"));
        assertThrows(IllegalArgumentException.class,
                () -> SeclumeGit.server("http://git.example.com/a.git"));
        assertThrows(IllegalArgumentException.class, () -> SeclumeGit.server("not a url"));
    }

    /** A credentials provider naming no remote went to whichever server asked first: refused. */
    @Test
    @SuppressWarnings("removal")
    void credentialsThatNameNoRemoteAreRefused() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SeclumeGit.credentials("deploy", "provider=file&path=/x"));
        assertTrue(refused.getMessage().contains("names no remote"), refused.getMessage());
    }

    @Test
    void thePasswordIsNotOnTheHeap() throws Exception {
        try (Git git = cloneInto("heap", "password")) {
            git.fetch().setCredentialsProvider(SeclumeGit.credentials("deploy",
                    "provider=file&path=" + directory.resolve("password"), url)).call();
        }
        NoSecretInHeap.assertAbsent(directory.resolve("password"));
        String leaked = Files.readString(directory.resolve("password")); // the control
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(directory.resolve("password")));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(leaked);
    }
}
