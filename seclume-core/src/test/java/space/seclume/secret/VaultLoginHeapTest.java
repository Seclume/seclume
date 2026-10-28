package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.ref.Reference;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.tck.NoSecretInHeap;
import space.seclume.tls.TestCertificates;

/**
 * The claim itself: after a JWT login to Vault, a database credential read
 * with the token it gave, and the lease and the token revoked at the end,
 * <b>none of the three secrets is on this JVM's heap</b> - not the JWT that
 * went into the login, not the client token that came back and went into
 * three requests, not the password.
 *
 * <p>Vault is {@link FakeVaultLoginMain} in another JVM: a server in this one
 * would hold all three as strings and the search would find them there. With
 * a negative control: the client token read into a {@code String} on purpose
 * must be found.
 */
@Timeout(300)
class VaultLoginHeapTest {

    @Test
    @SuppressWarnings("try")
    void theJwtTheTokenAndThePasswordAreNotOnTheHeap() throws Exception {
        Assumptions.assumeTrue(TestCertificates.available(), "no keytool in this JDK");
        Path directory = Files.createTempDirectory("seclume-vault-login-proof");
        Process server = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED",
                "--add-exports", "java.base/sun.security.tools.keytool=ALL-UNNAMED",
                "-cp", System.getProperty("java.class.path"),
                FakeVaultLoginMain.class.getName(),
                directory.toString()))
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        try (BufferedReader out = new BufferedReader(new InputStreamReader(
                server.getInputStream(), StandardCharsets.UTF_8))) {
            String ready = out.readLine();
            assertTrue(ready != null && ready.startsWith("READY "), "Vault said: " + ready);
            String port = ready.substring("READY ".length()).trim();

            VaultSecretProvider vault = (VaultSecretProvider) SecretProviders.of(Map.of(
                    "provider", "vault",
                    "address", "https://127.0.0.1:" + port,
                    "path", "database/creds/app",
                    "verify", "false",              // a CA made for this run in the other JVM
                    "auth-method", "jwt",
                    "auth-role", "app",
                    "jwt-provider", "file",
                    "jwt-path", directory.resolve("jwt.txt").toString()));

            assertEquals("v-app-1", vault.currentUser());
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment password = arena.allocate(vault.maxSecretLength());
                for (int connection = 0; connection < 5; connection++) {
                    int length = vault.writeSecret(password);
                    assertTrue(sameAsFile(password, length, directory.resolve("password.txt")),
                            "not the password Vault handed out");
                }
                password.fill((byte) 0);
            }
            vault.close();

            server.getOutputStream().close();
            assertTrue(server.waitFor(60, TimeUnit.SECONDS), "the fake Vault did not end");
            assertEquals("DONE logins=1 renewals=0 fetches=1 lease-revocations=1 "
                    + "token-revocations=1", out.readLine());

            for (String secret : List.of("jwt.txt", "client-token.txt", "password.txt")) {
                NoSecretInHeap.assertAbsent(directory.resolve(secret));
            }

            // Negative control: the same search finds a token that is a String.
            String leaked = Files.readString(directory.resolve("client-token.txt")); // seclume-allow: the control, put on the heap on purpose
            AssertionError found = assertThrows(AssertionError.class,
                    () -> NoSecretInHeap.assertAbsent(directory.resolve("client-token.txt")));
            assertTrue(found.getMessage().contains("the secret is on the heap"),
                    found.getMessage());
            Reference.reachabilityFence(leaked);
        } finally {
            server.destroyForcibly();
            try (var files = Files.list(directory)) {
                for (Path file : files.toList()) {
                    Files.deleteIfExists(file);
                }
            }
            Files.deleteIfExists(directory);
        }
    }

    /**
     * Compares without a heap copy of either side: the file is mapped, and a
     * mapped buffer lives outside the heap.
     */
    private static boolean sameAsFile(MemorySegment value, int length, Path file)
            throws Exception {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            if (channel.size() != length) {
                return false;
            }
            MappedByteBuffer mapped = channel.map(FileChannel.MapMode.READ_ONLY, 0, length);
            for (int i = 0; i < length; i++) {
                if (mapped.get(i) != value.get(ValueLayout.JAVA_BYTE, i)) {
                    return false;
                }
            }
            return true;
        }
    }
}
