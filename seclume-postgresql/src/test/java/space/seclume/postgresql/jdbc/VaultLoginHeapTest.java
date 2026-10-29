package space.seclume.postgresql.jdbc;

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

import space.seclume.secret.SecretProviders;
import space.seclume.secret.VaultSecretProvider;
import space.seclume.tck.NoSecretInHeap;

/**
 * The claim itself: after a login to Vault - by JWT, and by AWS IAM - a
 * database credential read with the token it gave, and the lease and the
 * token revoked at the end, <b>none of the secrets is on this JVM's heap</b>:
 * not the JWT, the AWS secret key or session token that went into the login,
 * not the client token that came back and went into three requests, not the
 * password.
 *
 * <p>Here rather than beside {@code VaultLogin} in seclume-core: the heap
 * search is seclume-tck's, and the TCK is built on the core.
 *
 * <p>Vault is {@link FakeVaultLoginMain} in another JVM: a server in this one
 * would hold all three as strings and the search would find them there. With
 * a negative control: the client token read into a {@code String} on purpose
 * must be found.
 */
@Timeout(300)
class VaultLoginHeapTest {

    @Test
    void theJwtTheTokenAndThePasswordAreNotOnTheHeap() throws Exception {
        prove(directory -> Map.of(
                "auth-method", "jwt",
                "auth-role", "app",
                "jwt-provider", "file",
                "jwt-path", directory.resolve("jwt.txt").toString()),
                List.of("jwt.txt", "client-token.txt", "password.txt"));
    }

    /**
     * An AWS IAM login: the secret access key signs, the session token is
     * signed and sent, the signature goes to Vault inside base64'd headers -
     * and none of them, nor the token Vault gives back, nor the password, is
     * on the heap. The fake Vault checks the signature as AWS would, so a
     * login that gets through was signed right.
     */
    @Test
    void theAwsKeyTheSessionTokenTheTokenAndThePasswordAreNotOnTheHeap() throws Exception {
        prove(directory -> Map.of(
                "auth-method", "aws",
                "auth-role", "app",
                "aws-access-key-id", "AKIASECLUMEHEAPTEST1",
                "aws-key-provider", "file",
                "aws-key-path", directory.resolve("aws-key.txt").toString(),
                "aws-session-token-provider", "file",
                "aws-session-token-path", directory.resolve("aws-session.txt").toString()),
                List.of("aws-key.txt", "aws-session.txt", "client-token.txt", "password.txt"));
    }

    /** The settings of one login method, given the directory the fake Vault wrote into. */
    private interface Login {
        Map<String, String> settings(Path directory);
    }

    @SuppressWarnings("try")
    private static void prove(Login login, List<String> secrets) throws Exception {
        Assumptions.assumeTrue(Files.isExecutable(Path.of(System.getProperty("java.home"),
                "bin", System.getProperty("os.name").startsWith("Windows") ? "keytool.exe"
                        : "keytool")), "no keytool in this JDK");
        Path directory = Files.createTempDirectory("seclume-vault-login-proof");
        Process server = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED",
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

            Map<String, String> settings = new java.util.LinkedHashMap<>(Map.of(
                    "provider", "vault",
                    "address", "https://127.0.0.1:" + port,
                    "path", "database/creds/app",
                    "verify", "false"));            // a CA made for this run in the other JVM
            settings.putAll(login.settings(directory));
            VaultSecretProvider vault = (VaultSecretProvider) SecretProviders.of(settings);

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

            for (String secret : secrets) {
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
