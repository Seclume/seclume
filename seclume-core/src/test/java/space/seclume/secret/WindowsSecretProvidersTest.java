package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.Segments;

/**
 * The platform test for Windows: create the blob with the built-in tools, read
 * it with the provider, and check whether the native buffer was zeroed before
 * {@code LocalFree}
 * genullt wurde.
 *
 * <p>Runs only on Windows and only as the user who created the blob - DPAPI in
 * the CurrentUser scope is meant for exactly that.
 */
@EnabledOnOs(OS.WINDOWS)
class WindowsSecretProvidersTest {

    @TempDir
    Path directory;

    @Test
    void readsADpapiBlob() throws Exception {
        Path blob = directory.resolve("db.dpapi");
        protect("test-password-42", blob, null);

        try (SecretScope scope = SecretScope.fromProvider(
                new DpapiSecretProvider(blob, 256))) {
            assertEquals("test-password-42",
                    new String(Segments.toBytes(scope.secret()), StandardCharsets.UTF_8));
        }
        assertTrue(DpapiSecretProvider.lastBufferWasZeroed,
                "the LocalAlloc buffer must be zeroed before LocalFree");
    }

    /** Non-ASCII has to survive the UTF-16 to UTF-8 conversion. */
    @Test
    void readsANonAsciiSecret() throws Exception {
        Path blob = directory.resolve("umlaut.dpapi");
        String secret = "Grüße-€-😀";
        protect(secret, blob, null);

        try (SecretScope scope = SecretScope.fromProvider(new DpapiSecretProvider(blob, 256))) {
            assertEquals(secret,
                    new String(Segments.toBytes(scope.secret()), StandardCharsets.UTF_8));
        }
    }

    /** Encrypted with entropy, read without it: has to fail. */
    @Test
    void entropyIsASecondFactor() throws Exception {
        Path blob = directory.resolve("entropy.dpapi");
        protect("with-entropy", blob, "myapp/reporting");

        try (SecretScope scope = SecretScope.fromProvider(
                new DpapiSecretProvider(blob, "myapp/reporting", 256))) {
            assertEquals("with-entropy",
                    new String(Segments.toBytes(scope.secret()), StandardCharsets.UTF_8));
        }
        assertThrows(SecretUnavailableException.class,
                () -> SecretScope.fromProvider(new DpapiSecretProvider(blob, 256)).close());
    }

    @Test
    void reportsAGarbageBlob() throws IOException {
        Path blob = directory.resolve("garbage.dpapi");
        Files.writeString(blob, "not hex at all", StandardCharsets.US_ASCII);
        assertThrows(SecretUnavailableException.class,
                () -> SecretScope.fromProvider(new DpapiSecretProvider(blob, 256)).close());
    }

    /** The FIFO route does not exist on Windows - and says so. */
    @Test
    void processProviderRefusesOnWindows() {
        SecretUnavailableException failure = assertThrows(SecretUnavailableException.class,
                () -> SecretScope.fromProvider(
                        new ProcessSecretProvider(List.of("cmd", "/c", "echo x"), 64)).close());
        assertTrue(failure.getMessage().contains("Unix only"));
    }

    /**
     * Creates the blob the way an administrator would:
     * {@code ConvertFrom-SecureString} schreibt DPAPI-Hex.
     */
    private static void protect(String secret, Path target, String entropy) throws Exception {
        String script;
        if (entropy == null) {
            script = "$s = ConvertTo-SecureString -String '" + secret + "' -AsPlainText -Force; "
                    + "ConvertFrom-SecureString -SecureString $s | Out-File -Encoding ascii '"
                    + target + "'";
        } else {
            // ConvertFrom-SecureString cannot do entropy - hence going
            // straight through the API, with the same output format (hex).
            script = "Add-Type -AssemblyName System.Security; "
                    + "$b = [Text.Encoding]::Unicode.GetBytes('" + secret + "'); "
                    + "$e = [Text.Encoding]::Unicode.GetBytes('" + entropy + "'); "
                    + "$p = [Security.Cryptography.ProtectedData]::Protect($b, $e, "
                    + "[Security.Cryptography.DataProtectionScope]::CurrentUser); "
                    + "($p | ForEach-Object { $_.ToString('x2') }) -join '' | "
                    + "Out-File -Encoding ascii '" + target + "'";
        }
        Process process = new ProcessBuilder("powershell", "-NoProfile", "-NonInteractive",
                "-Command", script)
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .start();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "powershell did not finish");
        assertEquals(0, process.exitValue(), "powershell failed");
        assertTrue(Files.size(target) > 0, "no blob was written");
    }
}
