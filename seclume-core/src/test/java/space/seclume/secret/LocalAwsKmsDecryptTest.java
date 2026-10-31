package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.field.EncryptedColumn;
import space.seclume.field.FieldKeys;

/**
 * {@code provider=kms-decrypt&kms=aws-kms} against an AWS KMS emulator (moto,
 * started by CI's brokers job with {@code kms_fixture.py}): a data key made by
 * {@code Encrypt} under a real key ARN, opened by {@code Decrypt} with a
 * SigV4-signed request, is the key that was encrypted - and keys a field
 * encryption ring. A ciphertext of another key is refused by the service.
 */
@Timeout(120)
class LocalAwsKmsDecryptTest {

    private static String arn;
    private static String ciphertext;
    private static byte[] expected;

    @TempDir
    static Path directory;

    @BeforeAll
    static void needsTheEmulator() throws IOException {
        Path keyArn = find(".local-kms-key-arn");
        Path blob = find(".local-kms-ciphertext");
        Path control = find(".local-kms-expected");
        assumeTrue(keyArn != null && blob != null && control != null,
                "no AWS KMS emulator fixture files");
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress("127.0.0.1", 4443), 2000);
        } catch (IOException e) {
            assumeTrue(false, "no AWS KMS emulator on 127.0.0.1:4443");
        }
        arn = Files.readString(keyArn).trim();
        ciphertext = Files.readString(blob).trim();
        expected = Base64.getDecoder().decode(Files.readString(control).trim());
    }

    private static Path find(String name) {
        for (Path candidate : List.of(Path.of(name), Path.of("..", name))) {
            if (Files.isReadable(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static Map<String, String> settings(String blob) throws IOException {
        Path secret = Files.writeString(directory.resolve("aws-secret"),
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "kms-decrypt");
        settings.put("kms", "aws-kms");
        settings.put("key", arn);
        settings.put("region", "eu-central-1");
        settings.put("endpoint", "https://127.0.0.1:4443");
        settings.put("verify", "false");
        settings.put("ciphertext", blob);
        settings.put("access-key-id", "AKIDEXAMPLE");
        settings.put("key-provider", "file");
        settings.put("key-path", secret.toString());
        return settings;
    }

    @Test
    void theDataKeyComesBackAsItWasEncrypted() throws IOException {
        try (SecretProvider provider = SecretProviders.of(settings(ciphertext));
             Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            assertArrayEquals(expected, target.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void itKeysAFieldRing() throws IOException {
        try (FieldKeys keys = FieldKeys.builder()
                .key(1, SecretProviders.of(settings(ciphertext))).build()) {
            EncryptedColumn column = keys.column("t.c", EncryptedColumn.Mode.DETERMINISTIC);
            assertTrue(column.encrypt(MemorySegment.ofArray(new byte[] {1})).length > 0);
        }
    }

    @Test
    void aCiphertextThatIsNotOneIsRefusedByTheService() throws IOException {
        byte[] bytes = Base64.getDecoder().decode(ciphertext);
        bytes[bytes.length / 2] ^= 0x10;
        Map<String, String> altered = settings(Base64.getEncoder().encodeToString(bytes));
        try (SecretProvider provider = SecretProviders.of(altered);
             Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            SecretUnavailableException e = assertThrows(SecretUnavailableException.class,
                    () -> provider.writeSecret(target));
            assertTrue(e.getMessage().contains("AWS KMS"), e.getMessage());
        }
    }
}
