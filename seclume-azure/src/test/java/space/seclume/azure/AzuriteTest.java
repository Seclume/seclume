package space.seclume.azure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.lang.ref.Reference;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.azure.core.util.BinaryData;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.BlobItem;
import com.azure.storage.blob.models.BlobStorageException;
import com.azure.storage.queue.QueueClient;
import com.azure.storage.queue.QueueServiceClientBuilder;

import space.seclume.tck.NoSecretInHeap;

/**
 * Blob and Queue against Azurite - Microsoft's storage emulator - in a process
 * of its own, started by a shell that reads the account key from its file:
 * the key is in Azurite and in native memory here, never on this heap.
 *
 * <p>Needs Azurite: {@code npm install -g azurite}, or its executable in
 * {@code SECLUME_AZURITE}. Skipped without it.
 */
class AzuriteTest {

    @TempDir
    static Path directory;

    static Process azurite;
    static int blobPort;
    static int queuePort;

    @BeforeAll
    static void start() throws Exception {
        String executable = System.getenv().getOrDefault("SECLUME_AZURITE", "azurite");
        Process probe = new ProcessBuilder("/bin/sh", "-c", "command -v " + executable)
                .start();
        assumeTrue(probe.waitFor() == 0, "Azurite is not installed");
        blobPort = freePort();
        queuePort = freePort();
        Path script = directory.resolve("azurite.sh");
        Files.writeString(script, String.join("\n",
                "set -e", "cd '" + directory + "'",
                "head -c 64 /dev/urandom | base64 | tr -d '\\n' > key",
                "base64 -d key > key.bin",
                "head -c 64 /dev/urandom | base64 | tr -d '\\n' > wrong-key",
                "export AZURITE_ACCOUNTS=\"acct:$(cat key)\"",
                "exec " + executable + " --silent --location '" + directory.resolve("data")
                        + "' --blobHost 127.0.0.1 --blobPort " + blobPort
                        + " --queueHost 127.0.0.1 --queuePort " + queuePort
                        + " --tableHost 127.0.0.1 --tablePort " + freePort()
                        + " --skipApiVersionCheck --loose", ""));
        azurite = new ProcessBuilder("/bin/sh", script.toString()).redirectErrorStream(true)
                .redirectOutput(directory.resolve("azurite.log").toFile()).start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (true) {
            assertTrue(azurite.isAlive(), "Azurite ended: see " + directory.resolve("azurite.log"));
            assertTrue(System.nanoTime() < deadline, "Azurite did not start");
            try {
                new Socket("127.0.0.1", queuePort).close();
                new Socket("127.0.0.1", blobPort).close();
                break;
            } catch (java.io.IOException notYet) {
                Thread.sleep(100);
            }
        }
    }

    @AfterAll
    static void stop() throws InterruptedException {
        if (azurite != null) {
            azurite.destroy();
            if (!azurite.waitFor(20, TimeUnit.SECONDS)) {
                azurite.destroyForcibly().waitFor(10, TimeUnit.SECONDS);
            }
        }
    }

    private static int freePort() throws java.io.IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static String spec(String keyFile) {
        return "account=acct&provider=file&path=" + directory.resolve(keyFile);
    }

    private static BlobServiceClient blobs(String keyFile) {
        return new BlobServiceClientBuilder().endpoint("http://127.0.0.1:" + blobPort + "/acct")
                .addPolicy(SeclumeAzure.sharedKey(spec(keyFile))).buildClient();
    }

    private static void exercise(String name) {
        BlobContainerClient container = blobs("key").createBlobContainerIfNotExists(name);
        container.getBlobClient("reports/ü q3.txt").upload(BinaryData.fromString("numbers"),
                true);
        assertEquals("numbers", container.getBlobClient("reports/ü q3.txt").downloadContent()
                .toString());
        List<String> names = container.listBlobs().stream().map(BlobItem::getName).toList();
        assertEquals(List.of("reports/ü q3.txt"), names);

        QueueClient queue = new QueueServiceClientBuilder()
                .endpoint("http://127.0.0.1:" + queuePort + "/acct")
                .addPolicy(SeclumeAzure.sharedKey(spec("key"))).buildClient()
                .getQueueClient(name);
        queue.createIfNotExists();
        queue.sendMessage("order 42");
        assertEquals("order 42", queue.receiveMessage().getBody().toString());
    }

    /** Each signed request is a SecretUse event: azure-storage, shared-key. */
    @Test
    void eachSignedRequestIsRecorded() throws Exception {
        var events = space.seclume.tck.Recorded.during(() -> exercise("events"),
                "space.seclume.SecretUse");
        assertTrue(!events.isEmpty(), "no request was recorded");
        assertEquals("azure-storage", events.get(0).getString("kind"));
        assertEquals("shared-key", events.get(0).getString("mechanism"));
    }

    @Test
    void blobAndQueue() {
        exercise("reports");
    }

    @Test
    void aWrongKeyIsRefused() {
        BlobStorageException refused = assertThrows(BlobStorageException.class,
                () -> blobs("wrong-key").createBlobContainerIfNotExists("nope"));
        assertEquals(403, refused.getStatusCode());
    }

    @Test
    void theAccountKeyIsNotOnTheHeap() throws Exception {
        exercise("heap");
        NoSecretInHeap.assertAbsent(directory.resolve("key"));
        NoSecretInHeap.assertAbsent(directory.resolve("key.bin"));
        String leaked = Files.readString(directory.resolve("key")); // the control
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(directory.resolve("key")));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(leaked);
    }
}
