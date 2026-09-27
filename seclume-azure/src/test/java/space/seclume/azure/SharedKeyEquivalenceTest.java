package space.seclume.azure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.storage.common.StorageSharedKeyCredential;

import space.seclume.secret.SecretProviders;

/**
 * (Every case carries a Content-Length, as the SDK's pipeline sets it: without
 * one, the SDK's credential signs the text {@code null} where the length goes.)
 *
 * <p>Request by request, the Authorization header is the one the Azure SDK's own
 * credential makes with the same key - which, as the reference, holds the key
 * as a String; this class runs in a JVM of its own.
 */
class SharedKeyEquivalenceTest {

    @TempDir
    Path directory;

    private record Case(String method, String url, Map<String, String> headers) {
    }

    private static List<Case> cases() {
        return List.of(
                new Case("GET", "https://acct.blob.core.windows.net/?comp=list&prefix=a%20b"
                        + "&include=metadata", Map.of("x-ms-date", "Sun, 27 Sep 2026 12:00:00 GMT",
                        "x-ms-version", "2025-11-05", "Content-Length", "0")),
                new Case("PUT", "https://acct.blob.core.windows.net/reports/2026/%C3%BC%20q3.txt",
                        Map.of("x-ms-date", "Sun, 27 Sep 2026 12:00:00 GMT", "x-ms-version",
                                "2025-11-05", "x-ms-blob-type", "BlockBlob", "Content-Type",
                                "text/plain", "Content-Length", "17", "x-ms-meta-Owner",
                                "  finance  ")),
                new Case("GET", "https://acct.blob.core.windows.net/reports/q3.txt?snapshot=x",
                        Map.of("x-ms-date", "Sun, 27 Sep 2026 12:00:00 GMT", "x-ms-version",
                                "2025-11-05", "Range", "bytes=0-99", "If-None-Match", "\"etag\"",
                                "Content-Length", "0")),
                new Case("DELETE", "https://acct.queue.core.windows.net/orders/messages/1"
                        + "?popreceipt=abc%2Bdef&visibilitytimeout=30&Timeout=5",
                        Map.of("Date", "Sun, 27 Sep 2026 12:00:00 GMT", "x-ms-version",
                                "2025-11-05", "Content-Length", "0")),
                new Case("PUT", "https://acct.blob.core.windows.net/c?restype=container&comp=acl",
                        Map.of("x-ms-date", "Sun, 27 Sep 2026 12:00:00 GMT", "x-ms-version",
                                "2025-11-05", "Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==",
                                "Content-Language", "de", "Content-Encoding", "gzip",
                                "If-Modified-Since", "Sat, 26 Sep 2026 12:00:00 GMT",
                                "Content-Length", "120")));
    }

    @Test
    void signsAsTheSdkDoes() throws Exception {
        Path key = directory.resolve("key");
        Process process = new ProcessBuilder("/bin/sh", "-c",
                "head -c 64 /dev/urandom | base64 | tr -d '\\n' > '" + key + "'").start();
        assertEquals(0, process.waitFor());
        StorageSharedKeyCredential reference = new StorageSharedKeyCredential("acct",
                Files.readString(key));
        SeclumeSharedKeyPolicy ours = new SeclumeSharedKeyPolicy("acct",
                SecretProviders.of(Map.of("provider", "file", "path", key.toString())));
        for (Case c : cases()) {
            HttpHeaders headers = new HttpHeaders();
            c.headers().forEach((name, value) -> headers.set(HttpHeaderName.fromString(name),
                    value));
            URL url = URI.create(c.url()).toURL();
            assertEquals(reference.generateAuthorizationHeader(url, c.method(), headers, false),
                    ours.authorization(url, c.method(), headers,
                            headers.getValue(HttpHeaderName.CONTENT_LENGTH)),
                    c.method() + " " + c.url());
        }
    }

    @Test
    void theKeyIsNamedNotGiven() {
        assertThrows(IllegalArgumentException.class, () -> SeclumeAzure.sharedKey(
                "account=a&account-key=abc&provider=file&path=/x"));
        assertThrows(IllegalArgumentException.class, () -> SeclumeAzure.sharedKey(
                "provider=file&path=/x"));
    }
}
