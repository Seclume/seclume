package space.seclume.azure;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import com.azure.core.http.policy.HttpPipelinePolicy;

import space.seclume.secret.SecretProviders;

/**
 * Azure Storage clients that sign with the account key off the heap.
 *
 * <pre>
 * HttpPipelinePolicy signing = SeclumeAzure.sharedKey(
 *         "account=mystorage&amp;provider=file&amp;path=/run/secrets/storage-key");
 *
 * BlobServiceClient blobs = new BlobServiceClientBuilder()
 *         .endpoint("https://mystorage.blob.core.windows.net")
 *         .addPolicy(signing)                    // instead of .credential(new StorageSharedKeyCredential(...))
 *         .buildClient();
 * QueueServiceClient queues = new QueueServiceClientBuilder()
 *         .endpoint("https://mystorage.queue.core.windows.net").addPolicy(signing).buildClient();
 * </pre>
 *
 * <p>Blob, Queue, File and Data Lake sign with Shared Key the same way; the
 * policy is given to the client builder in place of a credential. The account
 * name is public and given as it is; the key is named by its secret provider,
 * as in a seclume JDBC URL, and read for each request.
 */
public final class SeclumeAzure {

    private SeclumeAzure() {
    }

    /** A pipeline policy that signs each request with the account's Shared Key. */
    public static HttpPipelinePolicy sharedKey(String spec) {
        Map<String, String> options = new LinkedHashMap<>();
        for (String pair : (spec.startsWith("?") ? spec.substring(1) : spec).split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                options.put(URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
        }
        String account = options.remove("account");
        if (account == null || account.isBlank()) {
            throw new IllegalArgumentException("account= is missing - the storage account's "
                    + "name");
        }
        if (options.containsKey("account-key") || options.containsKey("key")) {
            throw new IllegalArgumentException("the account key is not given here: name it with "
                    + "provider= (provider=file&path=..., provider=azure-key-vault&...)");
        }
        if (!options.containsKey("provider")) {
            throw new IllegalArgumentException("no account key named: add provider= and its "
                    + "options, e.g. provider=file&path=/run/secrets/storage-key");
        }
        return new SeclumeSharedKeyPolicy(account.trim(), SecretProviders.of(options));
    }
}
