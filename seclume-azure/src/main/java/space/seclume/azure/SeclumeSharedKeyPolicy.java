package space.seclume.azure;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import com.azure.core.http.HttpHeader;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpPipelineCallContext;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.policy.HttpPipelineSyncPolicy;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;
import space.seclume.internal.AwsSigV4;
import space.seclume.internal.Base64Off;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Azure Storage's Shared Key signature, with the account key in native memory.
 *
 * <p>The Azure SDK's {@code StorageSharedKeyCredential} keeps the account key
 * as a {@code String} and signs with {@code javax.crypto.Mac} - the key to the
 * whole storage account on the heap for as long as the client lives. This
 * policy takes the client's place for signing: for each request it reads the
 * key (base64, as the portal shows it) from the secret provider, decodes it
 * into native memory, computes {@code HMAC-SHA256} over the string to sign and
 * wipes both. What becomes a {@code String} is the {@code Authorization}
 * header, whose signature is public.
 *
 * <p>The string to sign follows the SDK's own credential - a test compares the
 * two headers request by request.
 */
final class SeclumeSharedKeyPolicy extends HttpPipelineSyncPolicy {

    /** Room for a base64 account key: 64 bytes of key, 88 characters. */
    private static final int KEY_ROOM = 512;

    private final String account;
    private final SecretProvider key;

    SeclumeSharedKeyPolicy(String account, SecretProvider key) {
        this.account = account;
        this.key = key;
    }

    @Override
    protected void beforeSendingRequest(HttpPipelineCallContext context) {
        HttpRequest request = context.getHttpRequest();
        String contentLength = request.getHeaders().getValue(HttpHeaderName.CONTENT_LENGTH);
        if (contentLength == null && request.getBodyAsBinaryData() != null
                && request.getBodyAsBinaryData().getLength() != null) {
            contentLength = String.valueOf(request.getBodyAsBinaryData().getLength());
        }
        request.setHeader(HttpHeaderName.AUTHORIZATION, authorization(request.getUrl(),
                request.getHttpMethod().name(), request.getHeaders(), contentLength));
        URL url = request.getUrl();
        space.seclume.jfr.Observed.secretUse("azure-storage", url.getHost() + ":"
                + (url.getPort() < 0 ? url.getDefaultPort() : url.getPort()), "shared-key");
    }

    /** {@code SharedKey account:signature} for this request. */
    String authorization(URL url, String method, HttpHeaders headers, String contentLength) {
        String toSign = stringToSign(url, method, headers, contentLength);
        return "SharedKey " + account + ":" + sign(toSign);
    }

    String stringToSign(URL url, String method, HttpHeaders headers, String contentLength) {
        String length = contentLength == null || contentLength.equals("0") ? "" : contentLength;
        String date = headers.getValue(HttpHeaderName.fromString("x-ms-date")) != null ? "" : value(headers, "Date");
        return method + "\n"
                + value(headers, "Content-Encoding") + "\n"
                + value(headers, "Content-Language") + "\n"
                + length + "\n"
                + value(headers, "Content-MD5") + "\n"
                + value(headers, "Content-Type") + "\n"
                + date + "\n"
                + value(headers, "If-Modified-Since") + "\n"
                + value(headers, "If-Match") + "\n"
                + value(headers, "If-None-Match") + "\n"
                + value(headers, "If-Unmodified-Since") + "\n"
                + value(headers, "Range") + "\n"
                + canonicalHeaders(headers)
                + canonicalResource(url);
    }

    private static String value(HttpHeaders headers, String name) {
        String value = headers.getValue(HttpHeaderName.fromString(name));
        return value == null ? "" : value;
    }

    private static String canonicalHeaders(HttpHeaders headers) {
        TreeMap<String, String> msHeaders = new TreeMap<>();
        for (HttpHeader header : headers) {
            String name = header.getName().toLowerCase(Locale.ROOT);
            if (name.startsWith("x-ms-") && header.getValue() != null) {
                msHeaders.put(name, header.getValue());
            }
        }
        StringBuilder text = new StringBuilder();
        msHeaders.forEach((name, value) -> text.append(name).append(':').append(value)
                .append('\n'));
        return text.toString();
    }

    private String canonicalResource(URL url) {
        String path = url.getPath() == null || url.getPath().isEmpty() ? "/" : url.getPath();
        StringBuilder text = new StringBuilder("/").append(account).append(path);
        if (url.getQuery() != null) {
            TreeMap<String, List<String>> parameters = new TreeMap<>();
            for (String pair : url.getQuery().split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int equals = pair.indexOf('=');
                String name = decode(equals < 0 ? pair : pair.substring(0, equals))
                        .toLowerCase(Locale.ROOT);
                String value = equals < 0 ? "" : decode(pair.substring(equals + 1));
                parameters.computeIfAbsent(name, n -> new ArrayList<>()).add(value);
            }
            for (Map.Entry<String, List<String>> parameter : parameters.entrySet()) {
                List<String> values = parameter.getValue();
                values.sort(null);
                text.append('\n').append(parameter.getKey()).append(':')
                        .append(String.join(",", values));
            }
        }
        return text.toString();
    }

    private static String decode(String text) {
        return URLDecoder.decode(text, StandardCharsets.UTF_8);
    }

    /** base64(HMAC-SHA256(base64-decoded key, text)) - the key decoded and used off the heap. */
    private String sign(String text) {
        try (SecretScope encoded = SecretScope.fromProvider(key);
             SecretScope decoded = SecretScope.allocate(KEY_ROOM);
             Arena arena = Arena.ofConfined()) {
            int length = Base64Off.decode(encoded.segment(), 0, encoded.length(),
                    decoded.segment(), 0);
            if (length == 0) {
                throw new IllegalStateException("the storage account key is empty");
            }
            MemorySegment message = arena.allocate(text.length() * 3L + 1);
            int written = AwsSigV4.writeAscii(message, text);
            try (Hmac mac = new Hmac(HashAlgorithm.SHA_256, decoded.segment(), 0, length)) {
                mac.update(message, 0, written);
                MemorySegment out = arena.allocate(mac.macLength());
                mac.doFinal(out, 0);
                return java.util.Base64.getEncoder().encodeToString( // seclume-allow: the signature, sent in the header - public
                        out.toArray(ValueLayout.JAVA_BYTE));
            }
        }
    }
}
