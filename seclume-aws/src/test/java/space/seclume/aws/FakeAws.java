package space.seclume.aws;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4FamilyHttpSigner;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignRequest;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;

/**
 * Just enough of S3 (path style) and SQS (JSON) to run their clients against:
 * objects in a map, messages in a list. With a secret, every request's
 * signature is checked by signing it again with the SDK's own signer; a
 * wrong one gets a 403 as from AWS.
 */
final class FakeAws implements AutoCloseable {

    private static final Pattern AUTHORIZATION = Pattern.compile("AWS4-HMAC-SHA256 "
            + "Credential=([^/]+)/(\\d{8})/([^/]+)/([^/]+)/aws4_request, "
            + "SignedHeaders=([^,]+), Signature=([0-9a-f]{64})");

    final Map<String, byte[]> objects = new ConcurrentHashMap<>();
    final List<String> messages = new CopyOnWriteArrayList<>();
    final List<String> rejected = new CopyOnWriteArrayList<>();
    private final HttpServer server;
    private final Supplier<String> secret;

    /** @param secret the key to check signatures with, or {@code null} for none */
    FakeAws(Supplier<String> secret) throws IOException {
        this.secret = secret;
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    URI endpoint() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            byte[] body = exchange.getRequestBody().readAllBytes();
            if (secret != null) {
                String problem = check(exchange, body);
                if (problem != null) {
                    rejected.add(problem);
                    respond(exchange, 403, "<Error><Code>SignatureDoesNotMatch</Code>"
                            + "<Message>" + problem + "</Message></Error>", "application/xml");
                    return;
                }
            }
            String target = exchange.getRequestHeaders().getFirst("X-Amz-Target");
            if (target != null) {
                sqs(exchange, target, body);
            } else {
                s3(exchange, body);
            }
        }
    }

    private void sqs(HttpExchange exchange, String target, byte[] body) throws IOException {
        String json = new String(body, StandardCharsets.UTF_8);
        Matcher text = Pattern.compile("\"MessageBody\":\"((?:[^\"\\\\]|\\\\.)*)\"")
                .matcher(json);
        if (!target.endsWith("SendMessage") || !text.find()) {
            respond(exchange, 400, "{}", "application/x-amz-json-1.0");
            return;
        }
        String message = text.group(1);
        messages.add(message);
        respond(exchange, 200, "{\"MessageId\":\"m-" + messages.size()
                + "\",\"MD5OfMessageBody\":\"" + md5(message) + "\"}",
                "application/x-amz-json-1.0");
    }

    private void s3(HttpExchange exchange, byte[] body) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String query = exchange.getRequestURI().getRawQuery();
        String method = exchange.getRequestMethod();
        String[] parts = path.substring(1).split("/", 2);
        if (parts.length == 1 && method.equals("GET")) {
            String bucket = parts[0];
            StringBuilder xml = new StringBuilder("<ListBucketResult xmlns=\"http://s3.amazonaws"
                    + ".com/doc/2006-03-01/\"><Name>" + bucket + "</Name>");
            int count = 0;
            for (String key : new java.util.TreeSet<>(objects.keySet())) {
                if (key.startsWith(bucket + "/")) {
                    count++;
                    xml.append("<Contents><Key>").append(key.substring(bucket.length() + 1))
                            .append("</Key><Size>").append(objects.get(key).length)
                            .append("</Size></Contents>");
                }
            }
            xml.append("<KeyCount>").append(count).append("</KeyCount></ListBucketResult>");
            respond(exchange, 200, xml.toString(), "application/xml");
            return;
        }
        String key = parts[0] + "/" + (parts.length > 1 ? parts[1] : "");
        switch (method) {
            case "PUT" -> {
                objects.put(key, body);
                exchange.getResponseHeaders().add("ETag", "\"" + md5(body) + "\"");
                exchange.sendResponseHeaders(200, -1);
            }
            case "GET" -> {
                byte[] object = objects.get(key);
                if (object == null) {
                    respond(exchange, 404, "<Error><Code>NoSuchKey</Code></Error>",
                            "application/xml");
                } else {
                    exchange.getResponseHeaders().add("ETag", "\"" + md5(object) + "\"");
                    exchange.sendResponseHeaders(200, object.length);
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(object);
                    }
                }
            }
            case "DELETE" -> {
                objects.remove(key);
                exchange.sendResponseHeaders(204, -1);
            }
            default -> respond(exchange, 405, "", "text/plain");
        }
        if (query != null && query.contains("never")) {
            throw new IllegalStateException(query);
        }
    }

    /** Signs the request again with the SDK's signer; {@code null} when it matches. */
    private String check(HttpExchange exchange, byte[] body) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Matcher parsed = authorization == null ? null : AUTHORIZATION.matcher(authorization);
        if (parsed == null || !parsed.matches()) {
            return "no SigV4 authorization: " + authorization;
        }
        String service = parsed.group(4);
        String host = exchange.getRequestHeaders().getFirst("Host");
        URI uri = URI.create("http://" + host + exchange.getRequestURI().getRawPath()
                + (exchange.getRequestURI().getRawQuery() == null ? ""
                        : "?" + exchange.getRequestURI().getRawQuery()));
        SdkHttpRequest.Builder request = SdkHttpRequest.builder()
                .method(SdkHttpMethod.fromValue(exchange.getRequestMethod())).uri(uri);
        for (String name : parsed.group(5).split(";")) {
            if (!name.equals("host")) {
                request.putHeader(name, exchange.getRequestHeaders().get(name));
            }
        }
        String stamp = exchange.getRequestHeaders().getFirst("X-Amz-Date");
        Clock clock = Clock.fixed(LocalDateTime.parse(stamp,
                DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")).toInstant(ZoneOffset.UTC),
                ZoneOffset.UTC);
        boolean unsigned = "UNSIGNED-PAYLOAD".equals(
                exchange.getRequestHeaders().getFirst("x-amz-content-sha256"));
        SignRequest.Builder<AwsCredentialsIdentity> sign = SignRequest.builder(
                        AwsCredentialsIdentity.create(parsed.group(1), secret.get()))
                .request(request.build())
                .payload(ContentStreamProvider.fromByteArray(body))
                .putProperty(AwsV4HttpSigner.REGION_NAME, parsed.group(3))
                .putProperty(AwsV4FamilyHttpSigner.SERVICE_SIGNING_NAME, service)
                .putProperty(AwsV4FamilyHttpSigner.PAYLOAD_SIGNING_ENABLED, !unsigned)
                .putProperty(HttpSigner.SIGNING_CLOCK, clock);
        if (service.equals("s3")) {
            sign.putProperty(AwsV4FamilyHttpSigner.DOUBLE_URL_ENCODE, false)
                    .putProperty(AwsV4FamilyHttpSigner.NORMALIZE_PATH, false);
        }
        String expected = AwsV4HttpSigner.create().sign(sign.build()).request()
                .firstMatchingHeader("Authorization").orElse("");
        return expected.equals(authorization) ? null
                : exchange.getRequestMethod() + " " + uri + ": the signature does not match";
    }

    private static void respond(HttpExchange exchange, int status, String text, String type)
            throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", type);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
    }

    static String md5(String text) {
        return md5(text.getBytes(StandardCharsets.UTF_8));
    }

    static String md5(byte[] bytes) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("MD5")
                    .digest(bytes));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }

    static Map<String, String> sorted(Map<String, String> map) {
        return new TreeMap<>(map);
    }
}
