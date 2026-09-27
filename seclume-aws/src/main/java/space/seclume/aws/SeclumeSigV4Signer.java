package space.seclume.aws;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URI;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;

import software.amazon.awssdk.checksums.SdkChecksum;
import software.amazon.awssdk.checksums.spi.ChecksumAlgorithm;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4FamilyHttpSigner;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.AsyncSignRequest;
import software.amazon.awssdk.http.auth.spi.signer.AsyncSignedRequest;
import software.amazon.awssdk.http.auth.spi.signer.BaseSignRequest;
import software.amazon.awssdk.http.auth.spi.signer.HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignRequest;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;
import software.amazon.awssdk.identity.spi.AwsSessionCredentialsIdentity;

import space.seclume.crypto.Digest;
import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.AwsSigV4;
import space.seclume.secret.SecretProvider;

/**
 * AWS Signature Version 4 in the request's header, as the SDK's own signer
 * makes it - except for where the secret key is.
 *
 * <p>The SDK's signer takes the key from an {@code AwsCredentialsIdentity},
 * as a {@code String}, and derives the signing key from it with
 * {@code javax.crypto.Mac}: the key on the heap for the life of the client.
 * This one ignores the identity's secret - it is a placeholder, and anything
 * else is refused - and reads the key from a secret provider into native
 * memory for each signature, through the four HMACs of the derivation, and
 * wipes it ({@link AwsSigV4}).
 *
 * <p>Everything else in a SigV4 signature is public and made here in plain
 * Java: the canonical request, the payload's SHA-256, the string to sign. The
 * canonical form follows the SDK's signer, and a test compares the two
 * signatures request by request.
 *
 * <p>Presigned URLs ({@code S3Presigner} on a client set up here) are signed
 * in the query string the same way. Not here: SigV4a (multi-region access
 * points) and the
 * chunked ({@code aws-chunked}) upload encoding - a body is signed in one
 * piece, or, where the SDK allows it over HTTPS, sent as
 * {@code UNSIGNED-PAYLOAD}; an S3 checksum goes into its header. An async
 * client's body is collected before it is signed.
 */
final class SeclumeSigV4Signer implements HttpSigner<AwsCredentialsIdentity> {

    static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyyMMdd");
    /** What the SDK's signer leaves out of a signature. */
    private static final Set<String> IGNORED = Set.of("connection", "x-amzn-trace-id",
            "user-agent", "expect", "authorization");

    private final String accessKeyId;
    private final SecretProvider secretKey;

    SeclumeSigV4Signer(String accessKeyId, SecretProvider secretKey) {
        this.accessKeyId = accessKeyId;
        this.secretKey = secretKey;
    }

    @Override
    public SignedRequest sign(SignRequest<? extends AwsCredentialsIdentity> request) {
        ContentStreamProvider payload = request.payload().orElse(null);
        SdkHttpRequest signed = signed(request, payload);
        return SignedRequest.builder().request(signed).payload(payload).build();
    }

    /**
     * An async client's body is a publisher. When it has to be hashed or
     * checksummed, it is collected first - request bodies of SQS, SNS or
     * DynamoDB are small - and signed as a synchronous one would be; S3 over
     * HTTPS sends its body unsigned, and nothing is collected there.
     */
    @Override
    public CompletableFuture<AsyncSignedRequest> signAsync(
            AsyncSignRequest<? extends AwsCredentialsIdentity> request) {
        boolean needsBody = request.payload().isPresent() && (signsPayload(request)
                || request.property(AwsV4FamilyHttpSigner.CHECKSUM_ALGORITHM) != null);
        if (!needsBody) {
            try {
                return CompletableFuture.completedFuture(AsyncSignedRequest.builder()
                        .request(signed(request, null))
                        .payload(request.payload().orElse(null)).build());
            } catch (RuntimeException e) {
                return CompletableFuture.failedFuture(e);
            }
        }
        return collect(request.payload().get()).thenApply(body -> AsyncSignedRequest.builder()
                .request(signed(request, ContentStreamProvider.fromByteArrayUnsafe(body)))
                .payload(software.amazon.awssdk.core.async.AsyncRequestBody.fromBytesUnsafe(body))
                .build());
    }

    /** The body, all of it - public, it is sent as it is. */
    private static CompletableFuture<byte[]> collect(
            org.reactivestreams.Publisher<java.nio.ByteBuffer> publisher) {
        CompletableFuture<byte[]> done = new CompletableFuture<>();
        publisher.subscribe(new org.reactivestreams.Subscriber<>() {
            private final java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();

            @Override
            public void onSubscribe(org.reactivestreams.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(java.nio.ByteBuffer chunk) {
                byte[] bytes = new byte[chunk.remaining()];
                chunk.get(bytes);
                body.write(bytes, 0, bytes.length);
            }

            @Override
            public void onError(Throwable error) {
                done.completeExceptionally(error);
            }

            @Override
            public void onComplete() {
                done.complete(body.toByteArray());
            }
        });
        return done;
    }

    private static boolean signsPayload(BaseSignRequest<?, ?> request) {
        return request.requireProperty(AwsV4FamilyHttpSigner.PAYLOAD_SIGNING_ENABLED, true)
                || !"https".equalsIgnoreCase(request.request().protocol());
    }

    private SdkHttpRequest signed(BaseSignRequest<?, ? extends AwsCredentialsIdentity> request,
                                  ContentStreamProvider payload) {
        AwsCredentialsIdentity identity = request.identity();
        TemporaryCredentials.Generation generation = null;
        if (identity instanceof AwsSessionCredentialsIdentity session
                && SeclumeAws.PLACEHOLDER.equals(session.secretAccessKey())) {
            generation = TemporaryCredentials.byPlaceholder(session.sessionToken());
        }
        boolean ours = generation != null || (!(identity instanceof AwsSessionCredentialsIdentity)
                && SeclumeAws.PLACEHOLDER.equals(identity.secretAccessKey()) && secretKey != null);
        if (!ours) {
            throw new IllegalStateException("the client has credentials of its own; seclume's "
                    + "signer takes the key from its secret provider and uses nothing else - "
                    + "leave credentialsProvider to SeclumeAws.configure");
        }
        String keyId = generation != null ? generation.accessKeyId : accessKeyId;
        SecretProvider key = generation != null ? generation.secretKeyProvider() : secretKey;
        boolean presign = request.requireProperty(AwsV4FamilyHttpSigner.AUTH_LOCATION,
                AwsV4FamilyHttpSigner.AuthLocation.HEADER)
                == AwsV4FamilyHttpSigner.AuthLocation.QUERY_STRING;
        if (presign && generation != null) {
            throw new UnsupportedOperationException("a presigned URL made with temporary "
                    + "credentials carries the session token in the URL itself - a String, "
                    + "and handed out; presign with a long-term key");
        }
        String service = request.requireProperty(AwsV4FamilyHttpSigner.SERVICE_SIGNING_NAME);
        String region = request.requireProperty(AwsV4HttpSigner.REGION_NAME);
        boolean doubleEncode = request.requireProperty(AwsV4FamilyHttpSigner.DOUBLE_URL_ENCODE,
                true);
        boolean normalize = request.requireProperty(AwsV4FamilyHttpSigner.NORMALIZE_PATH, true);
        Clock clock = request.requireProperty(HttpSigner.SIGNING_CLOCK, Clock.systemUTC());
        ZonedDateTime now = ZonedDateTime.now(clock).withZoneSameInstant(ZoneOffset.UTC);
        String stamp = STAMP.format(now);
        String day = DAY.format(now);

        SdkHttpRequest.Builder builder = request.request().toBuilder();
        builder.putHeader("Host", host(request.request()));
        String scope = AwsSigV4.scope(day, region, service);
        String payloadHash;
        if (presign) {
            java.time.Duration expires = request.requireProperty(
                    AwsV4FamilyHttpSigner.EXPIRATION_DURATION, java.time.Duration.ofMinutes(15));
            payloadHash = signsPayload(request) && payload != null ? sha256Hex(payload)
                    : UNSIGNED_PAYLOAD;
            TreeMap<String, String> signedNames = canonicalHeaders(builder.build().headers());
            builder.putRawQueryParameter("X-Amz-Algorithm", AwsSigV4.ALGORITHM)
                    .putRawQueryParameter("X-Amz-Credential", keyId + "/" + scope)
                    .putRawQueryParameter("X-Amz-Date", stamp)
                    .putRawQueryParameter("X-Amz-Expires", String.valueOf(expires.getSeconds()))
                    .putRawQueryParameter("X-Amz-SignedHeaders",
                            String.join(";", signedNames.keySet()));
        } else {
            builder.putHeader("X-Amz-Date", stamp);
            if (generation != null) {
                builder.putHeader("X-Amz-Security-Token", generation.placeholder);
            }
            ChecksumAlgorithm checksum = request.property(
                    AwsV4FamilyHttpSigner.CHECKSUM_ALGORITHM);
            if (checksum != null && payload != null) {
                String header = "x-amz-checksum-"
                        + checksum.algorithmId().toLowerCase(Locale.ROOT);
                if (builder.firstMatchingHeader(header).isEmpty()) {
                    builder.putHeader(header, checksum(checksum, payload));
                }
            }
            payloadHash = !signsPayload(request) ? UNSIGNED_PAYLOAD
                    : payload == null ? AwsSigV4.EMPTY_PAYLOAD : sha256Hex(payload);
            builder.putHeader("x-amz-content-sha256", payloadHash);
        }

        SdkHttpRequest unsigned = builder.build();
        TreeMap<String, String> headers = canonicalHeaders(unsigned.headers());
        String signedHeaders = String.join(";", headers.keySet());
        String signature;
        try (Arena arena = Arena.ofConfined()) {
            String canonicalHash = canonicalHash(arena, unsigned, headers, signedHeaders,
                    payloadHash, doubleEncode, normalize, generation);
            String toSign = AwsSigV4.ALGORITHM + "\n" + stamp + "\n" + scope + "\n"
                    + canonicalHash;
            signature = AwsSigV4.hex(AwsSigV4.sign(arena, key::writeSecret, toSign, day,
                    region, service));
        }
        space.seclume.jfr.Observed.secretUse("aws", unsigned.host() + ":" + unsigned.port(),
                presign ? "sigv4-presign" : "sigv4");
        if (presign) {
            return builder.putRawQueryParameter("X-Amz-Signature", signature).build();
        }
        return builder.putHeader("Authorization", AwsSigV4.ALGORITHM + " Credential="
                + keyId + "/" + scope + ", SignedHeaders=" + signedHeaders
                + ", Signature=" + signature).build();
    }

    /**
     * The canonical request's SHA-256. Without a session token it is plain
     * text; with one, it is assembled in native memory and the token's bytes
     * go in where its header's value is - the digest that comes out is public.
     */
    private static String canonicalHash(Arena arena, SdkHttpRequest request,
                                        TreeMap<String, String> headers, String signedHeaders,
                                        String payloadHash, boolean doubleEncode,
                                        boolean normalize,
                                        TemporaryCredentials.Generation generation) {
        String start = request.method().name() + "\n"
                + canonicalUri(request.encodedPath(), doubleEncode, normalize) + "\n"
                + canonicalQuery(request.rawQueryParameters()) + "\n";
        String end = "\n" + signedHeaders + "\n" + payloadHash;
        if (generation == null) {
            StringBuilder canonical = new StringBuilder(512).append(start);
            headers.forEach((name, value) -> canonical.append(name).append(':').append(value)
                    .append('\n'));
            return AwsSigV4.sha256Hex(canonical.append(end).toString());
        }
        int capacity = 3 * (start.length() + end.length() + generation.token.length() + 64);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            capacity += 3 * (header.getKey().length() + header.getValue().length() + 2);
        }
        try (space.seclume.internal.CanonicalRequest canonical =
                     new space.seclume.internal.CanonicalRequest(arena, capacity)) {
            canonical.text(start);
            for (Map.Entry<String, String> header : headers.entrySet()) {
                canonical.text(header.getKey() + ":");
                if (header.getKey().equals("x-amz-security-token")) {
                    canonical.secret(generation.token.segment(), generation.token.length());
                } else {
                    canonical.text(header.getValue());
                }
                canonical.text("\n");
            }
            canonical.text(end);
            return canonical.sha256Hex();
        }
    }

    static String host(SdkHttpRequest request) {
        int port = request.port();
        boolean standard = port == ("https".equalsIgnoreCase(request.protocol()) ? 443 : 80);
        return standard || port < 0 ? request.host() : request.host() + ":" + port;
    }

    static TreeMap<String, String> canonicalHeaders(Map<String, List<String>> headers) {
        TreeMap<String, String> canonical = new TreeMap<>();
        headers.forEach((name, values) -> {
            String lower = name.toLowerCase(Locale.ROOT);
            if (IGNORED.contains(lower)) {
                return;
            }
            List<String> trimmed = new ArrayList<>(values.size());
            for (String value : values) {
                trimmed.add(value == null ? "" : value.trim().replaceAll(" +", " "));
            }
            canonical.merge(lower, String.join(",", trimmed), (a, b) -> a + "," + b);
        });
        return canonical;
    }

    static String canonicalUri(String encodedPath, boolean doubleEncode, boolean normalize) {
        String path = encodedPath == null || encodedPath.isEmpty() ? "/" : encodedPath;
        if (normalize) {
            boolean trailing = path.endsWith("/") && path.length() > 1;
            path = URI.create(path).normalize().getRawPath();
            if (trailing && !path.endsWith("/")) {
                path = path + "/";
            }
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        if (!doubleEncode) {
            return path;
        }
        List<String> segments = new ArrayList<>();
        for (String segment : path.split("/", -1)) {
            segments.add(AwsSigV4.urlEncode(segment));
        }
        return String.join("/", segments);
    }

    static String canonicalQuery(Map<String, List<String>> parameters) {
        TreeMap<String, List<String>> sorted = new TreeMap<>();
        parameters.forEach((name, values) -> {
            List<String> encoded = new ArrayList<>();
            if (values == null || values.isEmpty()) {
                encoded.add("");
            } else {
                for (String value : values) {
                    encoded.add(value == null ? "" : AwsSigV4.urlEncode(value));
                }
            }
            encoded.sort(null);
            sorted.put(AwsSigV4.urlEncode(name), encoded);
        });
        StringBuilder query = new StringBuilder();
        sorted.forEach((name, values) -> {
            for (String value : values) {
                if (query.length() > 0) {
                    query.append('&');
                }
                query.append(name).append('=').append(value);
            }
        });
        return query.toString();
    }

    /** The body's SHA-256 in hex - public, the body is sent as it is. */
    private static String sha256Hex(ContentStreamProvider payload) {
        try (InputStream in = payload.newStream();
             Digest digest = HashAlgorithm.SHA_256.newDigest();
             Arena arena = Arena.ofConfined()) {
            byte[] chunk = new byte[16384];
            MemorySegment buffer = arena.allocate(chunk.length);
            int read;
            while ((read = in.read(chunk)) > 0) {
                MemorySegment.copy(chunk, 0, buffer, ValueLayout.JAVA_BYTE, 0, read);
                digest.update(buffer, 0, read);
            }
            MemorySegment out = arena.allocate(digest.digestLength());
            digest.digest(out, 0);
            return AwsSigV4.hex(out);
        } catch (IOException e) {
            throw new UncheckedIOException("the request body could not be read to be signed", e);
        }
    }

    /** An S3 checksum of the body, base64 as its header has it - public. */
    private static String checksum(ChecksumAlgorithm algorithm, ContentStreamProvider payload) {
        SdkChecksum checksum = SdkChecksum.forAlgorithm(algorithm);
        try (InputStream in = payload.newStream()) {
            byte[] chunk = new byte[16384];
            int read;
            while ((read = in.read(chunk)) > 0) {
                checksum.update(chunk, 0, read);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("the request body could not be read for its "
                    + "checksum", e);
        }
        return java.util.Base64.getEncoder().encodeToString(checksum.getChecksumBytes()); // seclume-allow: the body's checksum, sent in a header - public
    }
}
