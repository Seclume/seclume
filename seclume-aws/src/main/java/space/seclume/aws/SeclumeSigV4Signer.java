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
 * <p>Not here: presigned URLs, SigV4a (multi-region access points) and the
 * chunked ({@code aws-chunked}) upload encoding - a body is signed in one
 * piece, or, where the SDK allows it over HTTPS, sent as
 * {@code UNSIGNED-PAYLOAD}; an S3 checksum goes into its header.
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

    @Override
    public CompletableFuture<AsyncSignedRequest> signAsync(
            AsyncSignRequest<? extends AwsCredentialsIdentity> request) {
        CompletableFuture<AsyncSignedRequest> result = new CompletableFuture<>();
        try {
            if (request.payload().isPresent() && (signsPayload(request)
                    || request.property(AwsV4FamilyHttpSigner.CHECKSUM_ALGORITHM) != null)) {
                throw new UnsupportedOperationException("an async client that signs its "
                        + "request body is not supported by seclume's signer - use the "
                        + "synchronous client, or HTTPS where S3 sends the body unsigned");
            }
            SdkHttpRequest signed = signed(request, null);
            result.complete(AsyncSignedRequest.builder().request(signed)
                    .payload(request.payload().orElse(null)).build());
        } catch (RuntimeException e) {
            result.completeExceptionally(e);
        }
        return result;
    }

    private static boolean signsPayload(BaseSignRequest<?, ?> request) {
        return request.requireProperty(AwsV4FamilyHttpSigner.PAYLOAD_SIGNING_ENABLED, true)
                || !"https".equalsIgnoreCase(request.request().protocol());
    }

    private SdkHttpRequest signed(BaseSignRequest<?, ? extends AwsCredentialsIdentity> request,
                                  ContentStreamProvider payload) {
        AwsCredentialsIdentity identity = request.identity();
        if (identity instanceof AwsSessionCredentialsIdentity
                || !SeclumeAws.PLACEHOLDER.equals(identity.secretAccessKey())) {
            throw new IllegalStateException("the client has credentials of its own; seclume's "
                    + "signer takes the key from its secret provider and uses nothing else - "
                    + "leave credentialsProvider to SeclumeAws.configure");
        }
        if (request.requireProperty(AwsV4FamilyHttpSigner.AUTH_LOCATION,
                AwsV4FamilyHttpSigner.AuthLocation.HEADER)
                != AwsV4FamilyHttpSigner.AuthLocation.HEADER) {
            throw new UnsupportedOperationException("presigned URLs are not made by seclume's "
                    + "signer yet");
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
        builder.putHeader("X-Amz-Date", stamp);

        ChecksumAlgorithm checksum = request.property(AwsV4FamilyHttpSigner.CHECKSUM_ALGORITHM);
        if (checksum != null && payload != null) {
            String header = "x-amz-checksum-" + checksum.algorithmId().toLowerCase(Locale.ROOT);
            if (builder.firstMatchingHeader(header).isEmpty()) {
                builder.putHeader(header, checksum(checksum, payload));
            }
        }
        String payloadHash = !signsPayload(request) ? UNSIGNED_PAYLOAD
                : payload == null ? AwsSigV4.EMPTY_PAYLOAD : sha256Hex(payload);
        builder.putHeader("x-amz-content-sha256", payloadHash);

        SdkHttpRequest unsigned = builder.build();
        TreeMap<String, String> headers = canonicalHeaders(unsigned.headers());
        String signedHeaders = String.join(";", headers.keySet());
        StringBuilder canonical = new StringBuilder(512);
        canonical.append(unsigned.method().name()).append('\n')
                .append(canonicalUri(unsigned.encodedPath(), doubleEncode, normalize))
                .append('\n')
                .append(canonicalQuery(unsigned.rawQueryParameters())).append('\n');
        headers.forEach((name, value) -> canonical.append(name).append(':').append(value)
                .append('\n'));
        canonical.append('\n').append(signedHeaders).append('\n').append(payloadHash);

        String scope = AwsSigV4.scope(day, region, service);
        String toSign = AwsSigV4.ALGORITHM + "\n" + stamp + "\n" + scope + "\n"
                + AwsSigV4.sha256Hex(canonical.toString());
        String signature;
        try (Arena arena = Arena.ofConfined()) {
            signature = AwsSigV4.hex(AwsSigV4.sign(arena, secretKey::writeSecret, toSign, day,
                    region, service));
        }
        return builder.putHeader("Authorization", AwsSigV4.ALGORITHM + " Credential="
                + accessKeyId + "/" + scope + ", SignedHeaders=" + signedHeaders
                + ", Signature=" + signature).build();
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
