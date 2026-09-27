package space.seclume.aws;

import java.net.URI;
import java.net.URL;
import java.net.MalformedURLException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4FamilyHttpSigner;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignRequest;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;

import space.seclume.internal.AwsSigV4;

/**
 * Presigned S3 URLs - for a browser to upload or download directly - signed
 * with the key in native memory.
 *
 * <pre>
 * SeclumeS3Presigner presigner = SeclumeS3Presigner.of(
 *         "access-key-id=AKIA...&amp;region=eu-central-1&amp;provider=file&amp;path=/run/secrets/aws-secret-key");
 * URL download = presigner.presignGet("reports", "2026/q3.pdf", Duration.ofMinutes(10));
 * URL upload = presigner.presignPut("uploads", "incoming/scan.pdf", Duration.ofMinutes(5));
 *
 * // MinIO, Ceph: their endpoint, path style
 * SeclumeS3Presigner.of(spec, URI.create("https://minio.internal:9000"));
 * </pre>
 *
 * <p>The SDK's own {@code S3Presigner} signs with the SDK's signer and the
 * credentials it was given - with a client set up by {@link SeclumeAws} that
 * is a placeholder, and its URLs are refused by S3. This one signs in the
 * query string with seclume's signer, the same signature as the SDK's (a test
 * compares them). A long-term key only: a URL presigned with temporary
 * credentials would carry the session token in itself.
 */
public final class SeclumeS3Presigner {

    private final HttpSigner<AwsCredentialsIdentity> signer;
    private final AwsCredentialsIdentity identity;
    private final String region;
    private final URI endpoint;
    private final Clock clock;

    private SeclumeS3Presigner(HttpSigner<AwsCredentialsIdentity> signer, String accessKeyId,
                               String region, URI endpoint, Clock clock) {
        this.signer = signer;
        this.identity = AwsCredentialsIdentity.create(accessKeyId, SeclumeAws.PLACEHOLDER);
        this.region = region;
        this.endpoint = endpoint;
        this.clock = clock;
    }

    /** For AWS's own S3, virtual-host style; {@code region=} is required in the spec. */
    public static SeclumeS3Presigner of(String spec) {
        return of(spec, null);
    }

    /** For an S3-compatible store at {@code endpoint}, path style. */
    public static SeclumeS3Presigner of(String spec, URI endpoint) {
        return of(spec, endpoint, Clock.systemUTC());
    }

    static SeclumeS3Presigner of(String spec, URI endpoint, Clock clock) {
        String accessKeyId = option(spec, "access-key-id");
        String region = option(spec, "region");
        if (region == null) {
            throw new IllegalArgumentException("a presigned URL names its region: add region=");
        }
        return new SeclumeS3Presigner(SeclumeAws.signer(spec), accessKeyId, region, endpoint,
                clock);
    }

    /** A URL that downloads {@code key} for {@code valid}, at most seven days. */
    public URL presignGet(String bucket, String key, Duration valid) {
        return presign(SdkHttpMethod.GET, bucket, key, valid);
    }

    /** A URL that uploads {@code key} with a PUT, for {@code valid}. */
    public URL presignPut(String bucket, String key, Duration valid) {
        return presign(SdkHttpMethod.PUT, bucket, key, valid);
    }

    private URL presign(SdkHttpMethod method, String bucket, String key, Duration valid) {
        if (valid.isNegative() || valid.isZero() || valid.compareTo(Duration.ofDays(7)) > 0) {
            throw new IllegalArgumentException("a presigned URL is valid for more than nothing "
                    + "and at most seven days, not " + valid);
        }
        List<String> segments = new ArrayList<>();
        for (String segment : key.split("/", -1)) {
            segments.add(AwsSigV4.urlEncode(segment));
        }
        String path = String.join("/", segments);
        URI uri = endpoint == null
                ? URI.create("https://" + bucket + ".s3." + region + ".amazonaws.com/" + path)
                : URI.create(endpoint.toString().replaceAll("/+$", "") + "/"
                        + AwsSigV4.urlEncode(bucket) + "/" + path);
        SdkHttpRequest signed = signer.sign(SignRequest.builder(identity)
                .request(SdkHttpRequest.builder().method(method).uri(uri).build())
                .putProperty(AwsV4HttpSigner.REGION_NAME, region)
                .putProperty(AwsV4FamilyHttpSigner.SERVICE_SIGNING_NAME, "s3")
                .putProperty(AwsV4FamilyHttpSigner.DOUBLE_URL_ENCODE, false)
                .putProperty(AwsV4FamilyHttpSigner.NORMALIZE_PATH, false)
                .putProperty(AwsV4FamilyHttpSigner.PAYLOAD_SIGNING_ENABLED, false)
                .putProperty(AwsV4FamilyHttpSigner.AUTH_LOCATION,
                        AwsV4FamilyHttpSigner.AuthLocation.QUERY_STRING)
                .putProperty(AwsV4FamilyHttpSigner.EXPIRATION_DURATION, valid)
                .putProperty(HttpSigner.SIGNING_CLOCK, clock)
                .build()).request();
        try {
            return signed.getUri().toURL();
        } catch (MalformedURLException e) {
            throw new IllegalStateException("the presigned URL is not a URL", e);
        }
    }

    private static String option(String spec, String name) {
        for (String pair : (spec.startsWith("?") ? spec.substring(1) : spec).split("&")) {
            if (pair.startsWith(name + "=")) {
                return java.net.URLDecoder.decode(pair.substring(name.length() + 1),
                        java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        return null;
    }
}
