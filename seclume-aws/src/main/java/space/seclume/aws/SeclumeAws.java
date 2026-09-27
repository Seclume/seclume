package space.seclume.aws;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import software.amazon.awssdk.awscore.client.builder.AwsClientBuilder;
import software.amazon.awssdk.http.auth.aws.scheme.AwsV4AuthScheme;
import software.amazon.awssdk.http.auth.spi.scheme.AuthScheme;
import software.amazon.awssdk.http.auth.spi.signer.HttpSigner;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;
import software.amazon.awssdk.identity.spi.IdentityProvider;
import software.amazon.awssdk.identity.spi.IdentityProviders;
import software.amazon.awssdk.identity.spi.ResolveIdentityRequest;
import software.amazon.awssdk.regions.Region;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * AWS SDK clients whose secret access key is never on the heap.
 *
 * <pre>
 * S3Client s3 = SeclumeAws.configure(S3Client.builder(),
 *         "access-key-id=AKIA...&amp;region=eu-central-1&amp;provider=file&amp;path=/run/secrets/aws-secret-key")
 *     .build();
 *
 * // MinIO, Ceph and other S3-compatible stores: the same, with their endpoint
 * S3Client minio = SeclumeAws.configure(S3Client.builder(), "access-key-id=minio&amp;region=us-east-1&amp;provider=vault&amp;...")
 *     .endpointOverride(URI.create("https://minio.internal:9000")).forcePathStyle(true).build();
 * </pre>
 *
 * <p>Any client of the SDK - S3, SQS, SNS, DynamoDB, Kinesis ... - is set up
 * the same way. {@code configure} replaces the client's SigV4 scheme with
 * seclume's signer and gives it a credentials provider whose secret is a
 * placeholder: the key is read from the secret provider into native memory
 * for each signature and wiped after it. The access key id is public (it is
 * in every request) and is given as it is; {@code region} is optional when the
 * builder gets one otherwise.
 *
 * <p>Long-term keys - an IAM user's, MinIO's, Ceph's. Temporary credentials
 * with a session token (instance roles, IRSA, AssumeRole) would put the token
 * into a header the SDK holds as a {@code String}; they are refused rather
 * than half protected. Presigned URLs, SigV4a and async clients that sign
 * their body are not supported yet.
 */
public final class SeclumeAws {

    /** What the SDK holds instead of the secret key. */
    static final String PLACEHOLDER = "seclume-signs-in-native-memory";

    private SeclumeAws() {
    }

    /** Sets up {@code builder} to sign with the key named by {@code spec}. */
    public static <B extends AwsClientBuilder<B, ?>> B configure(B builder, String spec) {
        Settings settings = Settings.of(spec);
        SeclumeSigV4Signer signer = new SeclumeSigV4Signer(settings.accessKeyId,
                settings.secret);
        IdentityProvider<AwsCredentialsIdentity> identity = identity(settings.accessKeyId);
        builder.credentialsProvider(identity);
        builder.putAuthScheme(new Scheme(signer, identity));
        if (settings.region != null) {
            builder.region(Region.of(settings.region));
        }
        return builder;
    }

    /**
     * The signer on its own - for a caller that sets up the scheme itself. Its
     * identity must be {@link #credentials(String)}'s.
     */
    public static HttpSigner<AwsCredentialsIdentity> signer(String spec) {
        Settings settings = Settings.of(spec);
        return new SeclumeSigV4Signer(settings.accessKeyId, settings.secret);
    }

    /** The access key id with the placeholder in place of the secret. */
    public static IdentityProvider<AwsCredentialsIdentity> credentials(String accessKeyId) {
        return identity(accessKeyId);
    }

    private static IdentityProvider<AwsCredentialsIdentity> identity(String accessKeyId) {
        AwsCredentialsIdentity identity = AwsCredentialsIdentity.create(accessKeyId, PLACEHOLDER);
        return new IdentityProvider<>() {
            @Override
            public Class<AwsCredentialsIdentity> identityType() {
                return AwsCredentialsIdentity.class;
            }

            @Override
            public CompletableFuture<AwsCredentialsIdentity> resolveIdentity(
                    ResolveIdentityRequest request) {
                return CompletableFuture.completedFuture(identity);
            }
        };
    }

    /** SigV4, with seclume's signer. */
    private record Scheme(SeclumeSigV4Signer signer,
                          IdentityProvider<AwsCredentialsIdentity> identity)
            implements AuthScheme<AwsCredentialsIdentity> {

        @Override
        public String schemeId() {
            return AwsV4AuthScheme.SCHEME_ID;
        }

        @Override
        public IdentityProvider<AwsCredentialsIdentity> identityProvider(
                IdentityProviders providers) {
            return identity;
        }
    }

    /** {@code access-key-id=...&region=...&provider=...}. */
    private record Settings(String accessKeyId, String region, SecretProvider secret) {

        static Settings of(String spec) {
            Map<String, String> options = new LinkedHashMap<>();
            for (String pair : (spec.startsWith("?") ? spec.substring(1) : spec).split("&")) {
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    options.put(URLDecoder.decode(pair.substring(0, equals),
                            StandardCharsets.UTF_8), URLDecoder.decode(pair.substring(equals + 1),
                            StandardCharsets.UTF_8));
                }
            }
            String accessKeyId = options.remove("access-key-id");
            String region = options.remove("region");
            if (accessKeyId == null || accessKeyId.isBlank()) {
                throw new IllegalArgumentException("access-key-id= is missing - the public "
                        + "half of the key, e.g. AKIA...");
            }
            if (options.containsKey("secret-access-key")) {
                throw new IllegalArgumentException("the secret access key is not given here: "
                        + "name it with provider= (provider=file&path=..., provider=vault&...)");
            }
            if (!options.containsKey("provider")) {
                throw new IllegalArgumentException("no secret key named: add provider= and "
                        + "its options, e.g. provider=file&path=/run/secrets/aws-secret-key");
            }
            return new Settings(accessKeyId.trim(), region, SecretProviders.of(options));
        }
    }
}
