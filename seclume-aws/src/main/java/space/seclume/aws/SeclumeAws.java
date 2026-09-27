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

import space.seclume.internal.TrustChoice;
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
 * <p>Long-term keys - an IAM user's, MinIO's, Ceph's - or temporary
 * credentials, which is how AWS means workloads to get them:
 *
 * <pre>
 * SeclumeAws.configure(S3Client.builder(), "credentials=instance&amp;region=eu-central-1")      // EC2
 * SeclumeAws.configure(S3Client.builder(), "credentials=container&amp;region=eu-central-1")     // ECS, EKS Pod Identity
 * SeclumeAws.configure(S3Client.builder(), "credentials=web-identity&amp;region=eu-central-1")  // EKS IRSA
 * </pre>
 *
 * <p>With temporary credentials the secret key <b>and the session token</b>
 * stay in native memory: the token is signed from there, and written into the
 * request by seclume's TLS, which becomes the client's HTTP transport (the
 * SDK's Apache 5 client over {@link SessionTokenSocket}) - so a synchronous
 * client. SigV4a is not supported yet.
 */
public final class SeclumeAws {

    /** What the SDK holds instead of the secret key. */
    static final String PLACEHOLDER = "seclume-signs-in-native-memory";

    private SeclumeAws() {
    }

    /**
     * Sets up {@code builder} to sign with the credentials {@code spec} names:
     * a long-term key ({@code access-key-id=...&provider=...}), or temporary
     * ones ({@code credentials=instance}, {@code container} or
     * {@code web-identity}) - which need a synchronous client, whose HTTP
     * client is then seclume's TLS carrying the session token.
     */
    public static <B extends AwsClientBuilder<B, ?>> B configure(B builder, String spec) {
        Settings settings = Settings.of(spec);
        if (settings.temporary != null) {
            if (!(builder instanceof software.amazon.awssdk.awscore.client.builder
                    .AwsSyncClientBuilder<?, ?> sync)) {
                throw new IllegalArgumentException("temporary credentials (credentials="
                        + settings.temporary.name() + ") need a synchronous client: the session "
                        + "token is written by seclume's TLS, which the SDK's asynchronous "
                        + "clients cannot use");
            }
            sync.httpClient(software.amazon.awssdk.http.apache5.Apache5HttpClient.builder()
                    .tlsSocketStrategy(new SeclumeTlsStrategy(settings.trust)).build());
            IdentityProvider<AwsCredentialsIdentity> identity = session(settings.temporary);
            builder.credentialsProvider(identity);
            builder.putAuthScheme(new Scheme(new SeclumeSigV4Signer(null, null), identity));
        } else {
            SeclumeSigV4Signer signer = new SeclumeSigV4Signer(settings.accessKeyId,
                    settings.secret);
            IdentityProvider<AwsCredentialsIdentity> identity = identity(settings.accessKeyId);
            builder.credentialsProvider(identity);
            builder.putAuthScheme(new Scheme(signer, identity));
        }
        if (settings.region != null) {
            builder.region(Region.of(settings.region));
        }
        return builder;
    }

    /** The current generation of temporary credentials, with placeholders for the secrets. */
    private static IdentityProvider<AwsCredentialsIdentity> session(TemporaryCredentials source) {
        return new IdentityProvider<>() {
            @Override
            public Class<AwsCredentialsIdentity> identityType() {
                return AwsCredentialsIdentity.class;
            }

            @Override
            public CompletableFuture<AwsCredentialsIdentity> resolveIdentity(
                    ResolveIdentityRequest request) {
                try {
                    TemporaryCredentials.Generation current = source.current();
                    return CompletableFuture.completedFuture(
                            software.amazon.awssdk.identity.spi.AwsSessionCredentialsIdentity
                                    .create(current.accessKeyId, PLACEHOLDER,
                                            current.placeholder));
                } catch (RuntimeException e) {
                    return CompletableFuture.failedFuture(e);
                }
            }
        };
    }

    /**
     * The signer on its own - for a caller that sets up the scheme itself. Its
     * identity must be {@link #credentials(String)}'s.
     */
    public static HttpSigner<AwsCredentialsIdentity> signer(String spec) {
        Settings settings = Settings.of(spec);
        if (settings.temporary != null) {
            throw new IllegalArgumentException("the signer on its own takes a long-term key; "
                    + "temporary credentials go through SeclumeAws.configure");
        }
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

    /**
     * {@code access-key-id=...&region=...&provider=...} for a long-term key, or
     * {@code credentials=instance|container|web-identity&region=...} for
     * temporary ones; {@code tlsRootCert} or {@code tlsPin} for a server whose
     * CA the JVM does not know.
     */
    private record Settings(String accessKeyId, String region, SecretProvider secret,
                            TemporaryCredentials temporary, TrustChoice.Choice trust) {

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
            String region = options.remove("region");
            String kind = options.remove("credentials");
            TrustChoice.Choice trust = trust(options);
            if (options.containsKey("secret-access-key")) {
                throw new IllegalArgumentException("the secret access key is not given here: "
                        + "name it with provider= (provider=file&path=..., provider=vault&...)");
            }
            if (kind != null && !kind.equals("static")) {
                return new Settings(null, region, null,
                        CredentialSources.of(kind, options, trust, region), trust);
            }
            String accessKeyId = options.remove("access-key-id");
            if (accessKeyId == null || accessKeyId.isBlank()) {
                throw new IllegalArgumentException("access-key-id= is missing - the public "
                        + "half of the key, e.g. AKIA... - or credentials=instance, container "
                        + "or web-identity for temporary credentials");
            }
            if (!options.containsKey("provider")) {
                throw new IllegalArgumentException("no secret key named: add provider= and "
                        + "its options, e.g. provider=file&path=/run/secrets/aws-secret-key");
            }
            return new Settings(accessKeyId.trim(), region, SecretProviders.of(options), null,
                    trust);
        }

        private static TrustChoice.Choice trust(Map<String, String> options) {
            String rootCert = options.remove(TrustChoice.ROOT_CERT);
            String pin = options.remove(TrustChoice.PIN);
            if (rootCert == null && pin == null) {
                return null;
            }
            java.util.Properties named = new java.util.Properties();
            if (rootCert != null) {
                named.setProperty(TrustChoice.ROOT_CERT, rootCert);
            }
            if (pin != null) {
                named.setProperty(TrustChoice.PIN, pin);
            }
            try {
                return TrustChoice.of(null, named);
            } catch (java.sql.SQLException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }
    }
}
