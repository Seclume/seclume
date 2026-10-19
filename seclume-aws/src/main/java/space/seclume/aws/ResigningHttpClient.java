package space.seclume.aws;

import java.time.Clock;

import software.amazon.awssdk.http.ExecutableHttpRequest;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4FamilyHttpSigner;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignRequest;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;
import software.amazon.awssdk.identity.spi.IdentityProvider;
import software.amazon.awssdk.identity.spi.ResolveIdentityRequest;

/**
 * An SDK HTTP client that signs every request again with
 * {@link SeclumeSigV4Signer} before it goes - for a client that signs with
 * the SDK's own signer and lets nobody replace it, as OpenSearch's
 * {@code AwsSdk2Transport} does in a private method. That client is given
 * credentials whose secret is {@link SeclumeAws#PLACEHOLDER}: it signs with
 * the placeholder, and the signature it made - worthless, and nothing secret
 * went into it - is dropped here with the headers that belong to it.
 *
 * <p>The body is signed as it is sent: such a client hands over a body it can
 * read again, which the signer reads once to hash it.
 */
final class ResigningHttpClient implements SdkHttpClient {

    /** What a signature puts on a request, removed before the real one is made. */
    private static final String[] SIGNATURE_HEADERS = {"Authorization", "X-Amz-Date",
        "x-amz-content-sha256", "X-Amz-Security-Token"};

    private final SdkHttpClient delegate;
    private final SeclumeSigV4Signer signer;
    private final IdentityProvider<AwsCredentialsIdentity> identity;
    private final String service;
    private final String region;
    private final Clock clock;

    ResigningHttpClient(SdkHttpClient delegate, SeclumeSigV4Signer signer,
                        IdentityProvider<AwsCredentialsIdentity> identity, String service,
                        String region, Clock clock) {
        this.delegate = delegate;
        this.signer = signer;
        this.identity = identity;
        this.service = service;
        this.region = region;
        this.clock = clock;
    }

    @Override
    public ExecutableHttpRequest prepareRequest(HttpExecuteRequest request) {
        SdkHttpRequest.Builder unsigned = request.httpRequest().toBuilder();
        for (String header : SIGNATURE_HEADERS) {
            unsigned.removeHeader(header);
        }
        AwsCredentialsIdentity credentials = identity.resolveIdentity(
                ResolveIdentityRequest.builder().build()).join();
        SignedRequest signed = signer.sign(SignRequest.builder(credentials)
                .request(unsigned.build())
                .payload(request.contentStreamProvider().orElse(null))
                .putProperty(AwsV4FamilyHttpSigner.SERVICE_SIGNING_NAME, service)
                .putProperty(AwsV4HttpSigner.REGION_NAME, region)
                .putProperty(HttpSigner.SIGNING_CLOCK, clock)
                .build());
        return delegate.prepareRequest(HttpExecuteRequest.builder()
                .request(signed.request())
                .contentStreamProvider(signed.payload().orElse(null))
                .build());
    }

    @Override
    public String clientName() {
        return "seclume-" + delegate.clientName();
    }

    @Override
    public void close() {
        delegate.close();
    }
}
