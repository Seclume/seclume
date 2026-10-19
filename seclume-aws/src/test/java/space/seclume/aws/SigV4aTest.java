package space.seclume.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4FamilyHttpSigner;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4aHttpSigner;
import software.amazon.awssdk.http.auth.aws.signer.RegionSet;
import software.amazon.awssdk.http.auth.spi.signer.HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignRequest;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;
import software.amazon.awssdk.services.s3.S3Client;

import space.seclume.internal.AwsSigV4;
import space.seclume.internal.AwsSigV4a;
import space.seclume.secret.SecretProviders;

/**
 * SigV4a against AWS's own test suite (aws-c-auth, {@code v4a/get-vanilla}):
 * the key derived from the example credentials has the public point the
 * suite names, and a signature made with it verifies there. Then the signer
 * as the SDK uses it: the canonical request with the region set, the scope
 * without a region, and S3 choosing it for a multi-region access point.
 *
 * <p>The example secret key is AWS's published one, not a secret.
 */
class SigV4aTest {

    private static final String KEY_ID = "AKIDEXAMPLE";
    private static final String EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    private static final String X = "b6618f6a65740a99e650b33b6b4b5bd0d43b176d721a3edfea7e7d2d56d936b1";
    private static final String Y = "865ed22a7eadc9c5cb9d2cbaca1b3699139fedc5043dc6661864218330c8e518";
    private static final String VANILLA_TO_SIGN = "AWS4-ECDSA-P256-SHA256\n20150830T123600Z\n"
            + "20150830/service/aws4_request\n"
            + "cf59db423e841c8b7e3444158185aa261b724a5c27cbe762676f3eed19f4dc02";

    @TempDir
    Path directory;

    private Path exampleSecret() throws Exception {
        Path file = directory.resolve("example-secret");
        Files.writeString(file, EXAMPLE_SECRET);
        return file;
    }

    private static AwsSigV4.SecretKey from(Path file) {
        return SecretProviders.of(Map.of("provider", "file", "path", file.toString()))::writeSecret;
    }

    private static PublicKey suitesKey() throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec curve = parameters.getParameterSpec(ECParameterSpec.class);
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
                new ECPoint(new BigInteger(X, 16), new BigInteger(Y, 16)), curve));
    }

    private static boolean verifies(String toSign, String hexSignature) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(suitesKey());
        verifier.update(toSign.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(HexFormat.of().parseHex(hexSignature));
    }

    @Test
    void theDerivedKeyIsTheOneTheSuiteNames() throws Exception {
        assumeTrue(AwsSigV4a.available(), "SigV4a signs through OpenSSL 3 on Linux");
        byte[] spki = AwsSigV4a.publicKey(from(exampleSecret()), KEY_ID);
        String point = HexFormat.of().formatHex(spki, spki.length - 64, spki.length);
        assertEquals(X + Y, point);
    }

    @Test
    void aSignatureVerifiesWithTheSuitesPublicKey() throws Exception {
        assumeTrue(AwsSigV4a.available(), "SigV4a signs through OpenSSL 3 on Linux");
        String signature = AwsSigV4a.sign(from(exampleSecret()), KEY_ID, VANILLA_TO_SIGN);
        assertTrue(verifies(VANILLA_TO_SIGN, signature), signature);
        // and is ECDSA's own, a fresh one each time: nothing deterministic to replay
        String again = AwsSigV4a.sign(from(exampleSecret()), KEY_ID, VANILLA_TO_SIGN);
        assertTrue(!again.equals(signature) && verifies(VANILLA_TO_SIGN, again));
        assertTrue(!verifies(VANILLA_TO_SIGN + "x", signature), "it verified anything");
    }

    /** The signer: the region set signed in, no region in the scope, the suite's key. */
    @Test
    void theSignerSignsTheCanonicalRequestWithTheRegionSet() throws Exception {
        assumeTrue(AwsSigV4a.available(), "SigV4a signs through OpenSSL 3 on Linux");
        SeclumeSigV4Signer signer = new SeclumeSigV4Signer(KEY_ID, SecretProviders.of(
                Map.of("provider", "file", "path", exampleSecret().toString())), true);
        SdkHttpRequest request = SdkHttpRequest.builder().method(SdkHttpMethod.GET)
                .uri(java.net.URI.create("https://example.amazonaws.com/")).build();
        SdkHttpRequest signed = signer.sign(SignRequest.builder(AwsCredentialsIdentity.create(
                        KEY_ID, SeclumeAws.PLACEHOLDER))
                .request(request)
                .putProperty(AwsV4FamilyHttpSigner.SERVICE_SIGNING_NAME, "service")
                .putProperty(AwsV4aHttpSigner.REGION_SET, RegionSet.create("us-east-1,eu-west-1"))
                .putProperty(HttpSigner.SIGNING_CLOCK, Clock.fixed(
                        Instant.parse("2015-08-30T12:36:00Z"), ZoneOffset.UTC))
                .build()).request();

        String canonical = "GET\n/\n\nhost:example.amazonaws.com\n"
                + "x-amz-content-sha256:" + AwsSigV4.EMPTY_PAYLOAD + "\n"
                + "x-amz-date:20150830T123600Z\nx-amz-region-set:eu-west-1,us-east-1\n\n"
                + "host;x-amz-content-sha256;x-amz-date;x-amz-region-set\n"
                + AwsSigV4.EMPTY_PAYLOAD;
        String toSign = "AWS4-ECDSA-P256-SHA256\n20150830T123600Z\n"
                + "20150830/service/aws4_request\n" + AwsSigV4.sha256Hex(canonical);
        String authorization = signed.firstMatchingHeader("Authorization").orElseThrow();
        String prefix = "AWS4-ECDSA-P256-SHA256 Credential=AKIDEXAMPLE/20150830/service/"
                + "aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
                + "x-amz-region-set, Signature=";
        assertTrue(authorization.startsWith(prefix), authorization);
        assertTrue(verifies(toSign, authorization.substring(prefix.length())),
                "the signature is not over the canonical request with the region set");
        assertEquals("eu-west-1,us-east-1", // the SDK sorts the set
                signed.firstMatchingHeader("X-Amz-Region-Set").orElseThrow());
    }

    /**
     * S3 with a multi-region access point asks for {@code aws.auth#sigv4a},
     * and gets seclume's signer - not the SDK's, which would need the CRT
     * and the key as a String. Where OpenSSL is missing, it says so.
     */
    @Test
    void s3ChoosesItForAMultiRegionAccessPoint() throws Exception {
        Path secret = SecretKeyFile.make(directory);
        AtomicReference<SdkHttpRequest> sent = new AtomicReference<>();
        ExecutionInterceptor capture = new ExecutionInterceptor() {
            @Override
            public void beforeTransmission(Context.BeforeTransmission context,
                    ExecutionAttributes attributes) {
                sent.set(context.httpRequest());
                throw new IllegalStateException("captured, not sent");
            }
        };
        try (S3Client s3 = SeclumeAws.configure(S3Client.builder(), SecretKeyFile.spec(
                        "AKIASECLUMEMRAP", secret))
                .overrideConfiguration(o -> o.addExecutionInterceptor(capture)).build()) {
            Exception failed = assertThrows(Exception.class, () -> s3.getObject(b -> b
                    .bucket("arn:aws:s3::123456789012:accesspoint/mfzwi23gnjvgw.mrap")
                    .key("orders.csv")));
            if (!AwsSigV4a.available()) {
                assertTrue(String.valueOf(rootMessage(failed)).contains("OpenSSL"),
                        String.valueOf(rootMessage(failed)));
                return;
            }
            SdkHttpRequest request = sent.get();
            assertTrue(request != null, "nothing was signed: " + failed);
            assertTrue(request.firstMatchingHeader("Authorization").orElseThrow()
                    .startsWith("AWS4-ECDSA-P256-SHA256 Credential=AKIASECLUMEMRAP/"));
            assertEquals("*", request.firstMatchingHeader("X-Amz-Region-Set").orElseThrow());
        }
    }

    private static String rootMessage(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return cause.getMessage();
    }
}
