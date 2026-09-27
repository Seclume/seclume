package space.seclume.jwt;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Makes the keys for the heap proof in a JVM of its own, so that the test's
 * JVM never holds them: an HMAC key, a webhook secret, an RSA and an EC key -
 * as PEM for the provider, and as DER and the RSA private exponent for the
 * heap search. Also a GitHub signature over a known body, which is public.
 *
 * <pre>args: directory</pre>
 */
public final class KeyMakerMain {

    static final String BODY = "{\"action\":\"opened\"}";

    private KeyMakerMain() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        SecureRandom random = new SecureRandom();
        String hmacKey = "hk-" + HexFormat.of().formatHex(random.generateSeed(24));
        String webhook = "whsec_" + HexFormat.of().formatHex(random.generateSeed(24));
        Files.writeString(directory.resolve("hmac-key"), hmacKey);
        Files.writeString(directory.resolve("webhook-secret"), webhook);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(webhook.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
        Files.writeString(directory.resolve("github-header"), "sha256="
                + HexFormat.of().formatHex(mac.doFinal(BODY.getBytes(StandardCharsets.UTF_8))));

        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(2048);
        KeyPair rsa = rsaGenerator.generateKeyPair();
        write(directory, "rsa", rsa);
        byte[] d = ((RSAPrivateCrtKey) rsa.getPrivate()).getPrivateExponent().toByteArray();
        Files.write(directory.resolve("rsa-d.bin"), d);

        KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
        ecGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        write(directory, "ec", ecGenerator.generateKeyPair());
    }

    private static void write(Path directory, String name, KeyPair pair) throws Exception {
        byte[] der = pair.getPrivate().getEncoded();
        Files.write(directory.resolve(name + ".der"), der);
        Files.writeString(directory.resolve(name + ".pem"), "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END PRIVATE KEY-----\n");
    }
}
