package space.seclume.jwt;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;
import space.seclume.crypto.OpenSslSigningKey;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;

/**
 * A signing key named by one line - the algorithm, then the secret provider's
 * options, as in a seclume JDBC URL:
 *
 * <pre>
 * HS256?kid=2026-09&amp;provider=vault&amp;...                     an HMAC key
 * RS256?kid=app-1&amp;provider=file&amp;path=/run/secrets/key.pem   an RSA key, PEM or DER
 * ES256?provider=encrypted&amp;...                              an EC key, encrypted at rest
 * </pre>
 *
 * <p>An HMAC key is read from the provider for each use and wiped after it.
 * A private key is read once, decoded by OpenSSL and kept there - in OpenSSL's
 * memory, never the JVM's - until {@link #close()}.
 */
final class SigningKey implements AutoCloseable {

    enum Family { HMAC, RSA, RSA_PSS, EC }

    final String algorithm;
    final Family family;
    final String digest;
    final HashAlgorithm hash;
    final int ecField;
    final String kid;
    final Map<String, String> options;
    private final SecretProvider secret;
    private OpenSslSigningKey privateKey;          // guarded by this

    private SigningKey(String algorithm, Family family, String digest, HashAlgorithm hash,
                       int ecField, String kid, Map<String, String> options,
                       SecretProvider secret) {
        this.algorithm = algorithm;
        this.family = family;
        this.digest = digest;
        this.hash = hash;
        this.ecField = ecField;
        this.kid = kid;
        this.options = options;
        this.secret = secret;
    }

    /**
     * {@code ALG?options}. Options this module reads are taken out first
     * ({@code kid} and those named in {@code own}); the rest is the secret
     * provider's.
     */
    static SigningKey of(String spec, String... own) {
        int question = spec.indexOf('?');
        String algorithm = (question < 0 ? spec : spec.substring(0, question)).trim()
                .toUpperCase(Locale.ROOT);
        Map<String, String> options = new LinkedHashMap<>();
        if (question >= 0) {
            for (String pair : spec.substring(question + 1).split("&")) {
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    options.put(decode(pair.substring(0, equals)),
                            decode(pair.substring(equals + 1)));
                }
            }
        }
        String kid = options.remove("kid");
        Map<String, String> mine = new LinkedHashMap<>();
        for (String name : own) {
            String value = options.remove(name);
            if (value != null) {
                mine.put(name, value);
            }
        }
        if (!options.containsKey("provider")) {
            throw new IllegalArgumentException("no key named: add provider= and its options "
                    + "after the algorithm, e.g. HS256?provider=file&path=/run/secrets/jwt-key");
        }
        Family family;
        String digest;
        HashAlgorithm hash;
        int field = 0;
        switch (algorithm) {
            case "HS256", "RS256", "PS256", "ES256" -> {
                digest = "SHA256";
                hash = HashAlgorithm.SHA_256;
                field = 32;
            }
            case "HS384", "RS384", "PS384", "ES384" -> {
                digest = "SHA384";
                hash = HashAlgorithm.SHA_384;
                field = 48;
            }
            case "HS512", "RS512", "PS512", "ES512" -> {
                digest = "SHA512";
                hash = HashAlgorithm.SHA_512;
                field = 66;
            }
            default -> throw new IllegalArgumentException("the algorithm is one of HS256, HS384, "
                    + "HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512 - "
                    + "not '" + algorithm + "' (and never 'none')");
        }
        family = switch (algorithm.charAt(0)) {
            case 'H' -> Family.HMAC;
            case 'R' -> Family.RSA;
            case 'P' -> Family.RSA_PSS;
            default -> Family.EC;
        };
        if (family != Family.HMAC && !OpenSslSigningKey.available()) {
            throw new IllegalStateException(algorithm + " signs with OpenSSL 3, which needs "
                    + "64-bit Linux; HS256/384/512 work everywhere");
        }
        if (family != Family.HMAC && !options.containsKey("max-length")
                && !options.containsKey("maxLength")) {
            // a PEM private key is a few kilobytes - RSA-4096 about 3.3 KB
            options.put("max-length", "16384");
        }
        return new SigningKey(algorithm, family, digest, hash,
                family == Family.EC ? field : 0, kid, mine, SecretProviders.of(options));
    }

    /** For a caller that has built its own provider - OAuth's private_key_jwt. */
    static SigningKey of(String algorithm, String kid, SecretProvider secret) {
        SigningKey parsed = of(algorithm + "?provider=none");
        parsed.secret.close();
        return new SigningKey(parsed.algorithm, parsed.family, parsed.digest, parsed.hash,
                parsed.ecField, kid, Map.of(), secret);
    }

    /** The signature over {@code input} - public, and so on the heap. */
    byte[] sign(byte[] input) {
        return family == Family.HMAC ? mac(input) : signPrivate(input);
    }

    /** HMAC over the concatenation of {@code parts}, the key read and wiped around it. */
    byte[] mac(byte[]... parts) {
        try (SecretScope key = SecretScope.fromProvider(secret)) {
            if (key.length() < hash.digestLength()) {
                throw new IllegalStateException(algorithm + " needs a key of at least "
                        + hash.digestLength() + " bytes (RFC 7518 3.2); a shorter one can be "
                        + "guessed");
            }
            try (Hmac hmac = new Hmac(hash, key.segment(), 0, key.length());
                 Arena arena = Arena.ofConfined()) {
                for (byte[] part : parts) {
                    hmac.update(MemorySegment.ofArray(part), 0, part.length);
                }
                MemorySegment out = arena.allocate(hash.digestLength());
                hmac.doFinal(out, 0);
                return out.toArray(ValueLayout.JAVA_BYTE);
            }
        }
    }

    private byte[] signPrivate(byte[] input) {
        OpenSslSigningKey key = privateKey();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment message = arena.allocate(Math.max(1, input.length));
            MemorySegment.copy(input, 0, message, ValueLayout.JAVA_BYTE, 0, input.length);
            MemorySegment out = arena.allocate(OpenSslSigningKey.MAX_SIGNATURE);
            int n;
            synchronized (this) {
                n = key.sign(digest, family == Family.RSA_PSS, message, input.length, out);
            }
            byte[] signature = out.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE);
            return family == Family.EC ? OpenSslSigningKey.rawEcdsa(signature, ecField)
                    : signature;
        }
    }

    private synchronized OpenSslSigningKey privateKey() {
        if (privateKey == null) {
            try (SecretScope encoded = SecretScope.fromProvider(secret)) {
                OpenSslSigningKey decoded = OpenSslSigningKey.decode(encoded.segment(),
                        encoded.length());
                boolean fits = family == Family.EC ? decoded.is("EC")
                        : decoded.is("RSA") || decoded.is("RSA-PSS");
                if (!fits) {
                    decoded.close();
                    throw new IllegalStateException(algorithm + " needs "
                            + (family == Family.EC ? "an EC" : "an RSA") + " key, and the one "
                            + "given is not");
                }
                privateKey = decoded;
            }
        }
        return privateKey;
    }

    @Override
    public synchronized void close() {
        if (privateKey != null) {
            privateKey.close();
            privateKey = null;
        }
        secret.close();
    }

    private static String decode(String text) {
        return java.net.URLDecoder.decode(text, StandardCharsets.UTF_8);
    }
}
