package space.seclume.jwt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest; // seclume-allow: constant-time comparison of a public MAC
import java.time.Clock;
import java.time.Duration;
import java.util.Base64; // seclume-allow: the MAC as the webhook header spells it - public
import java.util.HexFormat; // seclume-allow: the MAC in hex - public
import java.util.Locale;

/**
 * Webhook signatures checked with a shared secret that stays off the heap -
 * GitHub's, Stripe's, and any other HMAC over a request body.
 *
 * <pre>
 * SeclumeHmac github = SeclumeHmac.of("SHA256?provider=vault&amp;...");
 * if (!github.verifyGitHub(request.getHeader("X-Hub-Signature-256"), body)) { ... 401 ... }
 *
 * SeclumeHmac stripe = SeclumeHmac.of("SHA256?provider=file&amp;path=/run/secrets/stripe-whsec");
 * stripe.verifyStripe(request.getHeader("Stripe-Signature"), body, Duration.ofMinutes(5));
 * </pre>
 *
 * <p>The secret is read from its provider for each check and the HMAC is
 * computed in native memory; the comparison is in constant time. Everything
 * else - the body, the header, the MAC - is public.
 */
public final class SeclumeHmac implements AutoCloseable {

    private final SigningKey key;
    private Clock clock = Clock.systemUTC();

    private SeclumeHmac(SigningKey key) {
        this.key = key;
    }

    /** {@code SHA256?provider=...} (or {@code SHA384}, {@code SHA512}). */
    public static SeclumeHmac of(String spec) {
        String upper = spec.toUpperCase(Locale.ROOT);
        for (String bits : new String[] {"256", "384", "512"}) {
            if (upper.startsWith("SHA" + bits + "?") || upper.startsWith("SHA-" + bits + "?")) {
                return new SeclumeHmac(SigningKey.of("HS" + bits + spec.substring(
                        spec.indexOf('?'))));
            }
        }
        throw new IllegalArgumentException("an HMAC is SHA256, SHA384 or SHA512 followed by "
                + "?provider=... - not '" + spec.substring(0, Math.max(0, spec.indexOf('?')))
                + "'");
    }

    SeclumeHmac clock(Clock clock) {
        this.clock = clock;
        return this;
    }

    /** The HMAC over the concatenation of {@code parts}. */
    public byte[] mac(byte[]... parts) {
        return key.mac(parts);
    }

    /** Whether {@code signature} - hex, either case - is the HMAC of {@code parts}. */
    public boolean verifyHex(String signature, byte[]... parts) {
        byte[] given;
        try {
            given = HexFormat.of().parseHex(signature.trim().toLowerCase(Locale.ROOT)); // seclume-allow: the signature the sender put in the header - public
        } catch (IllegalArgumentException e) {
            return false;
        }
        return MessageDigest.isEqual(mac(parts), given);
    }

    /** Whether {@code signature} - base64 - is the HMAC of {@code parts}. */
    public boolean verifyBase64(String signature, byte[]... parts) {
        byte[] given;
        try {
            given = Base64.getDecoder().decode(signature.trim()); // seclume-allow: the signature the sender put in the header - public
        } catch (IllegalArgumentException e) {
            return false;
        }
        return MessageDigest.isEqual(mac(parts), given);
    }

    /** GitHub's {@code X-Hub-Signature-256: sha256=<hex>}. */
    public boolean verifyGitHub(String header, byte[] body) {
        return header != null && header.startsWith("sha256=") && key.algorithm.equals("HS256")
                && verifyHex(header.substring(7), body);
    }

    /**
     * Stripe's {@code Stripe-Signature: t=<seconds>,v1=<hex>[,v1=...]} over
     * {@code t.body}, with the timestamp no further off than {@code tolerance}.
     */
    public boolean verifyStripe(String header, byte[] body, Duration tolerance) {
        if (header == null || !key.algorithm.equals("HS256")) {
            return false;
        }
        String timestamp = null;
        for (String part : header.split(",")) {
            if (part.startsWith("t=")) {
                timestamp = part.substring(2);
            }
        }
        if (timestamp == null) {
            return false;
        }
        long seconds;
        try {
            seconds = Long.parseLong(timestamp);
        } catch (NumberFormatException e) {
            return false;
        }
        if (Math.abs(clock.instant().getEpochSecond() - seconds) > tolerance.toSeconds()) {
            return false;
        }
        byte[] prefix = (timestamp + ".").getBytes(StandardCharsets.US_ASCII); // seclume-allow: the Stripe timestamp - public
        for (String part : header.split(",")) {
            if (part.startsWith("v1=") && verifyHex(part.substring(3), prefix, body)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void close() {
        key.close();
    }
}
