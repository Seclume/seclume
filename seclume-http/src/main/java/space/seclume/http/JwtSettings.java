package space.seclume.http;

import java.util.Map;

/**
 * {@code auth=jwt}: {@code jwt-iss} (required - the app id, the service
 * account), {@code jwt-sub}, {@code jwt-aud}, {@code jwt-ttl} in seconds (300
 * by default; GitHub takes at most 600), {@code jwt-alg} (RS256 by default;
 * PS, ES and HS as well) and {@code jwt-kid}. The secret provider's options
 * name the key.
 */
final class JwtSettings {

    final String algorithm;
    final String issuer;
    final String subject;
    final String audience;
    final String kid;
    final long ttlSeconds;

    private JwtSettings(String algorithm, String issuer, String subject, String audience,
                        String kid, long ttlSeconds) {
        this.algorithm = algorithm;
        this.issuer = issuer;
        this.subject = subject;
        this.audience = audience;
        this.kid = kid;
        this.ttlSeconds = ttlSeconds;
    }

    static JwtSettings take(Map<String, String> options) {
        String algorithm = options.remove("jwt-alg");
        String issuer = options.remove("jwt-iss");
        String subject = options.remove("jwt-sub");
        String audience = options.remove("jwt-aud");
        String kid = options.remove("jwt-kid");
        String ttl = options.remove("jwt-ttl");
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("auth=jwt needs jwt-iss= - who signs: the app "
                    + "id, the service account");
        }
        long ttlSeconds;
        try {
            ttlSeconds = ttl == null ? 300 : Long.parseLong(ttl);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("jwt-ttl is a number of seconds, not '" + ttl
                    + "'", e);
        }
        if (ttlSeconds < 30 || ttlSeconds > 86_400) {
            throw new IllegalArgumentException("jwt-ttl is between 30 seconds and a day, not "
                    + ttlSeconds);
        }
        String alg = algorithm == null ? "RS256" : algorithm;
        if (!alg.toUpperCase(java.util.Locale.ROOT).startsWith("HS")
                && !options.containsKey("max-length") && !options.containsKey("maxLength")) {
            options.put("max-length", "16384");                  // a PEM private key
        }
        return new JwtSettings(alg, issuer, subject, audience, kid, ttlSeconds);
    }
}
