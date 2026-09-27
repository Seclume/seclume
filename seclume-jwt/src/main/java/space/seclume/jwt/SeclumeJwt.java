package space.seclume.jwt;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest; // seclume-allow: constant-time comparison of a public signature
import java.time.Clock;
import java.time.Duration;
import java.util.Base64; // seclume-allow: base64url of header, claims and signature - public
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import space.seclume.internal.JsonOff;

/**
 * JWTs signed - and, for HMAC keys, checked - with a key that stays off the
 * heap.
 *
 * <pre>
 * SeclumeJwt jwt = SeclumeJwt.of("HS256?kid=2026-09&amp;provider=vault&amp;...");
 * String token = jwt.sign(Map.of("sub", "user-42", "exp", now + 900));
 * String claims = jwt.verify(token);      // the payload's JSON, or an exception
 *
 * SeclumeJwt rsa = SeclumeJwt.of("RS256?kid=app-1&amp;provider=file&amp;path=/run/secrets/key.pem");
 * </pre>
 *
 * <p>The key is what a heap dump must not give away: with it, anyone can make
 * a token for any user. An HMAC key is read from its provider for each use and
 * computed on in native memory; an RSA or EC key is decoded and held by
 * OpenSSL. What is on the heap is public - the claims, the token, the
 * signature.
 *
 * <p>{@link #verify} is for tokens signed with this HMAC key. It takes the
 * algorithm from the key, never from the token - a token that names another
 * one, {@code none} included, is refused - compares the signature in constant
 * time, and checks {@code exp} and {@code nbf} when they are there. A token
 * signed with a private key is checked with the public key, which is no secret
 * and any JWT library will do.
 */
public final class SeclumeJwt implements AutoCloseable {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding(); // seclume-allow: JWS header, claims, signature or MAC - public
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder(); // seclume-allow: JWS header, claims, signature or MAC - public

    private final SigningKey key;
    private final Duration leeway;
    private Clock clock = Clock.systemUTC();

    private SeclumeJwt(SigningKey key, Duration leeway) {
        this.key = key;
        this.leeway = leeway;
    }

    /**
     * {@code ALG?kid=...&provider=...} - see the class comment; {@code leeway=}
     * seconds of clock difference allowed for {@code exp} and {@code nbf}
     * (60 by default).
     */
    public static SeclumeJwt of(String spec) {
        SigningKey key = SigningKey.of(spec, "leeway");
        String leeway = key.options.get("leeway");
        return new SeclumeJwt(key, Duration.ofSeconds(leeway == null ? 60
                : Long.parseLong(leeway)));
    }

    /**
     * A signer over a provider the caller has already made - for a library
     * that reads its own configuration, as seclume-http's private_key_jwt does.
     */
    public static SeclumeJwt of(String algorithm, String kid,
                                space.seclume.secret.SecretProvider key) {
        return new SeclumeJwt(SigningKey.of(algorithm, kid, key), Duration.ofSeconds(60));
    }

    /** For tests: the clock {@code exp} and {@code nbf} are checked against. */
    SeclumeJwt clock(Clock clock) {
        this.clock = clock;
        return this;
    }

    /** The algorithm, e.g. {@code RS256}. */
    public String algorithm() {
        return key.algorithm;
    }

    /** A token with these claims - strings, numbers, booleans, lists and maps. */
    public String sign(Map<String, ?> claims) {
        return sign(Map.of(), claims);
    }

    /**
     * The same with header parameters of the caller's - {@code x5t}, say.
     * {@code alg} and {@code kid} are this key's; {@code typ} is {@code JWT}
     * unless given.
     */
    public String sign(Map<String, ?> header, Map<String, ?> claims) {
        Map<String, Object> full = new LinkedHashMap<>();
        full.put("alg", key.algorithm);
        full.put("typ", "JWT");
        if (key.kid != null) {
            full.put("kid", key.kid);
        }
        header.forEach((name, value) -> {
            if (!name.equals("alg")) {
                full.put(name, value);
            }
        });
        return signJson(json(full), json(claims));
    }

    /** A token over a payload that is already JSON. */
    public String sign(String payloadJson) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", key.algorithm);
        header.put("typ", "JWT");
        if (key.kid != null) {
            header.put("kid", key.kid);
        }
        return signJson(json(header), payloadJson);
    }

    private String signJson(String headerJson, String payloadJson) {
        String input = ENCODER.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)) + "." // seclume-allow: JWS header, claims, signature or MAC - public
                + ENCODER.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8)); // seclume-allow: JWS header, claims, signature or MAC - public
        byte[] signature = key.sign(input.getBytes(StandardCharsets.US_ASCII)); // seclume-allow: JWS header, claims, signature or MAC - public
        return input + "." + ENCODER.encodeToString(signature);
    }

    /**
     * The payload of a token signed with this HMAC key, as JSON - or an
     * {@link InvalidTokenException} saying what is wrong with it.
     */
    public String verify(String token) {
        if (key.family != SigningKey.Family.HMAC) {
            throw new IllegalStateException(key.algorithm + " tokens are checked with the "
                    + "public key, which is no secret - any JWT library does that");
        }
        int first = token.indexOf('.');
        int second = token.indexOf('.', first + 1);
        if (first < 0 || second < 0 || token.indexOf('.', second + 1) >= 0) {
            throw new InvalidTokenException("not a compact JWS: three parts separated by dots");
        }
        byte[] header;
        byte[] payload;
        byte[] signature;
        try {
            header = DECODER.decode(token.substring(0, first));
            payload = DECODER.decode(token.substring(first + 1, second));
            signature = DECODER.decode(token.substring(second + 1));
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("a part of the token is not base64url", e);
        }
        String alg = field(header, "alg");
        if (!key.algorithm.equals(alg)) {
            throw new InvalidTokenException("the token says alg " + alg + ", this key is "
                    + key.algorithm);
        }
        byte[] expected = key.mac(token.substring(0, second).getBytes(StandardCharsets.US_ASCII)); // seclume-allow: JWS header, claims, signature or MAC - public
        if (!MessageDigest.isEqual(expected, signature)) {
            throw new InvalidTokenException("the signature does not match");
        }
        long now = clock.instant().getEpochSecond();
        Long exp = number(payload, "exp");
        if (exp != null && now - leeway.toSeconds() >= exp) {
            throw new InvalidTokenException("the token expired at " + exp);
        }
        Long nbf = number(payload, "nbf");
        if (nbf != null && now + leeway.toSeconds() < nbf) {
            throw new InvalidTokenException("the token is not valid before " + nbf);
        }
        return new String(payload, StandardCharsets.UTF_8); // seclume-allow: the claims - public, the application's data
    }

    private static String field(byte[] json, String name) {
        MemorySegment segment = MemorySegment.ofArray(json);
        if (!JsonOff.has(segment, json.length, name)) {
            return null;
        }
        byte[] out = new byte[json.length];
        try {
            int n = JsonOff.string(segment, json.length, MemorySegment.ofArray(out), name);
            return new String(out, 0, n, StandardCharsets.UTF_8); // seclume-allow: a JWT header field - public
        } catch (JsonOff.NotFound e) {
            throw new InvalidTokenException(name + " is not a string", e);
        }
    }

    private static Long number(byte[] json, String name) {
        MemorySegment segment = MemorySegment.ofArray(json);
        if (!JsonOff.has(segment, json.length, name)) {
            return null;
        }
        try {
            return JsonOff.number(segment, json.length, name);
        } catch (JsonOff.NotFound e) {
            throw new InvalidTokenException(name + " is not a whole number", e);
        }
    }

    // ---- JSON for claims and headers - public data -----------------------------

    static String json(Object value) {
        StringBuilder out = new StringBuilder(); // seclume-allow: claims and header, public
        write(out, value);
        return out.toString();
    }

    private static void write(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String text) {
            quote(out, text);
        } else if (value instanceof Number || value instanceof Boolean) {
            out.append(value);
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                quote(out, String.valueOf(entry.getKey()));
                out.append(':');
                write(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof Collection<?> list) {
            out.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                write(out, item);
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("a claim is a string, number, boolean, list or "
                    + "map, not " + value.getClass().getName());
        }
    }

    private static void quote(StringBuilder out, String text) {
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    @Override
    public void close() {
        key.close();
    }
}
