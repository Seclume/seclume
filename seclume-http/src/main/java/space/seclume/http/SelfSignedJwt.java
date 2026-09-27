package space.seclume.http;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import space.seclume.jwt.SeclumeJwt;
import space.seclume.secret.SecretProvider;

/**
 * {@code auth=jwt}: a JWT the client signs itself and sends as the bearer
 * token - the way GitHub Apps, Google service accounts, Apple, Zoom and many
 * service meshes take it. No secret goes over the wire, only a short proof
 * signed with a key that OpenSSL holds (RS, PS, ES) or that is read per use
 * (HS).
 *
 * <p>The token is reused until {@code min(30 s, ttl/10)} before it expires,
 * and signed afresh after a 401. {@code iat} is set a minute back, as GitHub
 * asks, for clocks that do not agree. Like any bearer token it is a credential
 * while it lasts, and it is on the heap as the String it is sent as; the key
 * that makes it is not.
 */
final class SelfSignedJwt implements BearerSource {

    private final JwtSettings jwt;
    private final SeclumeJwt signer;
    private String token;                   // guarded by this
    private long renewAt;                   // epoch seconds

    SelfSignedJwt(JwtSettings jwt, SecretProvider key) {
        this.jwt = jwt;
        this.signer = SeclumeJwt.of(jwt.algorithm, jwt.kid, key);
    }

    @Override
    public void writeHeader(HttpWire wire) throws IOException {
        wire.writeAscii("Authorization: Bearer " + current() + "\r\n");
    }

    private synchronized String current() {
        long now = Instant.now().getEpochSecond();
        if (token == null || now >= renewAt) {
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", jwt.issuer);
            if (jwt.subject != null) {
                claims.put("sub", jwt.subject);
            }
            if (jwt.audience != null) {
                claims.put("aud", jwt.audience);
            }
            claims.put("iat", now - 60);
            claims.put("exp", now + jwt.ttlSeconds);
            token = signer.sign(claims);
            renewAt = now + jwt.ttlSeconds - Math.min(30, jwt.ttlSeconds / 10);
        }
        return token;
    }

    @Override
    public synchronized void invalidate() {
        token = null;
    }

    @Override
    public synchronized void close() {
        token = null;
        signer.close();
    }
}
