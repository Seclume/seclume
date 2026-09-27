package space.seclume.http;

import java.io.IOException;

/**
 * Where a bearer token comes from when it is not a stored secret: fetched with
 * client credentials ({@link OAuthToken}) or signed here ({@link SelfSignedJwt}).
 * Either writes the whole {@code Authorization} header line, renews what it
 * has before it runs out, and starts over when the API answers 401.
 */
interface BearerSource extends AutoCloseable {

    void writeHeader(HttpWire wire) throws IOException;

    /** The API refused what was sent: the next request gets a fresh one. */
    void invalidate();

    @Override
    void close();
}
