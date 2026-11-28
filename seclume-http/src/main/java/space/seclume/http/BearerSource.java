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

    /**
     * The API answered 401: whether to start over with a fresh one now. A
     * source that fetches its token may say no to one fetched a moment ago -
     * an API that answers 401 to everything would otherwise have every
     * request fetch a token.
     */
    default boolean refusedByApi() {
        invalidate();
        return true;
    }

    @Override
    void close();
}
