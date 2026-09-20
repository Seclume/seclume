package space.seclume.internal.jdbc;

import java.nio.charset.StandardCharsets;
import java.sql.RowId;
import java.util.Arrays;

/**
 * A {@link RowId} that carries the server's own row address and nothing else.
 *
 * <p>JDBC is careful about what a {@code RowId} is: an opaque token, valid
 * only within the database it came from, comparable only with another token
 * from the same place, and with a lifetime the driver has to be honest about.
 * The one thing it is <b>not</b> is a number an application may reason about.
 * So this class stores the bytes the server sent and offers no way to turn
 * them into anything but themselves.
 *
 * <p>{@link #toString} returns the server's textual form - PostgreSQL's
 * {@code (0,7)}, Oracle's {@code AAAR3sAAEAAAACHAAA} - because that is what
 * the value looks like in a query, and a log line that says
 * {@code [B@1b6d3586} helps nobody.
 *
 * <p>Two of these are equal when their bytes are. Comparing a token from one
 * connection with one from another database is the caller's mistake, and one
 * this class cannot detect; JDBC says as much.
 */
public final class OpaqueRowId implements RowId {

    private final byte[] token;
    private final String text;

    /** From the server's textual form, which is how all four spell a row address. */
    public OpaqueRowId(String text) {
        this.text = text;
        // seclume-allow: a row address is user-visible payload, not a secret
        this.token = text.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public byte[] getBytes() {
        return token.clone(); // seclume-allow: a row address, not a secret
    }

    @Override
    public String toString() {
        return text;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof OpaqueRowId that && Arrays.equals(token, that.token);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(token);
    }
}
