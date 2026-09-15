package space.seclume.internal;

import java.io.IOException;
import java.util.Locale;

/**
 * Which {@link Transport} a connection gets, and who decides.
 *
 * <p>Two exist: the {@link SocketTransport} over a {@code SocketChannel}, which
  * is what every driver has always used, and another implementation over a
  * descriptor of our own. The second
 * is <b>not</b> the default and will not become it by being newer.
 *
 * <p>The system property {@code seclume.transport} decides, or the URL option
 * of the same name per connection. Values: {@code socket} (the default),
 * {@code ffm}, and {@code ffm-if-available} - the last one for a test run that
 * should use the new route on Linux and still pass everywhere else.
 */
public final class Transports {

    private Transports() {
    }

    /** What to use when nobody says otherwise. */
    public static final String DEFAULT = "socket";

    /** The property read when a URL carries no preference. */
    public static final String PROPERTY = "seclume.transport";

    public static Transport open(String kind, String host, int port, int connectTimeoutMillis)
            throws IOException {
        String wanted = kind == null || kind.isBlank()
                ? System.getProperty(PROPERTY, DEFAULT)
                : kind;
        return switch (wanted.toLowerCase(Locale.ROOT)) {
            case "socket" -> SocketTransport.connect(host, port, connectTimeoutMillis);
        // the alternate transport, developed separately
        // the alternate transport, developed separately
        // the alternate transport, developed separately
                    : SocketTransport.connect(host, port, connectTimeoutMillis);
            default -> throw new IOException("unknown transport '" + wanted
                    + "' - expected socket, ffm or ffm-if-available");
        };
    }
}
