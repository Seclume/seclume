package space.seclume.internal;

import java.io.IOException;
import java.util.Locale;
import java.util.ServiceLoader;

/**
 * Which {@link Transport} a connection gets, and who decides.
 *
 * <p>This library opens one kind: the {@link SocketTransport} over a
 * {@code SocketChannel}, which is what every driver has always used and what
 * every driver gets unless somebody says otherwise. Anything else arrives as a
 * {@link TransportProvider} on the class path and is asked for by name.
 *
 * <p>The system property {@code seclume.transport} decides, or the URL option
 * of the same name per connection. {@code socket} is the default; a name
 * ending in {@code -if-available} falls back to the socket where the provider
 * says it cannot run here, which is what a test run across platforms needs.
 *
 * <p><b>An unknown name is an error, not a silent fallback.</b> Someone who
 * asks for a transport and quietly gets another one debugs the wrong thing for
 * an afternoon.
 */
public final class Transports {

    private Transports() {
    }

    /** What to use when nobody says otherwise. */
    public static final String DEFAULT = "socket";

    /** The property read when a URL carries no preference. */
    public static final String PROPERTY = "seclume.transport";

    private static final String IF_AVAILABLE = "-if-available";

    public static Transport open(String kind, String host, int port, int connectTimeoutMillis)
            throws IOException {
        String wanted = kind == null || kind.isBlank()
                ? System.getProperty(PROPERTY, DEFAULT)
                : kind;
        String name = wanted.toLowerCase(Locale.ROOT);
        boolean orSocket = name.endsWith(IF_AVAILABLE);
        if (orSocket) {
            name = name.substring(0, name.length() - IF_AVAILABLE.length());
        }
        if (DEFAULT.equals(name)) {
            return SocketTransport.connect(host, port, connectTimeoutMillis);
        }
        for (TransportProvider provider : ServiceLoader.load(TransportProvider.class)) {
            if (!name.equalsIgnoreCase(provider.name())) {
                continue;
            }
            if (orSocket && !provider.available()) {
                return SocketTransport.connect(host, port, connectTimeoutMillis);
            }
            return provider.connect(host, port, connectTimeoutMillis);
        }
        if (orSocket) {
            return SocketTransport.connect(host, port, connectTimeoutMillis);
        }
        throw new IOException("unknown transport '" + wanted + "' - this library offers "
                + DEFAULT + ", and nothing on the class path offers that name");
    }
}
