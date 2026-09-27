package space.seclume.http;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;

/**
 * One HTTPS connection: the socket and seclume's own TLS 1.3 on it - so that
 * a credential written here goes from native memory into an encrypted record
 * without a heap copy, which JSSE's record buffers would make. Reads are
 * buffered for the response parser.
 *
 * <p>Not thread-safe; one exchange at a time, which the pool ensures.
 */
final class HttpWire implements AutoCloseable {

    private final HttpSettings settings;
    private final SocketTransport transport;
    private final TlsLayer tls;
    private final ByteBuffer incoming = ByteBuffer.allocateDirect(16 * 1024).flip();
    private boolean open = true;
    private long idleSince;

    private HttpWire(HttpSettings settings, SocketTransport transport, TlsLayer tls) {
        this.settings = settings;
        this.transport = transport;
        this.tls = tls;
    }

    /** Connected and encrypted, the server's certificate checked. */
    static HttpWire connect(HttpSettings settings) throws IOException {
        SocketTransport transport = SocketTransport.connect(settings.host, settings.port,
                settings.connectTimeout);
        try {
            transport.networkTimeout(settings.timeout);
            TlsLayer tls = TrustChoice.using(settings.trust, () -> {
                try {
                    return TlsLayers.start(TlsStack.SECLUME, transport, settings.host,
                            settings.port, true);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });
            return new HttpWire(settings, transport, tls);
        } catch (SQLException e) {
            transport.close();
            throw e.getCause() instanceof IOException io ? io : new IOException(e.getMessage(), e);
        } catch (IOException | RuntimeException e) {
            transport.close();
            throw e;
        }
    }

    void write(ByteBuffer bytes) throws IOException {
        tls.write(bytes);
    }

    /** Protocol text - the request line and headers, never a secret. */
    void writeAscii(String text) throws IOException {
        write(ByteBuffer.wrap(text.getBytes(StandardCharsets.ISO_8859_1))); // seclume-allow: the request line and the application's headers - the credential goes through Credential, off the heap
    }

    /**
     * A line of the response head without its CRLF, as ISO-8859-1 - or null
     * when the connection ended before the first byte of it.
     */
    String readLine(int max) throws IOException {
        StringBuilder line = new StringBuilder(); // seclume-allow: the server's status line and headers
        boolean any = false;
        while (true) {
            while (incoming.hasRemaining()) {
                byte b = incoming.get();
                any = true;
                if (b == '\n') {
                    int end = line.length();
                    if (end > 0 && line.charAt(end - 1) == '\r') {
                        line.setLength(end - 1);
                    }
                    return line.toString();
                }
                if (line.length() >= max) {
                    throw new IOException("a line of the response from " + settings.host
                            + " is longer than " + max + " bytes");
                }
                line.append((char) (b & 0xff));
            }
            if (!fill()) {
                if (!any) {
                    return null;
                }
                throw new IOException(settings.host + " closed the connection in the middle "
                        + "of the response head");
            }
        }
    }

    /** Up to {@code length} bytes of the body; -1 at the end of the connection. */
    int read(byte[] into, int offset, int length) throws IOException {
        if (!incoming.hasRemaining() && !fill()) {
            return -1;
        }
        int n = Math.min(length, incoming.remaining());
        incoming.get(into, offset, n);
        return n;
    }

    private boolean fill() throws IOException {
        incoming.clear();
        int n = tls.read(incoming);
        incoming.flip();
        return n >= 0;
    }

    /** Nothing of a previous response left over - the precondition for reuse. */
    boolean drained() {
        return !incoming.hasRemaining();
    }

    void idle() {
        idleSince = System.nanoTime();
    }

    boolean staleAfter(long idleTimeoutMillis) {
        return System.nanoTime() - idleSince > idleTimeoutMillis * 1_000_000L;
    }

    boolean isOpen() {
        return open && transport.isOpen();
    }

    @Override
    public void close() {
        if (!open) {
            return;
        }
        open = false;
        try {
            tls.close();
        } catch (Exception ignored) {
            // closing anyway
        }
        transport.close();
    }
}
