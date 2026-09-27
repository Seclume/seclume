package space.seclume.mail;

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
 * One connection to a mail server, the same for SMTP, IMAP and POP3: the
 * socket, seclume's own TLS 1.3 on top of it once it is encrypted, and lines
 * read and written.
 *
 * <p>Two things it does for all three protocols alike:
 *
 * <ul>
 *   <li><b>Encryption is seclume's own TLS</b>, not the JDK's: a credential
 *       written here goes from native memory into an encrypted record without
 *       a heap copy, which JSSE's record buffers would make.
 *   <li><b>Nothing sent before a STARTTLS takes effect is believed.</b> Bytes
 *       the server sent after its answer to STARTTLS (STLS on POP3) and before
 *       the handshake could have been injected by anyone on the path, to be
 *       taken as the first answers of the encrypted session (CVE-2011-0411
 *       and its many relatives). {@link #startTls} refuses the connection
 *       when there are any.
 * </ul>
 *
 * <p>Not thread-safe; one protocol exchange at a time.
 */
final class MailWire implements AutoCloseable {

    private static final int MAX_LINE = 8192;

    private final MailSettings settings;
    private final SocketTransport transport;
    private TlsLayer tls;
    private final ByteBuffer incoming = ByteBuffer.allocateDirect(16 * 1024).flip();
    private boolean open = true;

    private MailWire(MailSettings settings, SocketTransport transport) {
        this.settings = settings;
        this.transport = transport;
    }

    /** Connected, and encrypted already when the URL was {@code smtps}, {@code imaps} or {@code pop3s}. */
    static MailWire connect(MailSettings settings) throws IOException {
        SocketTransport transport = SocketTransport.connect(settings.host, settings.port,
                settings.connectTimeout);
        MailWire wire = new MailWire(settings, transport);
        try {
            transport.networkTimeout(settings.timeout);
            if (settings.implicitTls) {
                wire.encrypt();
            }
            return wire;
        } catch (IOException | RuntimeException e) {
            wire.close();
            throw e;
        }
    }

    /**
     * Encrypts a connection that has just been told to - after the server's
     * positive answer to STARTTLS or STLS, and only if nothing came after it.
     */
    void startTls() throws IOException {
        if (incoming.hasRemaining()) {
            throw new MailException(-1, "the server sent " + incoming.remaining()
                    + " bytes after its answer to STARTTLS and before the handshake - they "
                    + "could have been injected by anyone on the path, so the connection is "
                    + "refused");
        }
        encrypt();
    }

    private void encrypt() throws IOException {
        try {
            tls = TrustChoice.using(settings.trust, () -> {
                try {
                    return TlsLayers.start(TlsStack.SECLUME, transport, settings.host,
                            settings.port, true);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });
        } catch (SQLException e) {
            throw e.getCause() instanceof IOException io ? io : new IOException(e.getMessage(), e);
        }
    }

    boolean encrypted() {
        return tls != null;
    }

    MailSettings settings() {
        return settings;
    }

    /** A command line, CRLF added - for everything that holds no secret. */
    void writeLine(String line) throws IOException {
        write(ByteBuffer.wrap((line + "\r\n").getBytes(StandardCharsets.UTF_8))); // seclume-allow: a command line; credentials go through Sasl, off the heap
    }

    /** Writes all of {@code bytes}, encrypted when the connection is. */
    void write(ByteBuffer bytes) throws IOException {
        if (tls != null) {
            tls.write(bytes);
        } else {
            while (bytes.hasRemaining()) {
                transport.write(bytes);
            }
        }
    }

    /** One line without its CRLF - the server's words, never a secret. */
    String readLine() throws IOException {
        StringBuilder line = new StringBuilder(); // seclume-allow: a server reply, protocol text
        while (true) {
            while (incoming.hasRemaining()) {
                byte b = incoming.get();
                if (b == '\n') {
                    int end = line.length();
                    if (end > 0 && line.charAt(end - 1) == '\r') {
                        line.setLength(end - 1);
                    }
                    return line.toString();
                }
                if (line.length() >= MAX_LINE) {
                    throw new MailException(-1, "a line from " + settings.host
                            + " longer than " + MAX_LINE + " bytes");
                }
                line.append((char) (b & 0xff));
            }
            fill();
        }
    }

    /**
     * Raw bytes, for the protocol library the connection is handed to: what
     * is buffered first, then the connection. -1 at the end.
     */
    int read(ByteBuffer into) throws IOException {
        if (!incoming.hasRemaining()) {
            incoming.clear();
            int n = tls != null ? tls.read(incoming) : transport.read(incoming);
            incoming.flip();
            if (n < 0) {
                return -1;
            }
        }
        int n = Math.min(into.remaining(), incoming.remaining());
        ByteBuffer slice = incoming.slice(incoming.position(), n);
        into.put(slice);
        incoming.position(incoming.position() + n);
        return n;
    }

    private void fill() throws IOException {
        incoming.clear();
        int n = tls != null ? tls.read(incoming) : transport.read(incoming);
        incoming.flip();
        if (n < 0) {
            throw new MailException(-1, settings.host + " closed the connection");
        }
    }

    /** The read timeout, in milliseconds; 0 waits for ever. */
    void timeout(int millis) throws IOException {
        transport.networkTimeout(millis);
    }

    boolean isOpen() {
        return open;
    }

    @Override
    public void close() {
        if (!open) {
            return;
        }
        open = false;
        if (tls != null) {
            try {
                tls.close();
            } catch (Exception ignored) {
                // closing anyway
            }
        }
        transport.close();
    }
}
