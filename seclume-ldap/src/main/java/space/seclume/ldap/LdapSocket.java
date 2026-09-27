package space.seclume.ldap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Arrays;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.SecretScope;

/**
 * The socket JNDI gets: encrypted with seclume's TLS when JNDI connects, and a
 * pipe for LDAP messages - each of which is looked at once, on its way out.
 *
 * <p>An LDAP message is BER: {@code SEQUENCE { messageID, protocolOp,
 * controls? }}. When the operation is a {@code BindRequest} ({@code
 * [APPLICATION 0]}) with a simple password ({@code [0]}) that is a seclume
 * placeholder, the message is written again with the real password - from the
 * secret provider, in native memory - and with the lengths of the three
 * enclosing elements, which follow from the password's length and are written
 * there too. Any other message, and a bind with any other password, goes out
 * as JNDI wrote it.
 */
final class LdapSocket extends Socket {

    private static final int SEQUENCE = 0x30;
    private static final int BIND_REQUEST = 0x60;
    private static final int SIMPLE = 0x80;
    private static final byte[] PREFIX =
            SeclumeLdap.PLACEHOLDER_PREFIX.getBytes(StandardCharsets.US_ASCII); // seclume-allow: the placeholder's prefix - no secret

    private final Object writing = new Object();
    private final ByteArrayOutputStream pending = new ByteArrayOutputStream();
    private volatile LdapSettings settings;
    private volatile SocketTransport transport;
    private volatile TlsLayer tls;
    private volatile boolean closed;
    private int timeout;

    @Override
    public void connect(SocketAddress address, int connectTimeout) throws IOException {
        if (transport != null) {
            throw new SocketException("already connected");
        }
        if (!(address instanceof InetSocketAddress inet)) {
            throw new SocketException("an LDAP server is a host and a port");
        }
        String authority = (inet.getHostString().indexOf(':') >= 0
                ? "[" + inet.getHostString() + "]" : inet.getHostString()) + ":" + inet.getPort();
        LdapSettings found = SeclumeLdap.BY_AUTHORITY.get(authority);
        if (found == null) {
            throw new SocketException(authority + " was not set up with SeclumeLdap.of(...) - "
                    + "its URL names the host and port JNDI connects to");
        }
        SocketTransport opened = SocketTransport.connect(found.host, found.port,
                connectTimeout > 0 ? connectTimeout : found.connectTimeout);
        try {
            opened.networkTimeout(timeout);
            tls = TrustChoice.using(found.trust, () -> {
                try {
                    return TlsLayers.start(TlsStack.SECLUME, opened, found.host, found.port, true);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });
            settings = found;
            transport = opened;
        } catch (SQLException e) {
            opened.close();
            throw e.getCause() instanceof IOException io ? io : new IOException(e.getMessage(), e);
        } catch (IOException | RuntimeException e) {
            opened.close();
            throw e;
        }
    }

    @Override
    public void connect(SocketAddress address) throws IOException {
        connect(address, 0);
    }

    private final InputStream in = new InputStream() {
        private final byte[] one = new byte[1];

        @Override
        public int read() throws IOException {
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] target, int offset, int length) throws IOException {
            if (length == 0) {
                return 0;
            }
            return open().read(ByteBuffer.wrap(target, offset, length));
        }

        @Override
        public void close() {
            LdapSocket.this.close();
        }
    };

    private final OutputStream out = new OutputStream() {
        @Override
        public void write(int value) throws IOException {
            write(new byte[] {(byte) value}, 0, 1);
        }

        @Override
        public void write(byte[] source, int offset, int length) throws IOException {
            synchronized (writing) {
                pending.write(source, offset, length);
                sendComplete();
            }
        }

        @Override
        public void close() {
            LdapSocket.this.close();
        }
    };

    /** Sends every whole message collected so far; a partial one waits for the rest. */
    private void sendComplete() throws IOException {
        byte[] bytes = pending.toByteArray();
        int at = 0;
        while (true) {
            long[] header = header(bytes, at);
            if (header == null || at + header[0] + header[1] > bytes.length) {
                break;
            }
            int end = (int) (at + header[0] + header[1]);
            send(Arrays.copyOfRange(bytes, at, end));
            at = end;
        }
        pending.reset();
        pending.write(bytes, at, bytes.length - at);
    }

    /**
     * The tag and length at {@code at}: {@code {header size, content length}},
     * or {@code null} while the header is not complete.
     */
    private static long[] header(byte[] b, int at) throws IOException {
        if (b.length - at < 2) {
            return null;
        }
        int first = b[at + 1] & 0xff;
        if (first < 0x80) {
            return new long[] {2, first};
        }
        int count = first & 0x7f;
        if (count == 0 || count > 4) {
            throw new IOException("an LDAP message with a BER length JNDI does not write");
        }
        if (b.length - at < 2 + count) {
            return null;
        }
        long length = 0;
        for (int i = 0; i < count; i++) {
            length = (length << 8) | (b[at + 2 + i] & 0xff);
        }
        return new long[] {2 + count, length};
    }

    private void send(byte[] message) throws IOException {
        if ((message[0] & 0xff) == SEQUENCE) {
            long[] outer = header(message, 0);
            int id = (int) outer[0];
            long[] idHeader = header(message, id);
            int op = (int) (id + idHeader[0] + idHeader[1]);
            if (op < message.length && (message[op] & 0xff) == BIND_REQUEST) {
                long[] bind = header(message, op);
                int version = (int) (op + bind[0]);
                long[] versionHeader = header(message, version);
                int name = (int) (version + versionHeader[0] + versionHeader[1]);
                long[] nameHeader = header(message, name);
                int auth = (int) (name + nameHeader[0] + nameHeader[1]);
                if (auth < message.length && (message[auth] & 0xff) == SIMPLE) {
                    long[] authHeader = header(message, auth);
                    int value = (int) (auth + authHeader[0]);
                    byte[] password = Arrays.copyOfRange(message, value,
                            (int) (value + authHeader[1]));
                    if (startsWith(password, PREFIX)) {
                        rewriteBind(message, op, bind, auth, authHeader, password);
                        return;
                    }
                }
            }
        }
        open().write(ByteBuffer.wrap(message));
    }

    private void rewriteBind(byte[] message, int op, long[] bind, int auth, long[] authHeader,
                             byte[] placeholder) throws IOException {
        LdapSettings registered = SeclumeLdap.BY_PLACEHOLDER.get(
                new String(placeholder, StandardCharsets.US_ASCII)); // seclume-allow: the placeholder - no secret
        if (registered == null) {
            throw new IOException("a seclume placeholder no SeclumeLdap.of(...) made - is the "
                    + "password from another instance's SeclumeLdap?");
        }
        int authEnd = (int) (auth + authHeader[0] + authHeader[1]);
        int opEnd = (int) (op + bind[0] + bind[1]);
        int bindBefore = auth - (int) (op + bind[0]);            // version and name
        int bindAfter = opEnd - authEnd;                          // nothing, usually
        int opStart = (int) header(message, 0)[0];                // the message id starts here
        int messageAfter = message.length - opEnd;                // controls
        try (SecretScope password = SecretScope.fromProvider(registered.secret)) {
            int secret = password.length();
            int authContent = secret;
            int bindContent = bindBefore + 1 + lengthSize(authContent) + authContent + bindAfter;
            int messageContent = (op - opStart) + 1 + lengthSize(bindContent) + bindContent
                    + messageAfter;
            int total = 1 + lengthSize(messageContent) + messageContent;
            try (SecretScope rewritten = SecretScope.allocate(total)) {
                MemorySegment w = rewritten.segment();
                int p = 0;
                w.set(ValueLayout.JAVA_BYTE, p++, (byte) SEQUENCE);
                p = putLength(w, p, messageContent);
                MemorySegment.copy(message, opStart, w, ValueLayout.JAVA_BYTE, p, op - opStart);
                p += op - opStart;
                w.set(ValueLayout.JAVA_BYTE, p++, (byte) BIND_REQUEST);
                p = putLength(w, p, bindContent);
                MemorySegment.copy(message, (int) (op + bind[0]), w, ValueLayout.JAVA_BYTE, p,
                        bindBefore);
                p += bindBefore;
                w.set(ValueLayout.JAVA_BYTE, p++, (byte) SIMPLE);
                p = putLength(w, p, authContent);
                MemorySegment.copy(password.segment(), 0, w, p, secret);
                p += secret;
                MemorySegment.copy(message, authEnd, w, ValueLayout.JAVA_BYTE, p, bindAfter);
                p += bindAfter;
                MemorySegment.copy(message, opEnd, w, ValueLayout.JAVA_BYTE, p, messageAfter);
                p += messageAfter;
                open().write(w.asSlice(0, p).asByteBuffer());
            }
        }
    }

    private static int lengthSize(int length) {
        return length < 0x80 ? 1 : length < 0x100 ? 2 : length < 0x10000 ? 3
                : length < 0x1000000 ? 4 : 5;
    }

    /** A BER length, byte by byte into native memory - it follows from the password's. */
    private static int putLength(MemorySegment w, int at, int length) {
        int size = lengthSize(length);
        if (size == 1) {
            w.set(ValueLayout.JAVA_BYTE, at, (byte) length);
            return at + 1;
        }
        w.set(ValueLayout.JAVA_BYTE, at, (byte) (0x80 | (size - 1)));
        for (int i = size - 1; i >= 1; i--) {
            w.set(ValueLayout.JAVA_BYTE, at + i, (byte) length);
            length >>>= 8;
        }
        return at + size;
    }

    private static boolean startsWith(byte[] value, byte[] prefix) {
        return value.length > prefix.length
                && Arrays.equals(value, 0, prefix.length, prefix, 0, prefix.length);
    }

    private TlsLayer open() throws IOException {
        TlsLayer current = tls;
        if (current == null || closed) {
            throw new SocketException(closed ? "closed" : "not connected");
        }
        return current;
    }

    // ---- what JNDI asks of a socket ----------------------------------------------

    @Override
    public InputStream getInputStream() throws IOException {
        open();
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        open();
        return out;
    }

    @Override
    public void setSoTimeout(int millis) throws SocketException {
        timeout = millis;
        SocketTransport current = transport;
        if (current != null) {
            try {
                current.networkTimeout(millis);
            } catch (IOException e) {
                throw new SocketException(e.getMessage());
            }
        }
    }

    @Override
    public int getSoTimeout() {
        return timeout;
    }

    @Override
    public void setTcpNoDelay(boolean on) {
        // seclume's transport sets it itself
    }

    @Override
    public void setKeepAlive(boolean on) {
        // seclume's transport decides
    }

    @Override
    public void setSoLinger(boolean on, int linger) {
        // the TLS close is seclume's
    }

    @Override
    public boolean isConnected() {
        return tls != null;
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public boolean isBound() {
        return tls != null;
    }

    @Override
    public boolean isInputShutdown() {
        return closed;
    }

    @Override
    public boolean isOutputShutdown() {
        return closed;
    }

    @Override
    public int getPort() {
        LdapSettings current = settings;
        return current == null ? 0 : current.port;
    }

    @Override
    public InetAddress getInetAddress() {
        LdapSettings current = settings;
        if (current == null) {
            return null;
        }
        try {
            return InetAddress.getByName(current.host);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    @Override
    public void close() {
        closed = true;
        TlsLayer current = tls;
        if (current != null) {
            try {
                current.close();
            } catch (Exception ignored) {
                // closing anyway
            }
        }
        SocketTransport raw = transport;
        if (raw != null) {
            raw.close();
        }
    }

    @Override
    public String toString() {
        LdapSettings current = settings;
        return "seclume LDAP socket" + (current == null ? "" : " to " + current.authority());
    }
}
