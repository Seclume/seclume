package space.seclume.mail;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import javax.net.SocketFactory;

/**
 * The socket Jakarta Mail gets for IMAP and POP3: already connected,
 * encrypted and logged in by seclume when Jakarta Mail asks it to connect.
 *
 * <p>Angus Mail makes its sockets with {@code createSocket()} and then calls
 * {@code connect()}; this is where the work happens. The login is seclume's
 * ({@link ImapLogin}, {@link Pop3Login}), the credential written from native
 * memory. Then Jakarta Mail is told it is in:
 *
 * <ul>
 *   <li><b>IMAP</b> has a word for it. The greeting Jakarta Mail reads is
 *       {@code * PREAUTH} (RFC 9051), and it skips its own login - its first
 *       command goes to the server, which answers as the logged-in user.
 *   <li><b>POP3</b> has none. The greeting is {@code +OK}; the session is set
 *       so that Jakarta Mail logs in with USER and PASS (no CAPA, no APOP, no
 *       SASL), and those two commands are answered here with {@code +OK} and
 *       never reach the server - they carry the placeholder password, not a
 *       real one. Everything after them goes through.
 * </ul>
 *
 * <p>From then on this is a pipe: bytes Jakarta Mail writes go to the server,
 * encrypted, and what the server answers comes back.
 */
final class MailSocket extends Socket {

    private final MailSettings settings;
    private final Object writing = new Object();
    private volatile MailWire wire;
    private volatile boolean closed;
    private int timeout;

    /** Answers made here rather than by the server - the greeting, POP3's login. */
    private final Object answers = new Object();
    private ByteBuffer local = ByteBuffer.allocate(512).flip(); // seclume-allow: greetings and +OK made here - protocol text, never a secret
    /** POP3 before PASS: Jakarta Mail's login, a line at a time. */
    private boolean pop3Login;
    private final StringBuilder line = new StringBuilder(); // seclume-allow: Jakarta Mail's POP3 commands before PASS - the placeholder, never a secret

    MailSocket(MailSettings settings) {
        this.settings = settings;
    }

    /** The factory Jakarta Mail is given, as {@code mail.imap(s).socketFactory} and so on. */
    static SocketFactory factory(MailSettings settings) {
        return new SocketFactory() {
            @Override
            public Socket createSocket() {
                return new MailSocket(settings);
            }

            @Override
            public Socket createSocket(String host, int port) throws IOException {
                Socket socket = createSocket();
                socket.connect(null);
                return socket;
            }

            @Override
            public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
                    throws IOException {
                return createSocket(host, port);
            }

            @Override
            public Socket createSocket(InetAddress host, int port) throws IOException {
                return createSocket(host.getHostName(), port);
            }

            @Override
            public Socket createSocket(InetAddress host, int port, InetAddress localAddress,
                                       int localPort) throws IOException {
                return createSocket(host.getHostName(), port);
            }
        };
    }

    // ---- connecting is logging in ------------------------------------------

    /**
     * Connects where the URL says - not where Jakarta Mail asks, which is only
     * ever the host and port the session was given for the same URL.
     */
    @Override
    public void connect(SocketAddress ignored, int connectTimeout) throws IOException {
        if (wire != null) {
            throw new SocketException("already connected");
        }
        MailWire opened = settings.protocol == MailSettings.Protocol.IMAP
                ? ImapLogin.open(settings) : Pop3Login.open(settings);
        if (timeout > 0) {
            opened.timeout(timeout);
        }
        String greeting = settings.protocol == MailSettings.Protocol.IMAP
                ? "* PREAUTH [seclume] logged in as " + settings.user + "\r\n"
                : "+OK [seclume] logged in as " + settings.user + "\r\n";
        answer(greeting);
        pop3Login = settings.protocol == MailSettings.Protocol.POP3;
        wire = opened;
    }

    @Override
    public void connect(SocketAddress ignored) throws IOException {
        connect(ignored, 0);
    }

    // ---- the pipe -------------------------------------------------------------

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
            synchronized (answers) {
                if (local.hasRemaining()) {
                    int n = Math.min(length, local.remaining());
                    local.get(target, offset, n);
                    return n;
                }
            }
            return open().read(ByteBuffer.wrap(target, offset, length));
        }

        @Override
        public int available() {
            synchronized (answers) {
                return local.remaining();
            }
        }

        @Override
        public void close() throws IOException {
            MailSocket.this.close();
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
                int at = offset;
                int end = offset + length;
                while (pop3Login && at < end) {
                    char c = (char) (source[at++] & 0xff);
                    line.append(c);
                    if (c == '\n') {
                        loginLine(line.toString().trim());
                        line.setLength(0);
                    }
                }
                if (at < end) {
                    open().write(ByteBuffer.wrap(source, at, end - at));
                }
            }
        }

        @Override
        public void close() throws IOException {
            MailSocket.this.close();
        }
    };

    /**
     * POP3, before the login is over: Jakarta Mail's USER and PASS are
     * answered here and go nowhere; so is anything else it might try first.
     */
    private void loginLine(String command) throws IOException {
        String verb = command.contains(" ")
                ? command.substring(0, command.indexOf(' ')).toUpperCase(Locale.ROOT)
                : command.toUpperCase(Locale.ROOT);
        switch (verb) {
            case "USER" -> answer("+OK\r\n");
            case "PASS" -> {
                answer("+OK [seclume] logged in already\r\n");
                pop3Login = false;
            }
            case "QUIT" -> {
                open().writeLine("QUIT");
                pop3Login = false;
            }
            default -> answer("-ERR [seclume] the login is seclume's; only USER and PASS "
                    + "are taken before it\r\n");
        }
    }

    private void answer(String text) {
        synchronized (answers) {
            byte[] bytes = text.getBytes(StandardCharsets.UTF_8); // seclume-allow: a greeting or +OK made here - protocol text
            if (local.capacity() - local.remaining() < bytes.length) {
                ByteBuffer larger = ByteBuffer.allocate(local.remaining() + bytes.length); // seclume-allow: the same protocol text, grown for a long user name
                local = larger.put(local).flip();
            }
            local.compact();
            local.put(bytes);
            local.flip();
        }
    }

    private MailWire open() throws IOException {
        MailWire current = wire;
        if (current == null || closed) {
            throw new SocketException(closed ? "closed" : "not connected");
        }
        return current;
    }

    // ---- what Jakarta Mail asks of a socket ------------------------------------

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
        MailWire current = wire;
        if (current != null) {
            try {
                current.timeout(millis);
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
    public boolean isConnected() {
        return wire != null;
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public boolean isBound() {
        return wire != null;
    }

    @Override
    public int getPort() {
        return settings.port;
    }

    @Override
    public InetAddress getInetAddress() {
        try {
            return InetAddress.getByName(settings.host);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    @Override
    public void shutdownInput() {
        close();
    }

    @Override
    public void shutdownOutput() {
        close();
    }

    @Override
    public void close() {
        closed = true;
        MailWire current = wire;
        if (current != null) {
            current.close();
        }
    }

    @Override
    public String toString() {
        return "MailSocket[" + settings + (closed ? ", closed" : "") + "]";
    }
}
