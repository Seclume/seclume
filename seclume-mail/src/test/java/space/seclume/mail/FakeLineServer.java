package space.seclume.mail;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * What the fake IMAP and POP3 servers share: a listener on loopback -
 * plain for STARTTLS, or TLS 1.3 (the JDK's) from the first byte - a thread
 * per connection, and a connection that reads lines and can be upgraded.
 */
abstract class FakeLineServer implements AutoCloseable {

    private final SSLContext tls;
    final boolean implicitTls;
    private final ServerSocket listener;

    FakeLineServer(SSLContext tls, boolean implicitTls, String name) throws IOException {
        this.tls = tls;
        this.implicitTls = implicitTls;
        if (implicitTls) {
            SSLServerSocket secure = (SSLServerSocket) tls.getServerSocketFactory()
                    .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
            secure.setEnabledProtocols(new String[] {"TLSv1.3"});
            this.listener = secure;
        } else {
            this.listener = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        }
        Thread acceptor = new Thread(this::accept, name);
        acceptor.setDaemon(true);
        acceptor.start();
    }

    int port() {
        return listener.getLocalPort();
    }

    /** One connection, from the greeting on; returning closes it. */
    abstract void serve(Connection connection) throws IOException;

    private void accept() {
        while (!listener.isClosed()) {
            try {
                Socket socket = listener.accept();
                Thread session = new Thread(() -> {
                    try (Connection connection = new Connection(socket)) {
                        serve(connection);
                    } catch (IOException | RuntimeException ignored) {
                        // the client went away; the test asserts on what was recorded
                    }
                }, "fake-mail-session");
                session.setDaemon(true);
                session.start();
            } catch (IOException closed) {
                return;
            }
        }
    }

    @Override
    public void close() throws IOException {
        listener.close();
    }

    final class Connection implements AutoCloseable {

        private Socket socket;
        private InputStream in;
        private OutputStream out;
        boolean encrypted = implicitTls;

        Connection(Socket socket) throws IOException {
            this.socket = socket;
            this.in = new BufferedInputStream(socket.getInputStream());
            this.out = socket.getOutputStream();
        }

        void send(String text) throws IOException {
            out.write(text.getBytes(StandardCharsets.UTF_8));
            out.flush();
        }

        void line(String line) throws IOException {
            send(line + "\r\n");
        }

        /** A line without its CRLF, or null at the end of the stream. */
        String readLine() throws IOException {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            int b;
            while ((b = in.read()) >= 0) {
                if (b == '\n') {
                    byte[] bytes = line.toByteArray();
                    int length = bytes.length > 0 && bytes[bytes.length - 1] == '\r'
                            ? bytes.length - 1 : bytes.length;
                    return new String(bytes, 0, length, StandardCharsets.UTF_8);
                }
                line.write(b);
            }
            return null;
        }

        byte[] readBytes(int length) throws IOException {
            byte[] bytes = in.readNBytes(length);
            if (bytes.length != length) {
                throw new IOException("the stream ended in a literal");
            }
            return bytes;
        }

        /** The TLS handshake, after the reply that announced it has gone out. */
        void startTls() throws IOException {
            SSLSocket secure = (SSLSocket) tls.getSocketFactory().createSocket(socket, null, true);
            secure.setUseClientMode(false);
            secure.setEnabledProtocols(new String[] {"TLSv1.3"});
            // The server side, which checks no peer certificate at all - but set
            // like a client's, so no reading of this file takes it for a socket
            // that trusts whatever it is shown.
            SSLParameters parameters = secure.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            secure.setSSLParameters(parameters);
            secure.startHandshake();
            socket = secure;
            in = new BufferedInputStream(secure.getInputStream());
            out = secure.getOutputStream();
            encrypted = true;
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            all.writeBytes(part);
        }
        return all.toByteArray();
    }
}
