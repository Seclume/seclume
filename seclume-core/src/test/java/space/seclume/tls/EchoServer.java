package space.seclume.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * A JSSE server on the loopback interface that sends back whatever it is
 * given - the judge for everything this client produces.
 *
 * <p>It is the only peer in these tests that did not come from this
 * repository, which is what makes it worth having: it derives its own keys,
 * decrypts our records with them, and verifies our Finished. A transcript
 * off by a byte or a sequence number that restarted ends here as a failed
 * handshake or a refused record, rather than as a test agreeing with itself.
 */
final class EchoServer implements AutoCloseable {

    private final SSLServerSocket socket;
    private final Thread thread;
    private final AtomicReference<Exception> failure = new AtomicReference<>();

    private EchoServer(SSLServerSocket socket) {
        this.socket = socket;
        this.thread = Thread.ofVirtual().start(this::serve);
    }

    static EchoServer start(SSLContext context) throws IOException {
        return start(context, false);
    }

    /**
     * The same, optionally demanding a client certificate.
     *
     * <p>With {@code needClientAuth} the server sends a CertificateRequest and
     * refuses the connection unless what comes back is signed by a key it can
     * check against its trust store - which makes it the judge for the client
     * authentication as well, not only for the record layer.
     */
    static EchoServer start(SSLContext context, boolean needClientAuth) throws IOException {
        return start(context, needClientAuth, null);
    }

    /**
     * The same, willing to select one application protocol.
     *
     * <p>{@code null} means the server has no ALPN configured at all, which
     * is a case worth being able to produce: a client that offers a protocol
     * and is answered with silence has to refuse, and that refusal is only
     * testable against a server that stays silent.
     */
    static EchoServer start(SSLContext context, boolean needClientAuth, String alpn)
            throws IOException {
        SSLServerSocket socket = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress());
        socket.setSoTimeout(60_000);
        socket.setNeedClientAuth(needClientAuth);
        if (alpn != null) {
            javax.net.ssl.SSLParameters parameters = socket.getSSLParameters();
            parameters.setApplicationProtocols(new String[] {alpn});
            socket.setSSLParameters(parameters);
        }
        return new EchoServer(socket);
    }

    int port() {
        return socket.getLocalPort();
    }

    /** Whatever went wrong on the server side, for a test that wants to say why. */
    Exception failure() {
        return failure.get();
    }

    private void serve() {
        try (SSLSocket accepted = (SSLSocket) socket.accept()) {
            accepted.setSoTimeout(60_000);
            InputStream in = accepted.getInputStream();
            OutputStream out = accepted.getOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
                out.flush();
            }
        } catch (Exception e) {
            failure.set(e);               // a refused handshake or record lands here
        }
    }

    @Override
    public void close() throws IOException {
        socket.close();
        try {
            thread.join(java.time.Duration.ofSeconds(30));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
