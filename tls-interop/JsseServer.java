import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * The JDK's own TLS server, for the interop matrix: answers every connection
 * with a short HTTP response.
 *
 * <pre>  java JsseServer.java port keystore.p12 TLSv1.3|TLSv1.2</pre>
 */
public class JsseServer {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        char[] password = "interop".toCharArray();   // a throwaway test keystore
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Path.of(args[1]))) {
            store.load(in, password);
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance("PKIX");
        keys.init(store, password);
        // A TLSv1.3 context, which speaks 1.2 as well: the protocol each case
        // offers is set below, one per server, and nothing older is possible.
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), null, null);
        try (SSLServerSocket server = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(port)) {
            server.setEnabledProtocols(new String[] {args[2]});
            while (true) {
                try (SSLSocket socket = (SSLSocket) server.accept()) {
                    socket.startHandshake();
                    socket.getInputStream().read(new byte[1024]);
                    OutputStream out = socket.getOutputStream();
                    out.write(("HTTP/1.0 200 OK\r\n\r\njsse " + socket.getSession().getProtocol()
                            + " " + socket.getSession().getCipherSuite() + "\n")
                            .getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                } catch (Exception ignored) {
                    // a client that was refused, or left: the next one
                }
            }
        }
    }
}
