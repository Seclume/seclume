package space.seclume.mongodb;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

import javax.net.ssl.SSLSocketFactory;

/**
 * An {@link SSLSocketFactory} producing {@link SeclumeMongoSocket} instances
 * that authenticate via seclume's TLS and SCRAM-SHA-256 before handing the
 * socket to the caller.
 */
final class SeclumeMongoSocketFactory extends SSLSocketFactory {

    private static final String[] SUITES = {"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"};

    private final MongoUrl url;

    SeclumeMongoSocketFactory(MongoUrl url) {
        this.url = url;
    }

    @Override
    public Socket createSocket() {
        return new SeclumeMongoSocket(url);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        Socket socket = createSocket();
        socket.connect(new InetSocketAddress(host, port));
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        Socket socket = createSocket();
        socket.connect(new InetSocketAddress(host, port));
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException {
        Socket socket = createSocket();
        socket.bind(new InetSocketAddress(localHost, localPort));
        socket.connect(new InetSocketAddress(host, port));
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
                               int localPort) throws IOException {
        Socket socket = createSocket();
        socket.bind(new InetSocketAddress(localAddress, localPort));
        socket.connect(new InetSocketAddress(address, port));
        return socket;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose)
            throws IOException {
        Socket socket = createSocket();
        socket.connect(new InetSocketAddress(host, port));
        return socket;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return SUITES.clone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return SUITES.clone();
    }
}
