package space.seclume.ldap;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

import javax.net.SocketFactory;

/**
 * The socket factory JNDI is told to use
 * ({@code java.naming.ldap.factory.socket}); it finds it by name and calls
 * {@link #getDefault()}. Which server's TLS settings apply is looked up by the
 * host and port JNDI connects to - registered by {@link SeclumeLdap#of}.
 */
public final class SeclumeLdapSocketFactory extends SocketFactory {

    private static final SeclumeLdapSocketFactory INSTANCE = new SeclumeLdapSocketFactory();

    /** What JNDI calls. */
    public static SocketFactory getDefault() {
        return INSTANCE;
    }

    @Override
    public Socket createSocket() {
        return new LdapSocket();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        LdapSocket socket = new LdapSocket();
        socket.connect(InetSocketAddress.createUnresolved(host, port));
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
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
                               int localPort) throws IOException {
        return createSocket(address.getHostName(), port);
    }
}
