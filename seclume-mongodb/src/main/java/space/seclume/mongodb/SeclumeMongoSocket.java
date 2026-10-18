package space.seclume.mongodb;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.SQLException;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.mongodb.internal.MongoHandshake;

/**
 * An {@link SSLSocket} that opens a TLS 1.3 connection on seclume's own TLS
 * stack and completes SCRAM-SHA-256 authentication in native memory during
 * {@link #connect}, before handing the authenticated socket to the MongoDB
 * driver.
 */
final class SeclumeMongoSocket extends SSLSocket {

    private static final String[] SUITES = {"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"};
    private static final String[] PROTOCOLS = {"TLSv1.3"};

    private final MongoUrl url;
    private SSLParameters sslParameters = new SSLParameters();
    private SocketTransport transport;
    private TlsLayer tls;
    private InetSocketAddress remoteAddress;
    private volatile boolean connected;
    private volatile boolean closed;
    private int timeoutMillis;
    /** The bound on TLS and SCRAM where neither the driver nor the URL sets a connect timeout. */
    private static final int DEFAULT_LOGIN_TIMEOUT_MILLIS = 10_000;

    private final InputStream in = new InputStream() {
        private final byte[] one = new byte[1];

        @Override
        public int read() throws IOException {
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xff);
        }

        @Override
        public int read(byte[] target, int offset, int length) throws IOException {
            if (length == 0) {
                return 0;
            }
            check();
            try {
                int n = tls.read(ByteBuffer.wrap(target, offset, length));
                return n;
            } catch (IOException e) {
                if (timeoutMillis > 0 && !transport.isOpen() && !closed) {
                    throw new SocketTimeoutException("read timed out after " + timeoutMillis + " ms");
                }
                throw e;
            }
        }
    };

    private final OutputStream out = new OutputStream() {
        @Override
        public void write(int value) throws IOException {
            write(new byte[] {(byte) value}, 0, 1);
        }

        @Override
        public void write(byte[] source, int offset, int length) throws IOException {
            if (length == 0) {
                return;
            }
            check();
            tls.write(ByteBuffer.wrap(source, offset, length));
        }
    };

    SeclumeMongoSocket(MongoUrl url) {
        this.url = url;
    }

    private void check() throws SocketException {
        if (closed) {
            throw new SocketException("Socket is closed");
        }
        if (!connected || tls == null) {
            throw new SocketException("Socket is not connected");
        }
    }

    @Override
    public void connect(SocketAddress endpoint, int connectTimeout) throws IOException {
        if (connected) {
            throw new SocketException("already connected");
        }
        if (!(endpoint instanceof InetSocketAddress inet)) {
            throw new IllegalArgumentException("unsupported endpoint: " + endpoint);
        }
        this.remoteAddress = inet;
        String host = inet.getHostString();
        int port = inet.getPort();
        int effectiveTimeout = connectTimeout > 0 ? connectTimeout : url.connectTimeout();

        try {
            transport = SocketTransport.connect(host, port, effectiveTimeout);
            // The login is part of connecting, so the connect timeout bounds
            // it: without a read timeout of its own - the driver sets one only
            // when asked to - a server that answered TCP and then said nothing
            // held the TLS handshake or SCRAM for ever.
            transport.networkTimeout(effectiveTimeout > 0 ? effectiveTimeout : DEFAULT_LOGIN_TIMEOUT_MILLIS);

            tls = TrustChoice.using(url.trust(), () -> {
                try {
                    return TlsLayers.start(TlsStack.SECLUME, transport, host, port, true);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });

            MongoHandshake.authenticate(tls, url, host, port);
            transport.networkTimeout(timeoutMillis);        // the driver's, 0 for none
            connected = true;
        } catch (SQLException e) {
            closeQuietly();
            throw new IOException("TLS handshake failed for " + host + ":" + port + ": "
                    + e.getMessage(), e);
        } catch (IOException | RuntimeException e) {
            closeQuietly();
            throw e;
        }
    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        connect(endpoint, url.connectTimeout());
    }

    private void closeQuietly() {
        closed = true;
        try {
            if (tls != null) {
                tls.close();
            }
        } catch (Exception ignored) {
        }
        try {
            if (transport != null) {
                transport.close();
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public synchronized void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (tls != null) {
                tls.close();
            }
        } finally {
            if (transport != null) {
                transport.close();
            }
        }
    }

    @Override
    public boolean isConnected() {
        return connected;
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public InputStream getInputStream() {
        return in;
    }

    @Override
    public OutputStream getOutputStream() {
        return out;
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        this.timeoutMillis = timeout;
        if (transport != null) {
            try {
                transport.networkTimeout(timeout);
            } catch (IOException ignored) {
            }
        }
    }

    @Override
    public int getSoTimeout() {
        return timeoutMillis;
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        // SocketTransport sets TCP_NODELAY on connect
    }

    @Override
    public boolean getTcpNoDelay() {
        return true;
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        // SocketTransport sets keepalive on connect
    }

    @Override
    public boolean getKeepAlive() {
        return true;
    }

    @Override
    public InetAddress getInetAddress() {
        return remoteAddress != null ? remoteAddress.getAddress() : null;
    }

    @Override
    public int getPort() {
        return remoteAddress != null ? remoteAddress.getPort() : 0;
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return remoteAddress;
    }

    @Override
    public InetAddress getLocalAddress() {
        return null;
    }

    @Override
    public int getLocalPort() {
        return 0;
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return null;
    }

    @Override
    public SocketChannel getChannel() {
        return null;
    }

    // ---- SSLSocket contract -------------------------------------------------

    @Override
    public String[] getSupportedCipherSuites() {
        return SUITES.clone();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return SUITES.clone();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
    }

    @Override
    public String[] getSupportedProtocols() {
        return PROTOCOLS.clone();
    }

    @Override
    public String[] getEnabledProtocols() {
        return PROTOCOLS.clone();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
    }

    @Override
    public SSLSession getSession() {
        return new SSLSession() {
            @Override
            public byte[] getId() {
                return new byte[0];
            }

            @Override
            public SSLSessionContext getSessionContext() {
                return null;
            }

            @Override
            public long getCreationTime() {
                return 0;
            }

            @Override
            public long getLastAccessedTime() {
                return 0;
            }

            @Override
            public void invalidate() {
            }

            @Override
            public boolean isValid() {
                return connected && !closed;
            }

            @Override
            public void putValue(String name, Object value) {
            }

            @Override
            public Object getValue(String name) {
                return null;
            }

            @Override
            public void removeValue(String name) {
            }

            @Override
            public String[] getValueNames() {
                return new String[0];
            }

            @Override
            public Certificate[] getPeerCertificates() {
                try {
                    X509Certificate cert = tls != null ? tls.peerCertificate() : null;
                    return cert != null ? new Certificate[] {cert} : new Certificate[0];
                } catch (IOException e) {
                    return new Certificate[0];
                }
            }

            @Override
            public Certificate[] getLocalCertificates() {
                return null;
            }

            @Override
            public Principal getPeerPrincipal() {
                return null;
            }

            @Override
            public Principal getLocalPrincipal() {
                return null;
            }

            @Override
            public String getCipherSuite() {
                return "TLS_AES_256_GCM_SHA384";
            }

            @Override
            public String getProtocol() {
                return "TLSv1.3";
            }

            @Override
            public String getPeerHost() {
                return remoteAddress != null ? remoteAddress.getHostString() : "";
            }

            @Override
            public int getPeerPort() {
                return remoteAddress != null ? remoteAddress.getPort() : 0;
            }

            @Override
            public int getPacketBufferSize() {
                return 16 * 1024;
            }

            @Override
            public int getApplicationBufferSize() {
                return 16 * 1024;
            }
        };
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public void startHandshake() throws IOException {
    }

    @Override
    public void setUseClientMode(boolean mode) {
    }

    @Override
    public boolean getUseClientMode() {
        return true;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {
    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
    }

    @Override
    public boolean getEnableSessionCreation() {
        return true;
    }

    @Override
    public SSLParameters getSSLParameters() {
        return sslParameters;
    }

    @Override
    public void setSSLParameters(SSLParameters params) {
        if (params != null) {
            this.sslParameters = params;
        }
    }
}
