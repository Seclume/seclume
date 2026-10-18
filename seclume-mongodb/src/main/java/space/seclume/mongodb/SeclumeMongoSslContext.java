package space.seclume.mongodb;

import java.security.KeyManagementException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * An {@link SSLContext} providing {@link SeclumeMongoSocketFactory} for the
 * official MongoDB Sync driver.
 */
final class SeclumeMongoSslContext extends SSLContext {

    private static final Provider PROVIDER = new Provider("SeclumeMongo", "1.0", "seclume MongoDB TLS") {
        private static final long serialVersionUID = 1L;
    };

    SeclumeMongoSslContext(MongoUrl url) {
        super(new Spi(url), PROVIDER, "TLS");
    }

    private static final class Spi extends SSLContextSpi {

        private final SSLSocketFactory socketFactory;

        Spi(MongoUrl url) {
            this.socketFactory = new SeclumeMongoSocketFactory(url);
        }

        @Override
        protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr)
                throws KeyManagementException {
        }

        @Override
        protected SSLSocketFactory engineGetSocketFactory() {
            return socketFactory;
        }

        @Override
        protected SSLServerSocketFactory engineGetServerSocketFactory() {
            throw new UnsupportedOperationException("server sockets are not supported");
        }

        @Override
        protected SSLEngine engineCreateSSLEngine() {
            throw new UnsupportedOperationException(
                    "SSLEngine is not supported; use the sync driver (mongodb-driver-sync)");
        }

        @Override
        protected SSLEngine engineCreateSSLEngine(String host, int port) {
            throw new UnsupportedOperationException(
                    "SSLEngine is not supported; use the sync driver (mongodb-driver-sync)");
        }

        @Override
        protected SSLSessionContext engineGetServerSessionContext() {
            return null;
        }

        @Override
        protected SSLSessionContext engineGetClientSessionContext() {
            return null;
        }
    }
}
