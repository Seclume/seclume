package space.seclume.aws;

import java.io.IOException;
import java.net.Socket;

import javax.net.ssl.SSLSocket;

import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.protocol.HttpContext;

import space.seclume.internal.TrustChoice;

/** Hands the SDK's Apache 5 client {@link SessionTokenSocket}s instead of JSSE's. */
final class SeclumeTlsStrategy implements TlsSocketStrategy {

    private final TrustChoice.Choice trust;

    SeclumeTlsStrategy(TrustChoice.Choice trust) {
        this.trust = trust;
    }

    @Override
    public SSLSocket upgrade(Socket socket, String target, int port, Object attachment,
                             HttpContext context) throws IOException {
        return SessionTokenSocket.over(socket, target, port, trust);
    }
}
