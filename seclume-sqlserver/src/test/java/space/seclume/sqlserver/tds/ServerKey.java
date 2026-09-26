package space.seclume.sqlserver.tds;

import java.security.cert.X509Certificate;

/** The certificate a SQL Server presents, taken with no check - for tests that pin it. */
public final class ServerKey {

    private ServerKey() {
    }

    public static X509Certificate certificate(String host, int port) throws Exception {
        try (TdsChannel channel = TdsChannel.connect(host, port, 10_000)) {
            new PreLogin().exchange(channel, Tds.ENCRYPT_ON);
            TdsTls tls = TdsTls.create(channel.raw(), host, port, true);
            tls.handshake();
            return tls.peerCertificate();
        }
    }

    /** As a URL option value: {@code sha256/...}, its '+' escaped. */
    public static String pin(String host, int port) throws Exception {
        return space.seclume.internal.TrustChoice.pinOf(certificate(host, port))
                .replace("+", "%2B");
    }
}
