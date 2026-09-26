import space.seclume.internal.SocketTransport;
import space.seclume.tls.ClientHandshake;
import space.seclume.tls.TlsConnection;

/**
 * Connects seclume's TLS client to an OpenSSL s_server on 127.0.0.1:4433 and
 * prints what was negotiated - run by proof/pq.sh against a server that
 * offers only X25519MLKEM768, then one that offers only P-256.
 */
public class PqProof {
    public static void main(String[] args) throws Exception {
        System.out.println("PROOF hybrid available: "
                + space.seclume.crypto.HybridMlKem.available());
        try (TlsConnection tls = ClientHandshake.connectWithoutAuthenticating(
                SocketTransport.connect("127.0.0.1", 4433, 3000), "localhost")) {
            System.out.println("PROOF negotiated: " + tls.description());
        } catch (Exception e) {
            System.out.println("PROOF refused: " + e);
        }
    }
}
