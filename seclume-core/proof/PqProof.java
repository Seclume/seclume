import space.seclume.internal.SocketTransport;
import space.seclume.tls.ClientHandshake;
import space.seclume.tls.TlsConnection;

/**
 * Connects seclume's TLS client to an OpenSSL s_server on 127.0.0.1:4433 and
 * prints what was negotiated - run by proof/pq.sh against a server that
 * offers only X25519MLKEM768, then one that offers only P-256.
 *
 * <p>With {@code host port} as arguments it connects there instead - on
 * Windows, where there is no OpenSSL 3.5 to start, against any public server
 * that speaks the hybrid, e.g. {@code cloudflare.com 443}.
 */
public class PqProof {
    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 4433;
        String name = args.length > 0 ? args[0] : "localhost";
        System.out.println("PROOF hybrid available: "
                + space.seclume.crypto.HybridMlKem.available());
        try (TlsConnection tls = ClientHandshake.connectWithoutAuthenticating(
                SocketTransport.connect(host, port, 3000), name)) {
            System.out.println("PROOF negotiated: " + tls.description());
        } catch (Exception e) {
            System.out.println("PROOF refused: " + e);
        }
    }
}
