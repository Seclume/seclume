package space.seclume.tls;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import space.seclume.tls.ScriptedTlsServer.Step;

/**
 * One fuzz case against the <b>encrypted</b> part of the server's flight -
 * the part {@code ServerHelloFuzzTest}'s first sweep cannot reach, because
 * without the handshake key every byte it sends there fails its tag.
 *
 * <p>{@link ScriptedTlsServer} holds the key, so the input reaches the parser
 * behind the encryption. Two shapes, chosen by the first byte:
 *
 * <ul>
 *   <li><b>an order</b>: the following bytes pick messages one by one, each
 *       made correct where it stands - a signature over the transcript at
 *       that point, a Finished over whatever came before. What the input
 *       controls is the sequence, which is where the bypass was;
 *   <li><b>bytes</b>: a complete, legal flight with the rest of the input
 *       laid over its plaintext before it is sealed - lengths, types and
 *       certificate bytes spoilt, but authenticated.
 * </ul>
 *
 * <p>Two things must hold for every input. A failure is an
 * {@link IOException} and nothing else - no index out of bounds, no
 * {@code IllegalStateException}. And <b>a connection that is established
 * has an authenticated server</b>: a certificate and a verified
 * CertificateVerify, which in the first shape means one of exactly two
 * orders.
 */
final class EncryptedFlight {

    private static final String HOSTNAME = "db.example.com";
    private static volatile Material material;

    private EncryptedFlight() {
    }

    /** The certificate and key every case uses, made once per JVM. */
    record Material(byte[] leaf, PrivateKey key, CertificateTrust trust) {
    }

    static Material material() throws Exception {
        Material ready = material;
        if (ready != null) {
            return ready;
        }
        synchronized (EncryptedFlight.class) {
            if (material == null) {
                TestCertificates certificates = TestCertificates.generate();
                TestCertificates.Issued server = certificates.issueEc("server",
                        "san=dns:" + HOSTNAME, "ku:c=digitalSignature", "eku=serverAuth");
                KeyStore store = KeyStore.getInstance("PKCS12");
                try (InputStream in = Files.newInputStream(server.keystore())) {
                    store.load(in, TestCertificates.PASSWORD.toCharArray());
                }
                material = new Material(server.certificate().getEncoded(),
                        (PrivateKey) store.getKey("server", TestCertificates.PASSWORD.toCharArray()),
                        CertificateTrust.of(certificates.trustStore()));
                certificates.close();
            }
            return material;
        }
    }

    /**
     * Runs one input. Returns normally when the case ended the way a library
     * has to end; throws {@link AssertionError} when it did not.
     *
     * @return whether a connection was established - which the invariants
     *         above have then already checked
     */
    static boolean run(byte[] input, Material material) {
        if (input.length == 0) {
            return false;
        }
        boolean withTrust = (input[0] & 2) != 0;
        ScriptedTlsServer server;
        List<Step> script = null;
        if ((input[0] & 1) == 0) {
            script = new ArrayList<>();
            for (int i = 1; i < input.length && script.size() < 8; i++) {
                int pick = (input[i] & 0xff) % (Step.values().length + 1);
                if (pick == Step.values().length) {
                    break;
                }
                script.add(Step.values()[pick]);
            }
            server = new ScriptedTlsServer(script, material.leaf(), material.key(),
                    (input[0] & 4) != 0, null);
        } else {
            byte[] mask = java.util.Arrays.copyOfRange(input, 1, input.length);
            int length = (input[0] & 4) != 0 ? -1 : mask.length;   // -1: keep the length
            server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE, material.leaf(),
                    material.key(), false, flight -> overlay(flight, mask, length));
        }

        TlsConnection connection;
        try {
            connection = withTrust
                    ? ClientHandshake.connect(server, HOSTNAME, material.trust())
                    : ClientHandshake.connectWithoutAuthenticating(server, HOSTNAME);
        } catch (IOException expected) {
            return false;                     // what a hostile flight has to end in
        } catch (RuntimeException | Error wrong) {
            throw new AssertionError("a hostile flight ended in " + wrong
                    + " rather than an IOException", wrong);
        }
        try (connection) {
            if (connection.peerCertificate() == null) {
                throw new AssertionError("connected without a server certificate: "
                        + (script != null ? script : "overlaid flight"));
            }
            if (script != null && !script.equals(ScriptedTlsServer.COMPLETE)
                    && !script.equals(ScriptedTlsServer.COMPLETE_WITH_REQUEST)) {
                throw new AssertionError("connected after a flight out of order: " + script);
            }
        }
        return true;
    }

    /**
     * The flight with {@code mask} exclusive-ored over its start, cut or
     * padded to {@code length} bytes unless that is -1. A zero mask of the
     * right length is the flight itself, which is how the sweep keeps its
     * own control case.
     */
    static byte[] overlay(byte[] flight, byte[] mask, int length) {
        byte[] out = java.util.Arrays.copyOf(flight, length < 0 ? flight.length
                : Math.min(length + flight.length / 2, 1 << 15));
        for (int i = 0; i < mask.length && i < out.length; i++) {
            out[i] ^= mask[i];
        }
        return out;
    }
}
