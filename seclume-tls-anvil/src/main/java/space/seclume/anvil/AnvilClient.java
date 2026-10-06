package space.seclume.anvil;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

import space.seclume.internal.SocketTransport;
import space.seclume.tls.ClientHandshake;
import space.seclume.tls.ClientHello;
import space.seclume.tls.TlsConnection;

/**
 * seclume's TLS client, on call for TLS-Anvil.
 *
 * <p>TLS-Anvil tests a client by playing its server, hundreds of times over,
 * each time with a different deviation from RFC 8446, and judges how the
 * client reacts. Before every handshake it runs a trigger script; ours opens
 * a TCP connection to this process, and each one that arrives here starts
 * one TLS connection to TLS-Anvil with seclume's own stack.
 *
 * <p>What a connection does is what the drivers do: a handshake, a little
 * application data, whatever the server answers, and a close_notify. It runs
 * <b>without</b> checking the certificate chain against a trust store,
 * because TLS-Anvil makes its certificates up per test; the CertificateVerify
 * is still checked, as it always is. So the results say how the protocol is
 * handled, not how trust is decided - that part is the JDK's PKIX and has
 * tests of its own.
 *
 * <p>Arguments: {@code triggerPort anvilHost anvilPort [tls12]}. With
 * {@code tls12} the client offers the TLS 1.2 profile alone - what it offers
 * SQL Server on TDS 7.4 - so that TLS-Anvil's TLS 1.2 tests apply; without it,
 * what the drivers offer every other server.
 */
public final class AnvilClient {

    private static final AtomicLong HANDSHAKES = new AtomicLong();
    private static final AtomicLong CONNECTED = new AtomicLong();

    private AnvilClient() {
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 3) {
            usage();
            return;
        }
        int triggerPort;
        int anvilPort;
        try {
            triggerPort = Integer.parseInt(args[0]);
            anvilPort = Integer.parseInt(args[2]);
        } catch (NumberFormatException notAPort) {
            usage();
            return;
        }
        String anvilHost = args[1];
        ClientHello.Offer offer = args.length > 3 && "tls12".equals(args[3])
                ? ClientHello.Offer.TLS12 : ClientHello.Offer.TLS13_AND_12;
        System.out.println("offering " + offer);

        ExecutorService connections = Executors.newVirtualThreadPerTaskExecutor();
        // Plain TCP on loopback on purpose: the trigger carries no data at all.
        try (ServerSocket trigger = new ServerSocket(triggerPort, 50, InetAddress.getLoopbackAddress())) { // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
            System.out.println("waiting for TLS-Anvil's trigger on " + trigger.getLocalPort());
            while (true) {
                Socket asked = trigger.accept();
                // The trigger's connection itself carries nothing: that it
                // arrived is the request.
                asked.close();
                connections.submit(() -> connectOnce(anvilHost, anvilPort, offer));
            }
        }
    }

    private static void pause(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void usage() {
        System.err.println("usage: AnvilClient triggerPort anvilHost anvilPort [tls12]");
        System.exit(2);
    }

    private static void connectOnce(String host, int port, ClientHello.Offer offer) {
        long number = HANDSHAKES.incrementAndGet();
        String outcome;
        try (SocketTransport socket = SocketTransport.connect(host, port, 5_000)) {
            // A test that makes the server go quiet must not hang the client:
            // no read or write waits longer than this.
            socket.networkTimeout(10_000);
            try (TlsConnection tls = ClientHandshake.connect(socket, "localhost", null, null,
                    null, offer)) {
                CONNECTED.incrementAndGet();
                // A moment between our Finished and our first record. When
                // both reach TLS-Attacker in one TCP read, it takes the record
                // as part of the handshake and what it sends next never
                // arrives here - RecordProtocol.invalidCiphertext then fails
                // on a client that was never sent the altered record. A
                // property of the test server, not of TLS: a real server reads
                // records, not reads.
                pause(100);
                ByteBuffer ping = ByteBuffer.allocateDirect(5).put(new byte[] {'p', 'i', 'n', 'g', '\n'});
                tls.write(ping.flip());
                ByteBuffer answer = ByteBuffer.allocateDirect(4096);
                int read;
                long total = 0;
                while ((read = tls.read(answer.clear())) >= 0) {
                    total += read;
                }
                outcome = "connected, " + total + " bytes, closed by the server";
            }
        } catch (IOException | RuntimeException e) {
            outcome = "refused: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        System.out.println("#" + number + " " + outcome + " (" + CONNECTED.get() + " of "
                + HANDSHAKES.get() + " connected)");
    }
}
