package space.seclume.tls;

import java.io.IOException;
import java.nio.ByteBuffer;

import com.code_intelligence.jazzer.junit.FuzzTest;

import space.seclume.internal.Transport;

/**
 * The client handshake of seclume's own TLS stack, fed whatever a server - or
 * anybody in the middle - might send before anything is authenticated: the
 * record framing, the ServerHello or HelloRetryRequest, alerts. Everything
 * after the ServerHello is encrypted and authenticated, so this is the whole
 * of what can be sent without a key.
 *
 * <p>Passing means failing like a library: an {@link IOException} (a
 * {@link TlsAlertException} is one), nothing else - no index out of bounds, no
 * {@code OutOfMemoryError} from a length taken off the wire, and no hang,
 * because the input simply ends.
 */
class ServerHelloFuzzTest {

    @FuzzTest(maxDuration = "60s")
    void aHostileServerHelloFailsWithAnIoException(byte[] server) {
        try {
            TlsConnection connection = ClientHandshake.connectWithoutAuthenticating(
                    new Replay(server), "db.example");
            connection.close();
        } catch (IOException expected) {
            // what a hostile answer has to end in
        }
    }

    /** A server that says {@code bytes} and then hangs up; what the client sends is dropped. */
    private static final class Replay implements Transport {

        private final ByteBuffer bytes;
        private boolean open = true;

        Replay(byte[] bytes) {
            this.bytes = ByteBuffer.wrap(bytes);
        }

        @Override
        public int read(ByteBuffer into) {
            if (!bytes.hasRemaining()) {
                return -1;
            }
            int count = Math.min(into.remaining(), bytes.remaining());
            ByteBuffer slice = bytes.slice(bytes.position(), count);
            into.put(slice);
            bytes.position(bytes.position() + count);
            return count;
        }

        @Override
        public int write(ByteBuffer from) {
            int count = from.remaining();
            from.position(from.limit());
            return count;
        }

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public void close() {
            open = false;
        }
    }
}
