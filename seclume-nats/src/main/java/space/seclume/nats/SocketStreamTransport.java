package space.seclume.nats;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;

import space.seclume.internal.Transport;

/**
 * The socket the NATS client opened, as seclume's TLS - or, without TLS, the
 * CONNECT line - writes to it: through its streams, which take arrays only.
 */
final class SocketStreamTransport implements Transport {

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;

    SocketStreamTransport(Socket socket, InputStream in, OutputStream out) {
        this.socket = socket;
        this.in = in;
        this.out = out;
    }

    @Override
    public int read(ByteBuffer into) throws IOException {
        int rem = into.remaining();
        if (rem == 0) {
            return 0;
        }
        if (into.hasArray()) {
            int n = in.read(into.array(), into.arrayOffset() + into.position(), rem);
            if (n > 0) {
                into.position(into.position() + n);
            }
            return n;
        }
        byte[] buf = new byte[Math.min(rem, 16 * 1024)];
        int n = in.read(buf, 0, buf.length);
        if (n > 0) {
            into.put(buf, 0, n);
        }
        return n;
    }

    @Override
    public int write(ByteBuffer from) throws IOException {
        int rem = from.remaining();
        if (rem == 0) {
            return 0;
        }
        if (from.hasArray()) {
            out.write(from.array(), from.arrayOffset() + from.position(), rem);
            out.flush();
            from.position(from.limit());
            return rem;
        }
        // Native bytes - the CONNECT line with the password, when there is no
        // TLS - and a stream that takes an array: one of its own, wiped as
        // soon as the stream has had it, however that ended.
        byte[] buf = new byte[rem]; // seclume-allow: the stream takes an array; wiped below
        try {
            from.get(buf);
            out.write(buf, 0, rem);
            out.flush();
        } finally {
            java.util.Arrays.fill(buf, (byte) 0);
        }
        return rem;
    }

    @Override
    public boolean isOpen() {
        return !socket.isClosed();
    }

    @Override
    public void close() {
        try {
            socket.close();
        } catch (IOException ignored) {
            // On close an error has no consequences.
        }
    }
}
