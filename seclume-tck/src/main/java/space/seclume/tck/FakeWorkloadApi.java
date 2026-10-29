package space.seclume.tck;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * A stand-in for a SPIRE agent's Workload API, for tests: a Unix socket that
 * speaks as much HTTP/2 and gRPC as {@code FetchX509SVID} takes - the
 * preface, SETTINGS, the request's HEADERS and empty message - and answers
 * with an {@code X509SVIDResponse} the test made ({@link #x509SvidResponse}),
 * in as many DATA frames as asked, padded or not. Or, for the failures: with
 * trailers and no message, as SPIRE answers a workload it has no entry for,
 * or with nothing at all.
 *
 * <p>What it cannot show is SPIRE itself - attestation, rotation by the
 * agent; the answers are the shapes the SPIFFE Workload API specification and
 * its protobuf definitions give.
 */
public final class FakeWorkloadApi implements AutoCloseable {

    /** How the next call is answered. */
    public enum Mode {
        /** The SVID, in one DATA frame. */
        ANSWER,
        /** The SVID, split over several DATA frames, each padded. */
        SPLIT,
        /** Trailers only - an unregistered workload. */
        UNREGISTERED,
        /** No answer at all. */
        SILENT
    }

    private final Path socket;
    private final ServerSocketChannel server;
    private final Supplier<byte[]> answer;
    private final List<String> headerBlocks = new CopyOnWriteArrayList<>();
    private final AtomicInteger calls = new AtomicInteger();
    private volatile Mode mode = Mode.ANSWER;
    private volatile boolean stopped;

    /**
     * @param answer the protobuf {@code X509SVIDResponse} for each call - asked
     *               again every time, so that a test can rotate the SVID
     */
    public FakeWorkloadApi(Path socket, Supplier<byte[]> answer) throws IOException {
        this.socket = socket;
        this.answer = answer;
        Files.deleteIfExists(socket);
        this.server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(socket));
        Thread thread = new Thread(this::serve, "fake-workload-api");
        thread.setDaemon(true);
        thread.start();
    }

    public Path socket() {
        return socket;
    }

    public void mode(Mode mode) {
        this.mode = mode;
    }

    /** How many calls arrived. */
    public int calls() {
        return calls.get();
    }

    /** Each call's header block as received, decoded as the plain literals a client sends. */
    public List<String> headerBlocks() {
        return headerBlocks;
    }

    /**
     * An {@code X509SVIDResponse} with one SVID: its SPIFFE ID, its certificate
     * chain and key (both DER) and the bundle (DER certificates).
     */
    public static byte[] x509SvidResponse(String spiffeId, byte[] chain, byte[] key,
            byte[] bundle) {
        ByteArrayOutputStream svid = new ByteArrayOutputStream();
        // seclume-allow: a fake agent's own made-up data, no application secret
        field(svid, 1, spiffeId.getBytes(StandardCharsets.UTF_8));
        field(svid, 2, chain);
        field(svid, 3, key);
        field(svid, 4, bundle);
        // seclume-allow: a fake agent's own made-up data, no application secret
        field(svid, 5, "internal".getBytes(StandardCharsets.UTF_8));   // the hint
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        field(response, 1, svid.toByteArray());
        return response.toByteArray();
    }

    private static void field(ByteArrayOutputStream out, int number, byte[] value) {
        varint(out, (number << 3) | 2);
        varint(out, value.length);
        out.write(value, 0, value.length);
    }

    private static void varint(ByteArrayOutputStream out, long value) {
        long v = value;
        while ((v & ~0x7fL) != 0) {
            out.write((int) ((v & 0x7f) | 0x80));
            v >>>= 7;
        }
        out.write((int) v);
    }

    private void serve() {
        while (!stopped) {
            try (SocketChannel client = server.accept()) {
                calls.incrementAndGet();
                handle(client);
            } catch (IOException | RuntimeException e) {
                if (stopped) {
                    return;
                }
            }
        }
    }

    private void handle(SocketChannel client) throws IOException {
        read(client, 24);                                     // the preface
        boolean requested = false;
        while (!requested) {
            byte[] head = read(client, 9);
            int length = ((head[0] & 0xff) << 16) | ((head[1] & 0xff) << 8) | (head[2] & 0xff);
            int type = head[3] & 0xff;
            int flags = head[4] & 0xff;
            byte[] payload = read(client, length);
            if (type == 0x4 && (flags & 0x1) == 0) {
                write(client, frame(0x4, 0, 0, new byte[0]));       // our SETTINGS
                write(client, frame(0x4, 0x1, 0, new byte[0]));     // and the ACK of theirs
            } else if (type == 0x1) {
                headerBlocks.add(literals(payload));
            } else if (type == 0x0 && (flags & 0x1) != 0) {
                requested = true;                                    // the request is whole
            }
        }
        Mode now = mode;
        if (now == Mode.SILENT) {
            try {
                Thread.sleep(60_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return;
        }
        // :status 200, from the static table.
        if (now == Mode.UNREGISTERED) {
            write(client, frame(0x1, 0x4 | 0x1, 1, new byte[] {(byte) 0x88}));
            return;
        }
        write(client, frame(0x1, 0x4, 1, new byte[] {(byte) 0x88}));
        byte[] message = answer.get();
        ByteArrayOutputStream grpc = new ByteArrayOutputStream();
        grpc.write(0);
        grpc.write(message.length >>> 24);
        grpc.write(message.length >>> 16);
        grpc.write(message.length >>> 8);
        grpc.write(message.length);
        grpc.write(message, 0, message.length);
        byte[] data = grpc.toByteArray();
        if (now == Mode.SPLIT) {
            int parts = 3;
            int step = (data.length + parts - 1) / parts;
            for (int from = 0; from < data.length; from += step) {
                int to = Math.min(data.length, from + step);
                ByteArrayOutputStream padded = new ByteArrayOutputStream();
                padded.write(2);                                        // pad length
                padded.write(data, from, to - from);
                padded.write(0);
                padded.write(0);
                write(client, frame(0x0, 0x8, 1, padded.toByteArray()));
                // a PING on the way, which a client has to answer
                write(client, frame(0x6, 0, 0, new byte[8]));
            }
        } else {
            write(client, frame(0x0, 0, 1, data));
        }
        // A stream: no trailers - the client takes its message and goes.
        // seclume-allow: a fake agent's own made-up data, no application secret
        ByteBuffer rest = ByteBuffer.allocate(4096);
        while (client.read(rest) >= 0) {
            rest.clear();
        }
    }

    /** A header block of plain literals, as name: value lines. */
    private static String literals(byte[] block) {
        StringBuilder out = new StringBuilder();
        int at = 0;
        while (at < block.length) {
            int kind = block[at++] & 0xff;
            if (kind != 0x00 && kind != 0x10) {
                out.append("(not a plain literal)\n");
                break;
            }
            int nameLength = block[at++] & 0x7f;
            // seclume-allow: a fake agent's own made-up data, no application secret
            String name = new String(block, at, nameLength, StandardCharsets.US_ASCII);
            at += nameLength;
            int valueLength = block[at++] & 0x7f;
            // seclume-allow: a fake agent's own made-up data, no application secret
            String value = new String(block, at, valueLength, StandardCharsets.US_ASCII);
            at += valueLength;
            out.append(name).append(": ").append(value).append('\n');
        }
        return out.toString();
    }

    private static byte[] frame(int type, int flags, int stream, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(payload.length >>> 16);
        out.write(payload.length >>> 8);
        out.write(payload.length);
        out.write(type);
        out.write(flags);
        out.write(stream >>> 24);
        out.write(stream >>> 16);
        out.write(stream >>> 8);
        out.write(stream);
        out.write(payload, 0, payload.length);
        return out.toByteArray();
    }

    private static byte[] read(SocketChannel channel, int length) throws IOException {
        // seclume-allow: a fake agent's own made-up data, no application secret
        ByteBuffer buffer = ByteBuffer.allocate(length);
        while (buffer.hasRemaining()) {
            if (channel.read(buffer) < 0) {
                throw new IOException("the client closed its connection before its request was whole");
            }
        }
        return buffer.array();
    }

    private static void write(SocketChannel channel, byte[] bytes) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
    }

    @Override
    public void close() throws IOException {
        stopped = true;
        server.close();
        Files.deleteIfExists(socket);
    }
}
