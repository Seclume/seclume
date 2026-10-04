package space.seclume.sqlserver.tds;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

import space.seclume.internal.Transport;

/**
 * The transport a TDS 7.4 TLS handshake runs over: TLS records inside TDS
 * packets of type {@link Tds#TYPE_PRELOGIN}, both ways.
 *
 * <p>Outgoing records are collected and sent <b>as one TDS message per
 * flight</b> - SQL Server hangs up on a flight split into one packet per
 * record. A flight ends when this side starts waiting for the other, so the
 * collected bytes go out on the first read after them.
 *
 * <p>Only for the handshake. Once it is done the records travel on the socket
 * itself and the TDS packets inside them: the layer is moved onto the raw
 * transport with {@code replaceTransport}, after {@link #finished} has checked
 * that nothing the server sent is still unread here.
 *
 * <p>Handshake messages carry nothing secret; the buffers are direct anyway,
 * as everything on this path is.
 */
final class PreLoginRecords implements Transport {

    /** A TDS packet's length is two bytes; the default packet size is 4096. */
    private static final int PACKET = 4096;

    private final Transport raw;
    private ByteBuffer pending = ByteBuffer.allocateDirect(8192);
    private final ByteBuffer header = ByteBuffer.allocateDirect(Tds.HEADER_SIZE);
    private final ByteBuffer incoming = ByteBuffer.allocateDirect(1 << 16);
    private final ByteBuffer outgoing = ByteBuffer.allocateDirect(PACKET);

    PreLoginRecords(Transport raw) {
        this.raw = raw;
        incoming.limit(0);
    }

    @Override
    public int write(ByteBuffer from) {
        int count = from.remaining();
        if (pending.remaining() < count) {
            ByteBuffer bigger = ByteBuffer.allocateDirect(
                    Math.max(pending.capacity() * 2, pending.position() + count));
            pending.flip();
            bigger.put(pending);
            pending = bigger;
        }
        pending.put(from);
        return count;
    }

    @Override
    public int read(ByteBuffer into) throws IOException {
        flush();
        while (!incoming.hasRemaining()) {
            readPacket();
        }
        int count = Math.min(into.remaining(), incoming.remaining());
        int limit = incoming.limit();
        incoming.limit(incoming.position() + count);
        into.put(incoming);
        incoming.limit(limit);
        return count;
    }

    /** The collected flight, as PRELOGIN packets - the last one marked end of message. */
    private void flush() throws IOException {
        if (pending.position() == 0) {
            return;
        }
        pending.flip();
        int number = 1;
        while (pending.hasRemaining()) {
            int payload = Math.min(pending.remaining(), PACKET - Tds.HEADER_SIZE);
            boolean last = payload == pending.remaining();
            int length = Tds.HEADER_SIZE + payload;
            outgoing.clear();
            outgoing.put((byte) Tds.TYPE_PRELOGIN);
            outgoing.put((byte) (last ? Tds.STATUS_END_OF_MESSAGE : 0));
            outgoing.put((byte) (length >>> 8));
            outgoing.put((byte) length);
            outgoing.putShort((short) 0);                       // SPID
            outgoing.put((byte) number++);
            outgoing.put((byte) 0);                             // window
            int limit = pending.limit();
            pending.limit(pending.position() + payload);
            outgoing.put(pending);
            pending.limit(limit);
            outgoing.flip();
            while (outgoing.hasRemaining()) {
                raw.write(outgoing);
            }
        }
        pending.clear();
    }

    /** The next TDS packet's payload; the server may split a flight over several. */
    private void readPacket() throws IOException {
        header.clear();
        readFully(header);
        header.flip();
        header.get();                                           // type
        header.get();                                           // status
        int length = ((header.get() & 0xff) << 8) | (header.get() & 0xff);
        int payload = length - Tds.HEADER_SIZE;
        if (payload < 0 || payload > incoming.capacity()) {
            throw new IOException("the server announced a pre-login packet of " + length
                    + " bytes");
        }
        incoming.clear();
        incoming.limit(payload);
        readFully(incoming);
        incoming.flip();
    }

    private void readFully(ByteBuffer target) throws IOException {
        while (target.hasRemaining()) {
            if (raw.read(target) < 0) {
                throw new EOFException("the server closed the connection during the TLS "
                        + "handshake inside the pre-login packets");
            }
        }
    }

    /**
     * The handshake is over: whatever the server sent inside pre-login packets
     * has been read, and from here on records go on the socket itself.
     */
    void finished() throws IOException {
        flush();
        if (incoming.hasRemaining()) {
            throw new IOException("the server sent " + incoming.remaining() + " bytes inside "
                    + "the pre-login packets after its handshake had finished");
        }
    }

    @Override
    public void networkTimeout(int millis) throws IOException {
        raw.networkTimeout(millis);
    }

    @Override
    public boolean isOpen() {
        return raw.isOpen();
    }

    /** The socket belongs to the session, not to the handshake running over it. */
    @Override
    public void close() {
        // nothing of its own to release
    }
}
