package space.seclume.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * A growing buffer in native memory - the basis for everything that goes over
 * the wire.
 *
 * <p>Two reasons against {@code byte[]} or {@code ByteBuffer.allocate}:
 *
 * <ol>
 *   <li>The password passes through this buffer. A heap array would be findable
 *       in a heap dump, and it could not be zeroed reliably - the GC moves it,
 *       and copies stay behind.</li>
 *   <li>A direct buffer is written and read by {@code SocketChannel} straight
 *       away. With a heap buffer the JDK internally copies once more through a
 *       temporary direct buffer - one copy per network operation, which shows
 *       up in every throughput measurement.</li>
 * </ol>
 *
 * <p>Numbers come in both byte orders, because the protocols do not agree:
 * PostgreSQL writes big-endian, MySQL little-endian. The method names say so -
 * {@code putInt} is big-endian, {@code putIntLe} little-endian - so that the
 * order stays visible at the call site.
 *
 * <p>When the buffer grows, the old memory is <b>zeroed</b> before it is
 * released.
 */
public final class WireBuffer implements AutoCloseable {

    private static final ValueLayout.OfShort BE_SHORT =
            ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN);
    private static final ValueLayout.OfInt BE_INT =
            ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN);

    private static final ValueLayout.OfShort LE_SHORT =
            ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    private static final ValueLayout.OfInt LE_INT =
            ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    private static final ValueLayout.OfLong LE_LONG =
            ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    /**
     * Shared, not pinned to one thread.
     *
     * <p>{@code Arena.ofConfined()} would close faster, but it binds the memory
     * to the thread that created it. That is exactly what goes wrong in a
     * pooled driver: a connection is opened on one virtual thread and returned
     * or closed on another - and {@code close()} would fail with
     * {@code WrongThreadException}, in the middle of cleaning up.
     *
     * <p>The price is a more expensive {@code close()} (the JVM has to
     * coordinate with the other threads). That cost falls once per connection,
     * not per query - and a connection that cannot be closed would be orders of
     * magnitude more expensive.
     */
    private final Arena arena = Arena.ofShared();
    private MemorySegment segment;
    /**
     * A view onto the same memory for {@code SocketChannel}. Cached, because
     * every network operation needs it and {@code asByteBuffer()} would
     * otherwise allocate a new object per call - allocation pressure on the
     * hottest path a driver has.
     */
    private java.nio.ByteBuffer view;
    private int position;
    private int limit;
    private boolean closed;

    public WireBuffer(int initialCapacity) {
        this.segment = arena.allocate(Math.max(initialCapacity, 64));
        this.view = segment.asByteBuffer();
    }

    /**
     * The buffer as a direct {@link java.nio.ByteBuffer} - the same memory, no
     * copy. Position and limit are the caller's business.
     */
    public java.nio.ByteBuffer view() {
        return view;
    }

    /** The raw memory - for channels and cryptography. */
    public MemorySegment segment() {
        return segment;
    }

    public int position() {
        return position;
    }

    public void position(int newPosition) {
        this.position = newPosition;
    }

    /** How many bytes are valid (set while reading; equals position while writing). */
    public int limit() {
        return limit;
    }

    public void limit(int newLimit) {
        this.limit = newLimit;
    }

    public int capacity() {
        return (int) segment.byteSize();
    }

    public int remaining() {
        return limit - position;
    }

    /** Resets the buffer without leaving the content behind. */
    public void clear() {
        segment.asSlice(0, limit == 0 ? Math.min(capacity(), position) : limit).fill((byte) 0);
        position = 0;
        limit = 0;
    }

    /** Resets the pointers only - for buffers that hold no secrets. */
    public void rewind() {
        position = 0;
        limit = 0;
    }

    public void ensureCapacity(int needed) {
        if (needed <= capacity()) {
            return;
        }
        int size = Math.max(capacity() * 2, needed);
        MemorySegment bigger = arena.allocate(size);
        MemorySegment.copy(segment, 0, bigger, 0, Math.max(position, limit));
        // The old buffer may have held the password.
        segment.fill((byte) 0);
        segment = bigger;
        view = segment.asByteBuffer();
    }

    // ---- writing ---------------------------------------------------------

    public WireBuffer putByte(byte value) {
        ensureCapacity(position + 1);
        segment.set(ValueLayout.JAVA_BYTE, position++, value);
        return this;
    }

    public WireBuffer putShort(short value) {
        ensureCapacity(position + 2);
        segment.set(BE_SHORT, position, value);
        position += 2;
        return this;
    }

    public WireBuffer putInt(int value) {
        ensureCapacity(position + 4);
        segment.set(BE_INT, position, value);
        position += 4;
        return this;
    }

    public WireBuffer putInt(int at, int value) {
        segment.set(BE_INT, at, value);
        return this;
    }

    public WireBuffer putBytes(MemorySegment source, long offset, long length) {
        ensureCapacity(position + (int) length);
        MemorySegment.copy(source, offset, segment, position, length);
        position += (int) length;
        return this;
    }

    public WireBuffer putBytes(MemorySegment source) {
        return putBytes(source, 0, source.byteSize());
    }

    /**
     * ASCII/UTF-8 text without a terminator. Only for protocol text and
     * identifiers - <b>never</b> for a password, which would then come from a
     * {@code String} and therefore from the heap.
     */
    public WireBuffer putText(String text) {
        // The fast path writes straight into native memory, one byte per
        // character, and allocates nothing. That is worth a loop: protocol
        // text is SQL, identifiers, portal names - ASCII almost always, and
        // the empty string more often than anything else. The old version
        // went through String.getBytes, which allocates a byte[] every time,
        // including a zero-length one for "". Three of those per execution
        // showed up in the allocation profile of a prepared statement.
        int length = text.length();
        ensureCapacity(position + length);
        for (int i = 0; i < length; i++) {
            char c = text.charAt(i);
            if (c >= 0x80) {
                return putTextUtf8(text);        // rare, and then done properly
            }
            segment.set(ValueLayout.JAVA_BYTE, position + i, (byte) c);
        }
        position += length;
        return this;
    }

    /**
     * The general case, for text that is not ASCII.
     *
     * <p>Nothing written by the fast path before it gave up is kept: the
     * position has not moved, so these bytes land on top of it.
     */
    private WireBuffer putTextUtf8(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8); // seclume-allow: protocol text and identifiers, never a secret
        ensureCapacity(position + bytes.length);
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, segment, position, bytes.length);
        position += bytes.length;
        return this;
    }

    /** Text with a trailing zero, the way the protocol wants it everywhere. */
    public WireBuffer putCString(String text) {
        putText(text);
        return putByte((byte) 0);
    }


    // ---- little-endian, the way MySQL writes it --------------------------

    public WireBuffer putShortLe(short value) {
        ensureCapacity(position + 2);
        segment.set(LE_SHORT, position, value);
        position += 2;
        return this;
    }

    public WireBuffer putIntLe(int value) {
        ensureCapacity(position + 4);
        segment.set(LE_INT, position, value);
        position += 4;
        return this;
    }

    public WireBuffer putIntLe(int at, int value) {
        segment.set(LE_INT, at, value);
        return this;
    }

    public WireBuffer putLongLe(long value) {
        ensureCapacity(position + 8);
        segment.set(LE_LONG, position, value);
        position += 8;
        return this;
    }

    /** Writes one byte at a fixed spot without moving the position. */
    public WireBuffer putByteAt(int at, byte value) {
        segment.set(ValueLayout.JAVA_BYTE, at, value);
        return this;
    }

    /**
     * Fills an unsigned number in at a fixed spot - this is how a packet
     * length is inserted after its content has been written.
     */
    public WireBuffer putUnsignedLeAt(int at, long value, int length) {
        for (int i = 0; i < length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, at + i, (byte) (value >>> (8 * i)));
        }
        return this;
    }

    /** {@code count} zero bytes - filler, as the protocols require in several places. */
    public WireBuffer putZeroes(int count) {
        ensureCapacity(position + count);
        segment.asSlice(position, count).fill((byte) 0);
        position += count;
        return this;
    }

    public short getShortLe() {
        require(2);
        short value = segment.get(LE_SHORT, position);
        position += 2;
        return value;
    }

    public int getIntLe() {
        require(4);
        int value = segment.get(LE_INT, position);
        position += 4;
        return value;
    }

    public int getIntLe(int at) {
        return segment.get(LE_INT, at);
    }

    public long getLongLe() {
        require(8);
        long value = segment.get(LE_LONG, position);
        position += 8;
        return value;
    }

    /** An unsigned number from {@code length} bytes, least significant first. */
    public long getUnsignedLe(int length) {
        require(length);
        long value = 0;
        for (int i = 0; i < length; i++) {
            value |= (segment.get(ValueLayout.JAVA_BYTE, position + i) & 0xffL) << (8 * i);
        }
        position += length;
        return value;
    }

    /** Writes an unsigned number into {@code length} bytes, least significant first. */
    public WireBuffer putUnsignedLe(long value, int length) {
        ensureCapacity(position + length);
        for (int i = 0; i < length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, position + i, (byte) (value >>> (8 * i)));
        }
        position += length;
        return this;
    }

    // ---- reading ---------------------------------------------------------

    public byte getByte() {
        require(1);
        return segment.get(ValueLayout.JAVA_BYTE, position++);
    }

    public short getShort() {
        require(2);
        short value = segment.get(BE_SHORT, position);
        position += 2;
        return value;
    }

    public int getInt() {
        require(4);
        int value = segment.get(BE_INT, position);
        position += 4;
        return value;
    }

    public int getInt(int at) {
        return segment.get(BE_INT, at);
    }

    public byte getByte(int at) {
        return segment.get(ValueLayout.JAVA_BYTE, at);
    }

    /** A slice without copying - this is how row data is passed on. */
    public MemorySegment slice(int offset, int length) {
        return segment.asSlice(offset, length);
    }

    /**
     * Length of the null-terminated string at {@code position}, excluding the
     * zero. The text stays in the buffer; whoever needs it fetches it via
     * {@link #readString(int)}.
     */
    public int cStringLength() {
        int end = position;
        while (end < limit && segment.get(ValueLayout.JAVA_BYTE, end) != 0) {
            end++;
        }
        return end - position;
    }

    /**
     * Reads a null-terminated string as a {@code String}.
     *
     * <p>Allowed for protocol text: error messages, column names, server
     * parameters. For payload, and all the more for secrets,
     * {@link #slice(int, int)} is the way.
     */
    public String readCString() {
        int length = cStringLength();
        String value = readString(length);
        position++;   // Abschlussbyte
        return value;
    }

    /** {@code length} bytes from {@code position} as text; advances. */
    public String readString(int length) {
        require(length);
        byte[] bytes = new byte[length]; // seclume-allow: protocol text such as column names and error messages, never a secret
        MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, position, bytes, 0, length);
        position += length;
        return new String(bytes, StandardCharsets.UTF_8); // seclume-allow: protocol text, never a secret
    }

    public void skip(int bytes) {
        require(bytes);
        position += bytes;
    }

    private void require(int bytes) {
        if (position + bytes > limit) {
            throw new IllegalStateException(
                    "the message ends after " + limit + " bytes, but " + (position + bytes)
                    + " were needed - the server sent something unexpected");
        }
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        segment.fill((byte) 0);
        arena.close();
    }

    /** No content in {@code toString} - it may be carrying a password. */
    @Override
    public String toString() {
        return "WireBuffer[capacity=" + (closed ? "released" : capacity())
                + ", position=" + position + ", limit=" + limit + "]";
    }
}
