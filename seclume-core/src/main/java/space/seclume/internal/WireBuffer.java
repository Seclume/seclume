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

    /**
     * Says how much of the buffer is valid - and refuses a claim the memory
     * cannot back.
     *
     * <p><b>The bounds checks below are only as honest as this number.</b>
     * {@code require} compares against {@code limit}, so a limit set from a
     * length that came off the wire and was never compared to the capacity
     * makes every check downstream pass while the reads walk off the end.
     * That is how it showed up: a MySQL packet header spoilt to announce
     * 131 072 bytes in a 32 KB buffer, {@code require(131072)} passing
     * cheerfully, and the {@code IndexOutOfBoundsException} arriving from the
     * MemorySegment two frames later. Found by the decoder fuzz sweep on
     * 23.09.2026, after two shallower fixes in the same area had each moved
     * the failure one layer down.
     */
    public void limit(int newLimit) {
        if (newLimit < 0 || newLimit > capacity()) {
            throw new Truncated("a message of " + newLimit + " bytes was announced, and this "
                    + "buffer holds " + capacity() + " - the server sent something unexpected");
        }
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
        // The check alone, small enough to be inlined into every put: the
        // growing below made this too large for that, and a call per byte
        // written was the largest single cost of encoding a batch.
        if (needed > segment.byteSize()) {
            grow(needed);
        }
    }

    private void grow(int needed) {
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
        // Checked like getByte and getInt: this one was not, and read past
        // the valid bytes into whatever the buffer held before - which a
        // reader that goes on packet by packet relies on hearing about.
        requireAt(at, 4);
        return segment.get(LE_INT, at);
    }

    /**
     * Eight bytes at {@code at}, little endian.
     *
     * <p>Here for a reason that is not about endianness at all: a checked
     * access to a {@link java.lang.foreign.MemorySegment} costs the same
     * whether it fetches one byte or eight, and the cost is per access. Text
     * that is parsed a digit at a time therefore pays eight times over.
     * Measured on the parse loop alone, three hundred thousand values: 2.37 ms
     * byte by byte, 0.74 ms eight at a time - and a plain {@code byte[]}, which
     * this library cannot use for payload, is 0.70 ms.
     *
     * <p>See {@code Row#getLong}, which is what this exists for.
     */
    public long getLongLe(int at) {
        // Not checked against the limit, unlike getIntLe: TextNumber reads
        // eight bytes at a time up to the capacity and uses only its own.
        return segment.get(LE_LONG, at);
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
        requireAt(at, 4);
        return segment.get(BE_INT, at);
    }

    public byte getByte(int at) {
        requireAt(at, 1);
        return segment.get(ValueLayout.JAVA_BYTE, at);
    }

    /** A slice without copying - this is how row data is passed on. */
    public MemorySegment slice(int offset, int length) {
        requireAt(offset, length);
        return segment.asSlice(offset, length);
    }

    /**
     * The same check as {@link #require}, for the accessors that take an
     * offset instead of using the cursor.
     *
     * <p><b>These three had no check at all.</b> The sequential readers all
     * call {@code require}; the absolute ones did not, and the difference was
     * invisible because the absolute ones are used for random access within a
     * message whose offsets the decoder had just computed itself - which is
     * fine until one of those offsets is computed from a length that came off
     * the wire.
     *
     * <p>What that looked like: SQL Server's {@code ColumnMetadata} reading a
     * column count that disagreed with the columns, walking its offset past
     * the end of a 32 KB buffer, and getting an {@code IndexOutOfBoundsException}
     * <b>from the MemorySegment</b> - a JVM-level message about a native
     * address, out of {@code Statement.executeQuery}, where an application
     * expects a {@code SQLException}. Found by the decoder fuzz sweep on
     * 23.09.2026.
     *
     * <p>The bound is the message's {@code limit} and not the segment's
     * capacity, deliberately: reading another message's bytes is not a crash
     * but it is still wrong, and it is the more insidious of the two.
     */
    private void requireAt(int at, int bytes) {
        // Against the furthest byte known to be good, which is `limit` while
        // reading and `position` while writing - this class does not track
        // which it is doing, and the first version of this check compared
        // against `limit` alone. That broke every caller that reads back out
        // of a buffer it has just written, where `limit` is still zero: 70
        // tests in the core said so within a minute of it going in.
        int valid = Math.max(limit, position);
        if (at < 0 || bytes < 0 || at > valid - bytes) {
            throw new Truncated("the buffer holds " + valid + " valid bytes, and " + bytes
                    + " were wanted at " + at + " - the server sent something unexpected");
        }
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

    /**
     * An answer that cannot be what the protocol says - a count below zero, a
     * length past any limit. Thrown where it is found, and handled like a
     * truncated one: the connection is broken, because its stream is at a
     * position nobody can make sense of.
     */
    public static Truncated malformed(String what) {
        return new Truncated(what);
    }

    /**
     * A message that stopped before it had said everything it promised.
     *
     * <p>Its own type, and not a bare {@code IllegalStateException}, so the
     * protocol layers can tell the two cases apart: <b>the peer sent
     * nonsense</b>, which is a connection error and belongs to the caller as
     * a {@code SQLException}, and <b>this code has a bug</b>, which does not
     * and must not be swallowed with it. Catching {@code RuntimeException} at
     * a protocol boundary would hide the second inside the first, and the
     * second is the one worth finding.
     *
     * <p>It stays an {@code IllegalStateException} so that anything already
     * catching that keeps working.
     */
    public static final class Truncated extends IllegalStateException {

        private static final long serialVersionUID = 1L;

        Truncated(String message) {
            super(message);
        }

        /**
         * For a decoder outside this package that has found the same fact.
         *
         * <p>A row that ends after two of its three columns is a message
         * announcing more than it brought, said in the vocabulary of the layer
         * above. Throwing this rather than a bare
         * {@code IllegalStateException} is what makes the refusal reach an
         * application as a {@code SQLException}: the four sessions map this
         * type to a connection failure, and they map nothing else.
         */
        public static Truncated because(String message) {
            return new Truncated(message);
        }
    }

    /**
     * The one bounds check every decoder in all four drivers stands on.
     *
     * <p><b>Written as a subtraction, and that is the whole of it.</b> The
     * obvious form, {@code position + bytes > limit}, is wrong for exactly the
     * input an attacker sends: a length of {@code 0x7fffffff} read off the
     * wire makes the addition overflow, the sum comes out negative, the
     * comparison says the bytes are there, and the position walks off the end
     * of the buffer. Everything downstream then reads at an offset that means
     * nothing - and in PostgreSQL's row reader it meant
     * {@code new byte[0x7fffffff]} and an {@code OutOfMemoryError}, which in a
     * server is not this connection's death but every connection's.
     *
     * <p>{@code bytes < 0} is refused for the same reason rather than trusted
     * to be impossible: a negative length reaching a caller that adds it to a
     * position is the same bug wearing the other sign.
     *
     * <p>Found by the decoder fuzz sweep on 23.09.2026, from a DataRow whose
     * column length was a single spoilt field. The check had been correct for
     * every length a server actually sends, which is why nothing else found
     * it.
     */
    private void require(int bytes) {
        if (bytes < 0 || bytes > limit - position) {
            throw new Truncated(
                    "the message ends after " + limit + " bytes, but " + bytes
                    + " more were needed at " + position
                    + " - the server sent something unexpected");
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
