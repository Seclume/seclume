package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

/**
 * The shared scaffolding of the four Merkle-Damgard hashes.
 *
 * <p>The chaining value, the message schedule and the partial block live in an
 * {@link Arena} of their own and are zeroed on close. The round variables of
 * the compression function are local {@code int}/{@code long} values - those
 * sit on the stack or in registers and appear in no hprof dump; an hprof dump
 * contains objects and primitive arrays, not stack frames.
 */
abstract sealed class BlockDigest implements Digest
        permits Md5Digest, Sha1Digest, Sha256Digest, Sha512Digest {

    static final ValueLayout.OfInt BE_INT =
            ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN);
    static final ValueLayout.OfInt LE_INT =
            ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final ValueLayout.OfLong BE_LONG =
            ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN);
    static final ValueLayout.OfLong LE_LONG =
            ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    private final Arena arena = Arena.ofConfined();
    private final int blockLength;
    private final int lengthFieldBytes;

    /** The partial block; it holds plaintext and is therefore zeroed. */
    final MemorySegment block;
    /** Chaining value and message schedule; the subclass fixes the size. */
    final MemorySegment state;

    private int blockUsed;
    private long byteCount;
    private boolean closed;

    BlockDigest(int blockLength, int lengthFieldBytes, long stateBytes) {
        this.blockLength = blockLength;
        this.lengthFieldBytes = lengthFieldBytes;
        this.block = arena.allocate(blockLength);
        this.state = arena.allocate(stateBytes);
        initState();
    }

    /** Sets the chaining value to the constants of the algorithm. */
    abstract void initState();

    /** Processes exactly one block starting at {@code offset}. */
    abstract void compress(MemorySegment data, long offset);

    /** Writes the chaining value out as the result. */
    abstract void writeResult(MemorySegment out, long offset);

    @Override
    public final int blockLength() {
        return blockLength;
    }

    @Override
    public final void update(MemorySegment data, long offset, long length) {
        checkOpen();
        if (length < 0 || offset < 0 || offset + length > data.byteSize()) {
            throw new IndexOutOfBoundsException("update outside of the segment");
        }
        long position = offset;
        long remaining = length;

        if (blockUsed > 0) {
            int missing = blockLength - blockUsed;
            int take = (int) Math.min(missing, remaining);
            MemorySegment.copy(data, position, block, blockUsed, take);
            blockUsed += take;
            position += take;
            remaining -= take;
            byteCount += take;
            if (blockUsed == blockLength) {
                compress(block, 0);
                blockUsed = 0;
            }
        }

        // Full blocks straight from the source - every intermediate copy
        // would be one more place the secret sits in.
        while (remaining >= blockLength) {
            compress(data, position);
            position += blockLength;
            remaining -= blockLength;
            byteCount += blockLength;
        }

        if (remaining > 0) {
            MemorySegment.copy(data, position, block, 0, remaining);
            blockUsed = (int) remaining;
            byteCount += remaining;
        }
    }

    @Override
    public final void digest(MemorySegment out, long offset) {
        checkOpen();
        if (offset < 0 || offset + digestLength() > out.byteSize()) {
            throw new IndexOutOfBoundsException("digest does not fit into the target");
        }
        long bitCount = byteCount * 8;

        block.set(ValueLayout.JAVA_BYTE, blockUsed++, (byte) 0x80);
        if (blockUsed > blockLength - lengthFieldBytes) {
            block.asSlice(blockUsed, blockLength - blockUsed).fill((byte) 0);
            compress(block, 0);
            blockUsed = 0;
        }
        block.asSlice(blockUsed, blockLength - lengthFieldBytes - blockUsed).fill((byte) 0);
        writeLength(blockLength - lengthFieldBytes, bitCount);
        compress(block, 0);

        writeResult(out, offset);
        reset();
    }

    /** Writes the bit length in the byte order of the respective algorithm. */
    void writeLength(int at, long bitCount) {
        if (lengthFieldBytes == 16) {
            block.set(BE_LONG, at, 0L);
            block.set(BE_LONG, at + 8L, bitCount);
        } else {
            block.set(BE_LONG, at, bitCount);
        }
    }

    @Override
    public final void reset() {
        checkOpen();
        block.fill((byte) 0);
        state.fill((byte) 0);
        blockUsed = 0;
        byteCount = 0;
        initState();
    }

    @Override
    public final void close() {
        if (closed) {
            return;
        }
        closed = true;
        block.fill((byte) 0);
        state.fill((byte) 0);
        blockUsed = 0;
        byteCount = 0;
        arena.close();
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("this digest is closed - its state was wiped, build a new one");
        }
    }
}
