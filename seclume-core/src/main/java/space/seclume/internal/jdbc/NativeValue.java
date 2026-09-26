package space.seclume.internal.jdbc;

import java.lang.foreign.MemorySegment;

/**
 * A parameter whose bytes are in native memory and must stay there.
 *
 * <p>What {@link space.seclume.SensitiveParameters} puts into a driver's
 * parameter list. Every encoder here already knows how to write a byte string;
 * this is the same thing with the bytes somewhere a heap dump cannot see, and
 * each driver's encoder gains one branch for it.
 *
 * <p><b>It holds the caller's segment and does not copy.</b> Copying would
 * need somewhere to copy to, and the only somewhere that is not the heap is
 * another native allocation with a lifetime of its own - locked, wiped,
 * owned by whom. The caller already has one, usually a
 * {@link space.seclume.secret.SecretScope}, so the contract is instead that it
 * stays open until the statement has executed. That is the same contract a
 * {@code byte[]} parameter has and nobody writes down, made explicit here
 * because the consequence of breaking it is louder.
 */
public record NativeValue(MemorySegment memory) {

    public NativeValue {
        if (memory == null) {
            throw new IllegalArgumentException("a native parameter needs a segment");
        }
    }

    /** How many bytes will go on the wire. */
    public int length() {
        return (int) memory.byteSize();
    }
}
