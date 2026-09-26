package space.seclume.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.HashAlgorithm;

/**
 * An AWS canonical request, assembled in native memory because one of its
 * lines can be a secret.
 *
 * <p>Almost all of a canonical request is public: a method, a path, the
 * header names, the hash of a body that carries nothing. Building it by
 * concatenating strings was therefore right, and this class exists for the
 * one line where it stops being right.
 *
 * <p><b>The session token.</b> Temporary AWS credentials - IRSA, an instance
 * role, {@code AssumeRole} - come as three parts: an access key id, a secret
 * key and a <b>session token</b>. The token is not merely sent, it is
 * <em>signed</em>, which means it appears inside the canonical request as
 * {@code x-amz-security-token:...}. Concatenate that into a {@code String}
 * and the token is on the heap for as long as the garbage collector feels
 * like it - and a session token is a credential in every sense that matters:
 * whoever has it, together with the other two parts, is you.
 *
 * <p>That is why this project said for a while that session tokens were not
 * supported, rather than supporting them badly. The answer turns out to be
 * small: write the canonical request into a segment, append the token as
 * bytes, hash the segment. What comes out is a hex digest - public by
 * construction, because it is what gets signed and sent - so everything
 * above this line can go back to being ordinary text.
 *
 * <p>The buffer is wiped on close, and the class is {@link AutoCloseable} so
 * that an exception on the way cannot skip it.
 */
public final class CanonicalRequest implements AutoCloseable {

    private final MemorySegment buffer;
    private int length;
    private boolean closed;

    /**
     * @param arena    where the buffer lives; the caller's, so that its
     *                 lifetime is visibly the caller's too
     * @param capacity an upper bound on the finished request in bytes
     */
    public CanonicalRequest(Arena arena, int capacity) {
        this.buffer = arena.allocate(capacity);
    }

    /** Appends public text - a method, a header name, a newline. */
    public CanonicalRequest text(String value) {
        checkOpen();
        length += AwsSigV4.writeAscii(buffer.asSlice(length, buffer.byteSize() - length), value);
        return this;
    }

    /**
     * Appends bytes that must not become a Java object.
     *
     * <p>Copied segment to segment. Nothing here looks at what it is - a
     * length check and nothing else - because the moment this class starts
     * inspecting the value is the moment somebody wants it as a string.
     */
    public CanonicalRequest secret(MemorySegment value, int valueLength) {
        checkOpen();
        if (valueLength < 0 || length + valueLength > buffer.byteSize()) {
            throw new IllegalStateException("the canonical request does not fit in the "
                    + buffer.byteSize() + " bytes reserved for it");
        }
        MemorySegment.copy(value, 0, buffer, length, valueLength);
        length += valueLength;
        return this;
    }

    /** Appends secret bytes URL-encoded - a session token inside a query. */
    public CanonicalRequest secretUrlEncoded(MemorySegment value, int valueLength) {
        checkOpen();
        if (valueLength < 0 || length + 3L * valueLength > buffer.byteSize()) {
            throw new IllegalStateException("the canonical request does not fit in the "
                    + buffer.byteSize() + " bytes reserved for it");
        }
        length += AwsSigV4.urlEncode(value, valueLength, buffer, length);
        return this;
    }

    /**
     * The SHA-256 of what has been written, hex-encoded.
     *
     * <p>Public by construction: this digest is what the string to sign
     * carries and what eventually travels to AWS. Once it exists, nothing
     * downstream needs the request itself - which is the whole trick.
     */
    public String sha256Hex() {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment digest = arena.allocate(HashAlgorithm.SHA_256.digestLength());
            HashAlgorithm.SHA_256.hash(buffer, 0, length, digest, 0);
            return AwsSigV4.hex(digest);
        }
    }

    /** How many bytes have been written - for tests and for bounds. */
    public int length() {
        return length;
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("this canonical request has been wiped");
        }
    }

    /**
     * Wipes the buffer.
     *
     * <p>The arena would free it eventually and freeing is not erasing.
     * Since one line of this may have been a credential, it is zeroed here
     * and the object refuses to be used afterwards.
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        buffer.asSlice(0, length).fill((byte) 0);
        length = 0;
    }

    /** For a caller that wants to check the shape in a test. */
    public byte at(int index) {
        checkOpen();
        return buffer.get(ValueLayout.JAVA_BYTE, index);
    }
}
