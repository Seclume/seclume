package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * An RSA public key, held off-heap.
 *
 * <p>The key itself is not a secret - it is distributed publicly, and MySQL
 * will even send it unencrypted over the wire on request. It still lives
 * off-heap here, because the computation it feeds into processes the password:
 * were the modulus a {@code BigInteger}, the exponentiation would have to run
 * on {@code BigInteger} too, and its intermediate values carry the password.
 */
public final class RsaPublicKey implements AutoCloseable {

    private final Arena arena = Arena.ofConfined();
    private final MemorySegment modulusWords;
    private final MemorySegment exponent;
    private final int exponentLength;
    private final int modulusBytes;
    private final int words;
    private boolean closed;

    private RsaPublicKey(MemorySegment modulus, long modulusOffset, int modulusLength,
                         MemorySegment exponentBytes, long exponentOffset, int exponentLength) {
        // Leading zero bytes are not part of the key length; a DER INTEGER
        // likes to carry one so the number stays positive.
        int start = 0;
        while (start < modulusLength - 1
                && modulus.get(ValueLayout.JAVA_BYTE, modulusOffset + start) == 0) {
            start++;
        }
        this.modulusBytes = modulusLength - start;
        this.words = BigWords.wordCount(modulusBytes);
        this.modulusWords = arena.allocate(words * 4L);
        BigWords.fromBytes(modulus, modulusOffset + start, modulusBytes, modulusWords, words);

        int expStart = 0;
        while (expStart < exponentLength - 1
                && exponentBytes.get(ValueLayout.JAVA_BYTE, exponentOffset + expStart) == 0) {
            expStart++;
        }
        this.exponentLength = exponentLength - expStart;
        this.exponent = arena.allocate(this.exponentLength);
        MemorySegment.copy(exponentBytes, exponentOffset + expStart, exponent, 0, this.exponentLength);
    }

    /** From modulus and exponent, each as big-endian bytes. */
    public static RsaPublicKey of(MemorySegment modulus, MemorySegment exponent) {
        return new RsaPublicKey(modulus, 0, (int) modulus.byteSize(),
                exponent, 0, (int) exponent.byteSize());
    }

    /**
     * From a DER-encoded {@code SubjectPublicKeyInfo} - the content of a
     * {@code BEGIN PUBLIC KEY} PEM block, the way MySQL delivers it.
     */
    public static RsaPublicKey fromSubjectPublicKeyInfo(MemorySegment der) {
        Der.Reader outer = new Der.Reader(der, 0, der.byteSize());
        Der.Reader spki = outer.readSequence();
        spki.skipElement();                       // AlgorithmIdentifier
        Der.Reader bitString = spki.readBitString();
        Der.Reader rsaKey = bitString.readSequence();
        Der.Range modulus = rsaKey.readIntegerRange();
        Der.Range exponent = rsaKey.readIntegerRange();
        return new RsaPublicKey(der, modulus.offset(), (int) modulus.length(),
                der, exponent.offset(), (int) exponent.length());
    }

    /** Length of the modulus in bytes - every ciphertext comes out this long. */
    public int modulusBytes() {
        checkOpen();
        return modulusBytes;
    }

    int words() {
        return words;
    }

    MemorySegment modulusWords() {
        checkOpen();
        return modulusWords;
    }

    MemorySegment exponentBytes() {
        checkOpen();
        return exponent;
    }

    int exponentLength() {
        return exponentLength;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        modulusWords.fill((byte) 0);
        exponent.fill((byte) 0);
        arena.close();
    }

    @Override
    public String toString() {
        return "RsaPublicKey[bits=" + (modulusBytes * 8) + "]";
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("this RSA key is closed - its memory was wiped, build a new one");
        }
    }
}
