package space.seclume.oracle.net;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.Aes;
import space.seclume.crypto.AesKey;
import space.seclume.crypto.ConstantTime;
import space.seclume.crypto.Digest;
import space.seclume.crypto.HashAlgorithm;
import space.seclume.secret.SecretScope;

/**
 * Oracle Native Network Encryption on a DATA packet's contents, once the
 * advanced negotiation ({@link AdvancedNegotiation}) has settled the
 * algorithms and a Diffie-Hellman secret.
 *
 * <p>What a packet carries after its ten-byte header and data flags:
 * <pre>
 *   AES-CBC( data || checksum || zero padding to 16 )  ||  padding + 1  ||  0
 * </pre>
 * The encryption starts from a zero IV on every packet, with the first 16,
 * 24 or 32 bytes of the shared secret as the key. The checksum is a hash of
 * the data and of the next block of a keystream: an AES-128-CBC chain per
 * direction, keyed from the shared secret and the IV the server sent, that
 * runs on from packet to packet and is derived afresh after a reset marker.
 *
 * <p>This follows go-ora's implementation of the protocol (MIT licence - see
 * NOTICE), checked against Oracle Free 23 with the encryption and checksums
 * required. Everything keyed lives in native memory: the shared secret, the
 * AES keys and the keystream state.
 *
 * <p>Only AES (128, 192, 256) and SHA-2 checksums are accepted - the RC4,
 * DES and MD5/SHA-1 variants of the protocol are not offered.
 */
final class NativeEncryption implements AutoCloseable {

    static final int AES128 = 15;
    static final int AES192 = 16;
    static final int AES256 = 17;
    static final int SHA512 = 4;
    static final int SHA256 = 5;
    static final int SHA384 = 6;

    private final Arena arena = Arena.ofShared();
    private final String description;
    private final AesKey key;                     // null without encryption
    private final HashAlgorithm checksum;         // null without checksums
    private final MemorySegment zeroIv;
    private Chain keyGenerator;
    private Chain sending;
    private Chain receiving;
    private final MemorySegment seed;             // 32 bytes, carried from one derivation to the next
    private final MemorySegment sendBlock;        // the keystream's last block, each direction
    private final MemorySegment receiveBlock;

    /**
     * @param shared    the Diffie-Hellman secret; copied, the caller closes it
     * @param serverIv  the IV the server sent with its public value
     */
    NativeEncryption(int encryption, int integrity, SecretScope shared, MemorySegment serverIv) {
        MemorySegment secret = shared.segment();
        int keyLength = switch (encryption) {
            case 0 -> 0;
            case AES128 -> 16;
            case AES192 -> 24;
            case AES256 -> 32;
            default -> throw new IllegalArgumentException("encryption algorithm " + encryption
                    + " - only AES is offered");
        };
        this.checksum = switch (integrity) {
            case 0 -> null;
            case SHA256 -> HashAlgorithm.SHA_256;
            case SHA384 -> HashAlgorithm.SHA_384;
            case SHA512 -> HashAlgorithm.SHA_512;
            default -> throw new IllegalArgumentException("checksum algorithm " + integrity
                    + " - only SHA-2 is offered");
        };
        if (shared.length() < Math.max(keyLength, 5)) {
            throw new IllegalArgumentException("a shared secret of " + shared.length()
                    + " bytes is too short for the negotiated algorithms");
        }
        this.key = keyLength == 0 ? null : new AesKey(secret, 0, keyLength);
        this.description = (keyLength == 0 ? "no encryption" : "AES" + keyLength * 8) + "/"
                + (checksum == null ? "no checksum" : checksum.name().replace("_", ""));
        this.zeroIv = arena.allocate(Aes.BLOCK);
        this.seed = arena.allocate(32);
        if (checksum != null) {
            if (serverIv.byteSize() < Aes.BLOCK) {
                throw new IllegalArgumentException("the server's IV has " + serverIv.byteSize()
                        + " bytes, 16 are needed");
            }
            this.sendBlock = arena.allocate(checksum.digestLength());
            this.receiveBlock = arena.allocate(checksum.digestLength());
            MemorySegment first = arena.allocate(16);
            MemorySegment.copy(secret, 0, first, 0, 5);
            first.set(ValueLayout.JAVA_BYTE, 5, (byte) 0xff);
            this.keyGenerator = new Chain(first, serverIv.asSlice(0, Aes.BLOCK));
            first.fill((byte) 0);
            derive();
        } else {
            this.sendBlock = null;
            this.receiveBlock = null;
        }
    }

    /** The algorithms, e.g. {@code AES256/SHA256}. */
    String description() {
        return description;
    }

    /** At most this many bytes more than the data. */
    int overhead() {
        return (checksum == null ? 0 : checksum.digestLength()) + (key == null ? 0 : Aes.BLOCK + 1)
                + 1;
    }

    /**
     * The checksum keys anew, after a reset marker - both ends do it, the
     * chain carrying on from where it stood.
     */
    void reset() {
        if (checksum != null) {
            derive();
        }
    }

    private void derive() {
        keyGenerator.encrypt(seed, 0, 32);
        MemorySegment iv = seed.asSlice(16, 16);
        try (Arena call = Arena.ofConfined()) {
            MemorySegment next = call.allocate(16);
            MemorySegment.copy(seed, 0, next, 0, 16);
            Chain generator = new Chain(next, iv);
            next.set(ValueLayout.JAVA_BYTE, 5, (byte) 90);
            Chain send = new Chain(next, iv);
            next.set(ValueLayout.JAVA_BYTE, 5, (byte) 180);
            Chain receive = new Chain(next, iv);
            keyGenerator.close();
            if (sending != null) {
                sending.close();
                receiving.close();
            }
            keyGenerator = generator;
            sending = send;
            receiving = receive;
            next.fill((byte) 0);
        }
    }

    /**
     * Seals {@code length} bytes of {@code data} at {@code offset} into
     * {@code out} at {@code outOffset}, which has room for
     * {@code length + overhead()}; returns the sealed length.
     */
    int seal(MemorySegment data, long offset, int length, MemorySegment out, long outOffset) {
        MemorySegment.copy(data, offset, out, outOffset, length);
        int total = length;
        if (checksum != null) {
            sending.encrypt(sendBlock, 0, (int) sendBlock.byteSize());
            try (Digest digest = checksum.newDigest()) {     // per packet: its state is thread-bound
                digest.update(data, offset, length);
                digest.update(sendBlock);
                digest.digest(out, outOffset + total);
            }
            total += checksum.digestLength();
        }
        if (key != null) {
            int padding = (Aes.BLOCK - total % Aes.BLOCK) % Aes.BLOCK;
            out.asSlice(outOffset + total, padding).fill((byte) 0);
            total += padding;
            Aes.cbcEncrypt(key, zeroIv, out, outOffset, out, outOffset, total);
            out.set(ValueLayout.JAVA_BYTE, outOffset + total, (byte) (padding + 1));
            total++;
        }
        out.set(ValueLayout.JAVA_BYTE, outOffset + total, (byte) 0);    // the folding key
        return total + 1;
    }

    /**
     * Opens a packet's contents in place: {@code length} bytes at
     * {@code offset}; returns the length of the data, which then starts at
     * {@code offset}.
     */
    int open(MemorySegment packet, long offset, int length) throws IOException {
        if (length <= 1) {
            return length;
        }
        int total = length - 1;                                          // the folding key
        if (key != null) {
            if (total < 1 || (total - 1) % Aes.BLOCK != 0) {           // no blocks: empty data
                throw new IOException("an encrypted packet of " + total + " bytes cannot be "
                        + "whole blocks and a padding byte");
            }
            int padding = packet.get(ValueLayout.JAVA_BYTE, offset + total - 1) & 0xff;
            if (padding < 1 || padding > Aes.BLOCK) {
                throw new IOException("an encrypted packet with a padding byte of " + padding);
            }
            Aes.cbcDecrypt(key, zeroIv, packet, offset, packet, offset, total - 1);
            total -= padding;
        }
        if (checksum != null) {
            int size = checksum.digestLength();
            if (total <= size) {
                throw new IOException("a packet too short for its checksum");
            }
            total -= size;
            receiving.encrypt(receiveBlock, 0, (int) receiveBlock.byteSize());
            try (Arena call = Arena.ofConfined(); Digest digest = checksum.newDigest()) {
                MemorySegment computed = call.allocate(size);
                digest.update(packet, offset, total);
                digest.update(receiveBlock);
                digest.digest(computed, 0);
                if (!ConstantTime.equals(computed, 0, packet, offset + total, size)) {
                    throw new IOException("a packet failed its checksum - it was changed on "
                            + "the way, or the keys do not agree");
                }
            }
        }
        return total;
    }

    @Override
    public void close() {
        if (key != null) {
            key.close();
        }
        if (keyGenerator != null) {
            keyGenerator.close();
        }
        if (sending != null) {
            sending.close();
            receiving.close();
        }
        seed.fill((byte) 0);
        if (sendBlock != null) {
            sendBlock.fill((byte) 0);
            receiveBlock.fill((byte) 0);
        }
        arena.close();
    }

    /** AES-128-CBC whose chaining runs on from one call to the next. */
    private static final class Chain implements AutoCloseable {

        private final AesKey key;
        private final Arena arena = Arena.ofShared();      // a pooled connection changes threads
        private final MemorySegment iv;

        Chain(MemorySegment key, MemorySegment iv) {
            this.key = new AesKey(key, 0, 16);
            this.iv = arena.allocate(Aes.BLOCK);
            MemorySegment.copy(iv, 0, this.iv, 0, Aes.BLOCK);
        }

        /** Encrypts whole blocks in place, and keeps the last as the next IV. */
        void encrypt(MemorySegment data, long offset, int length) {
            Aes.cbcEncrypt(key, iv, data, offset, data, offset, length);
            MemorySegment.copy(data, offset + length - Aes.BLOCK, iv, 0, Aes.BLOCK);
        }

        @Override
        public void close() {
            key.close();
            iv.fill((byte) 0);
            arena.close();
        }
    }
}
