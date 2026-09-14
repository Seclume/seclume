package space.seclume.crypto;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * As much DER as an RSA public key needs - and no more.
 *
 * <p>Works exclusively with positions inside the segment it is given; nothing
 * is copied and nothing is materialised as a {@code byte[]}.
 */
final class Der {

    static final int SEQUENCE = 0x30;
    static final int INTEGER = 0x02;
    static final int BIT_STRING = 0x03;

    private Der() {
    }

    /** A range within the source segment. */
    record Range(long offset, long length) {
    }

    /** A moving cursor over a DER structure. */
    static final class Reader {

        private final MemorySegment data;
        private long position;
        private final long end;

        Reader(MemorySegment data, long offset, long length) {
            this.data = data;
            this.position = offset;
            this.end = offset + length;
        }

        /** Descends into a SEQUENCE. */
        Reader readSequence() {
            Range content = readTagged(SEQUENCE);
            return new Reader(data, content.offset(), content.length());
        }

        /**
         * Descends into a BIT STRING. The first content byte counts the unused
         * bits and is not part of the content.
         */
        Reader readBitString() {
            Range content = readTagged(BIT_STRING);
            if (content.length() < 1) {
                throw new IllegalArgumentException("empty BIT STRING");
            }
            int unused = data.get(ValueLayout.JAVA_BYTE, content.offset()) & 0xff;
            if (unused != 0) {
                throw new IllegalArgumentException("unexpected unused bits in BIT STRING: " + unused);
            }
            return new Reader(data, content.offset() + 1, content.length() - 1);
        }

        /** The content of an INTEGER, without the length field. */
        Range readIntegerRange() {
            return readTagged(INTEGER);
        }

        /** Skips the next element together with its content. */
        void skipElement() {
            readAny();
        }

        private Range readTagged(int expectedTag) {
            int tag = nextByte();
            if (tag != expectedTag) {
                throw new IllegalArgumentException(
                        "expected DER tag 0x" + Integer.toHexString(expectedTag)
                        + ", found 0x" + Integer.toHexString(tag));
            }
            long length = readLength();
            long offset = position;
            position += length;
            if (position > end) {
                throw new IllegalArgumentException("DER element exceeds its container");
            }
            return new Range(offset, length);
        }

        private Range readAny() {
            nextByte();
            long length = readLength();
            long offset = position;
            position += length;
            if (position > end) {
                throw new IllegalArgumentException("DER element exceeds its container");
            }
            return new Range(offset, length);
        }

        private long readLength() {
            int first = nextByte();
            if ((first & 0x80) == 0) {
                return first;
            }
            int count = first & 0x7f;
            if (count == 0 || count > 4) {
                throw new IllegalArgumentException("unsupported DER length of " + count + " bytes");
            }
            long length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | nextByte();
            }
            return length;
        }

        private int nextByte() {
            if (position >= end) {
                throw new IllegalArgumentException("truncated DER structure");
            }
            return data.get(ValueLayout.JAVA_BYTE, position++) & 0xff;
        }
    }
}
