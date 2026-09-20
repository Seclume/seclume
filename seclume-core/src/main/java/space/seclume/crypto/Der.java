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
    static final int OCTET_STRING = 0x04;

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

        /** Descends into an OCTET STRING, whose content is itself DER. */
        Reader readOctetStringAsDer() {
            Range content = readTagged(OCTET_STRING);
            return new Reader(data, content.offset(), content.length());
        }

        /** The content of an OCTET STRING, as a range in the source. */
        Range readOctetStringRange() {
            return readTagged(OCTET_STRING);
        }

        /** The content of an INTEGER, without the length field. */
        Range readIntegerRange() {
            return readTagged(INTEGER);
        }

        /**
         * A small unsigned INTEGER - version numbers and nothing else.
         *
         * <p>Refuses anything that does not fit in an {@code int}, because the
         * only callers are structure versions and a four-byte version number
         * is a structure this code should not be parsing.
         */
        int readSmallInteger() {
            Range value = readIntegerRange();
            if (value.length() < 1 || value.length() > 4) {
                throw new IllegalArgumentException(
                        "expected a small DER INTEGER, found " + value.length() + " bytes");
            }
            int result = 0;
            for (long i = 0; i < value.length(); i++) {
                result = (result << 8) | (data.get(ValueLayout.JAVA_BYTE, value.offset() + i) & 0xff);
            }
            return result;
        }

        /** The tag of the next element, without consuming it. */
        int peekTag() {
            if (position >= end) {
                throw new IllegalArgumentException("truncated DER structure");
            }
            return data.get(ValueLayout.JAVA_BYTE, position) & 0xff;
        }

        /** Whether anything is left in this container. */
        boolean hasMore() {
            return position < end;
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
