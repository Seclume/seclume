package space.seclume.mongodb.driver.internal;

import io.airlift.compress.v3.MalformedInputException;
import io.airlift.compress.v3.snappy.SnappyJavaCompressor;
import io.airlift.compress.v3.snappy.SnappyJavaDecompressor;
import io.airlift.compress.v3.zstd.ZstdJavaCompressor;
import io.airlift.compress.v3.zstd.ZstdJavaDecompressor;

/**
 * snappy and zstd from aircompressor - Java, no native library to load, as
 * zlib from the JDK needs none either. An optional dependency: this class is
 * loaded only when a URL asks for one of the two, and {@link #available}
 * says beforehand whether it can be.
 */
final class Airlift {

    private Airlift() {
    }

    static boolean available() {
        try {
            Class.forName("io.airlift.compress.v3.zstd.ZstdJavaCompressor", false,
                    Airlift.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    static byte[] compress(OpMsg.Compressor compressor, byte[] body) {
        if (compressor == OpMsg.Compressor.SNAPPY) {
            SnappyJavaCompressor snappy = new SnappyJavaCompressor();
            byte[] out = new byte[snappy.maxCompressedLength(body.length)];
            int n = snappy.compress(body, 0, body.length, out, 0, out.length);
            return java.util.Arrays.copyOf(out, n);
        }
        ZstdJavaCompressor zstd = new ZstdJavaCompressor();
        byte[] out = new byte[zstd.maxCompressedLength(body.length)];
        int n = zstd.compress(body, 0, body.length, out, 0, out.length);
        return java.util.Arrays.copyOf(out, n);
    }

    /**
     * Into exactly {@code into.length} bytes - what the reply announced. A
     * stream that names another size, or would write past it, is refused
     * before anything is written beyond the buffer; @return the bytes written.
     */
    static int decompress(OpMsg.Compressor compressor, byte[] packed, byte[] into) {
        try {
            if (compressor == OpMsg.Compressor.SNAPPY) {
                SnappyJavaDecompressor snappy = new SnappyJavaDecompressor();
                if (snappy.getUncompressedLength(packed, 0) != into.length) {
                    return -1;
                }
                return snappy.decompress(packed, 0, packed.length, into, 0, into.length);
            }
            ZstdJavaDecompressor zstd = new ZstdJavaDecompressor();
            long announced = zstd.getDecompressedSize(packed, 0, packed.length);
            if (announced >= 0 && announced != into.length) {
                return -1;
            }
            return zstd.decompress(packed, 0, packed.length, into, 0, into.length);
        } catch (MalformedInputException | IndexOutOfBoundsException
                | IllegalArgumentException | IllegalStateException e) {
            // Whatever a malformed stream throws: not a reply.
            return -1;
        }
    }
}
