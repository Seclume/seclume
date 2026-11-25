package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * A MAX value arrives as an eight-byte total and chunks. The reader followed
 * the chunks and never compared them with the total: a server announcing ten
 * bytes and sending four was read as four, without a word.
 */
class PlpTotalTest {

    /** COLMETADATA for one varbinary(max) column. */
    private static void column(ByteArrayOutputStream out) {
        out.write(0x81);
        out.writeBytes(new byte[] {0x01, 0x00});            // one column
        out.writeBytes(new byte[] {0x00, 0x00, 0x00, 0x00}); // user type
        out.writeBytes(new byte[] {0x09, 0x00});            // flags: nullable
        out.write(0xa5);                                    // varbinary
        out.writeBytes(new byte[] {(byte) 0xff, (byte) 0xff}); // MAX
        out.write(0x01);                                    // name: one character
        out.writeBytes(new byte[] {'v', 0x00});
    }

    private static byte[] le(long value, int bytes) {
        byte[] out = new byte[bytes];
        for (int i = 0; i < bytes; i++) {
            out[i] = (byte) (value >>> (8 * i));
        }
        return out;
    }

    private static byte[] tokens(long total, int... chunks) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        column(out);
        out.write(0xd1);
        out.writeBytes(le(total, 8));
        for (int chunk : chunks) {
            out.writeBytes(le(chunk, 4));
            out.writeBytes(new byte[chunk]);
        }
        out.writeBytes(le(0, 4));                           // terminator
        out.write(0xfd);
        out.writeBytes(new byte[] {0x10, 0x00, 0x00, 0x00});
        out.writeBytes(new byte[] {0x01, 0, 0, 0, 0, 0, 0, 0});
        return out.toByteArray();
    }

    private static WireBuffer buffer(byte[] bytes) {
        WireBuffer in = new WireBuffer(bytes.length + 16);
        for (byte b : bytes) {
            in.putByte(b);
        }
        in.position(0);
        in.limit(bytes.length);
        return in;
    }

    private static int read(byte[] tokens) throws Exception {
        try (WireBuffer in = buffer(tokens)) {
            return new TokenStream().readComplete(in, 0, tokens.length, row -> { });
        }
    }

    @Test
    void aTotalTheChunksDoNotAddUpToIsRefused() {
        IOException refused = assertThrows(IOException.class, () -> read(tokens(10, 4)));
        assertTrue(String.valueOf(refused.getMessage()).contains("announced"),
                String.valueOf(refused.getMessage()));
        assertThrows(IOException.class, () -> read(tokens(3, 2, 2)));
    }

    @Test
    void aTotalThatMatchesOrIsUnknownIsRead() throws Exception {
        byte[] matching = tokens(6, 4, 2);
        assertTrue(read(matching) == matching.length);
        byte[] unknown = tokens(0xfffffffffffffffeL, 4, 2);
        assertTrue(read(unknown) == unknown.length);
    }
}
