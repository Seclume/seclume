package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.sql.SQLException;

import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * The OSON reader takes a server's bytes - a JSON column - and makes text of
 * them. Whatever the bytes, it gives text or an SQLException - a data
 * exception (class 22), or 0A000 for what it does not read. It reads nothing
 * past the length it was given, and shared or cyclic nodes cannot make it run
 * away. The fuzzer's bytes go in as they are, and
 * once more behind a well-formed header, so that mutation reaches the tree
 * instead of dying at the magic.
 */
class OracleJsonFuzzTest {

    private static final int MAX_INPUT = 4096;

    private static byte[] behindAHeader(byte[] tree) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {(byte) 0xff, 0x4a, 0x5a, 0x01});
        out.writeBytes(new byte[] {0x00, 0x00});
        out.write(0x00);
        out.writeBytes(new byte[] {0x00, 0x00});
        out.writeBytes(new byte[] {(byte) (tree.length >> 8), (byte) tree.length});
        out.writeBytes(new byte[] {0x00, 0x00});
        out.writeBytes(tree);
        return out.toByteArray();
    }

    @FuzzTest(maxDuration = "60s")
    void anyColumnValueIsReadOrRefused(byte[] bytes) {
        if (bytes.length > MAX_INPUT) {
            return;
        }
        for (byte[] value : new byte[][] {bytes, behindAHeader(bytes)}) {
            try (Arena arena = Arena.ofConfined()) {
                // Guard bytes on both sides, and an exact slice: a read past the
                // given length is an IndexOutOfBoundsException, not a wrong answer.
                MemorySegment storage = arena.allocate(value.length + 2L);
                storage.fill((byte) 0x5a);
                MemorySegment.copy(value, 0, storage, ValueLayout.JAVA_BYTE, 1, value.length);
                MemorySegment exact = storage.asSlice(1, value.length).asReadOnly();
                try {
                    assertNotNull(OracleJson.toText(exact, 0, value.length));
                } catch (SQLException refused) {
                    // Class 22: not OSON, or a value that does not exist (a 13th
                    // month); 0A000: a version or node type (interval, vector,
                    // extension) this driver does not read.
                    String state = String.valueOf(refused.getSQLState());
                    assertTrue(state.startsWith("22") || state.equals("0A000"),
                            refused.getSQLState() + ": " + refused.getMessage());
                }
            }
        }
    }
}
