package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.MemorySegment;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * OSON keeps its children as offsets, and the reader followed them as given.
 * A child pointing back at its parent recursed until the stack overflowed;
 * nodes shared by many parents doubled the text with every level, and a value
 * of a few hundred bytes filled the heap. A tree visits each node once.
 */
@Timeout(10)
class OracleJsonTest {

    /** The header of an OSON value with no field names, then the tree. */
    private static byte[] oson(byte[] tree) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {(byte) 0xff, 0x4a, 0x5a, 0x01}); // magic, version 1
        out.writeBytes(new byte[] {0x00, 0x00});                    // flags: a tree, u16 offsets
        out.write(0x00);                                            // no short field names
        out.writeBytes(new byte[] {0x00, 0x00});                    // their segment: empty
        out.writeBytes(new byte[] {(byte) (tree.length >> 8), (byte) tree.length});
        out.writeBytes(new byte[] {0x00, 0x00});                    // tiny nodes
        out.writeBytes(tree);
        return out.toByteArray();
    }

    private static String read(byte[] value) throws SQLException {
        return OracleJson.toText(MemorySegment.ofArray(value), 0, value.length);
    }

    @Test
    void aCycleIsRefused() {
        // An array of one child, at offset 0: itself.
        byte[] value = oson(new byte[] {(byte) 0xc0, 0x01, 0x00, 0x00});
        SQLException refused = assertThrows(SQLException.class, () -> read(value));
        assertEquals("22000", refused.getSQLState());
        assertTrue(refused.getMessage().contains("cycle"), refused.getMessage());
    }

    @Test
    void sharedNodesCannotExplode() {
        // Forty levels, each an array of two children that are both the next
        // level: 2^40 nulls from about 250 bytes.
        int levels = 40;
        ByteArrayOutputStream tree = new ByteArrayOutputStream();
        for (int i = 0; i < levels; i++) {
            int next = (i + 1) * 6;
            tree.writeBytes(new byte[] {(byte) 0xc0, 0x02,
                (byte) (next >> 8), (byte) next, (byte) (next >> 8), (byte) next});
        }
        tree.write(0x30);                                            // null
        byte[] value = oson(tree.toByteArray());
        SQLException refused = assertThrows(SQLException.class, () -> read(value));
        assertEquals("22000", refused.getSQLState());
    }

    @Test
    void aTreeIsReadAsBefore() throws SQLException {
        // Control: an array of two nulls, each its own node.
        byte[] value = oson(new byte[] {(byte) 0xc0, 0x02, 0x00, 0x06, 0x00, 0x07, 0x30, 0x30});
        assertEquals("[null,null]", read(value));
    }
}
