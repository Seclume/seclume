package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import space.seclume.crypto.HybridMlKem;

/**
 * The ClientHello with the post-quantum hybrid beside P-256: both groups in
 * supported_groups, both shares in key_share, in that order - checked on the
 * bytes, so that it holds on a platform without OpenSSL 3.5 as well.
 */
class ClientHelloGroupsTest {

    @Test
    void twoGroupsTwoSharesInOrder() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment random = arena.allocate(32);
            MemorySegment session = arena.allocate(32);
            MemorySegment hybrid = arena.allocate(HybridMlKem.CLIENT_SHARE);
            MemorySegment p256 = arena.allocate(65);
            p256.set(ValueLayout.JAVA_BYTE, 0, (byte) 4);
            MemorySegment hello = arena.allocate(2048);
            int length = ClientHello.write(hello, 0, random, session,
                    new int[] {ClientHello.X25519MLKEM768, ClientHello.SECP256R1},
                    new MemorySegment[] {hybrid, p256}, "db.example", null);
            assertEquals(length - Handshake.HEADER, Handshake.length(hello, 0));

            int[] extensionsLength = new int[1];
            long at = Handshake.clientHelloExtensions(hello, Handshake.HEADER, extensionsLength);
            List<Integer> groups = new ArrayList<>();
            List<String> shares = new ArrayList<>();
            Handshake.extensions(hello, at, extensionsLength[0], (type, where, size) -> {
                if (type == Handshake.EXTENSION_SUPPORTED_GROUPS) {
                    for (int i = 0; i < u16(hello, where) / 2; i++) {
                        groups.add(u16(hello, where + 2 + 2L * i));
                    }
                } else if (type == Handshake.EXTENSION_KEY_SHARE) {
                    long p = where + 2;
                    long end = where + 2 + u16(hello, where);
                    while (p < end) {
                        int group = u16(hello, p);
                        int shareLength = u16(hello, p + 2);
                        shares.add(Integer.toHexString(group) + ":" + shareLength);
                        p += 4 + shareLength;
                    }
                    assertEquals(end, p, "the key_share list does not add up");
                }
            });
            assertEquals(List.of(0x11EC, 0x0017), groups);
            assertEquals(List.of("11ec:1216", "17:65"), shares);
        }
    }

    private static int u16(MemorySegment data, long at) {
        return ((data.get(ValueLayout.JAVA_BYTE, at) & 0xff) << 8)
                | (data.get(ValueLayout.JAVA_BYTE, at + 1) & 0xff);
    }
}
