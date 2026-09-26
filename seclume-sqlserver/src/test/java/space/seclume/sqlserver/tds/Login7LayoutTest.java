package space.seclume.sqlserver.tds;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.Test;

/**
 * LOGIN7 byte for byte where MS-TDS puts things (2.2.6.4): nine offset/length
 * pairs after the 36 fixed bytes, then ClientID at 72, the SSPI pair at 78,
 * cbSSPILong at 90. Until 26.09.2026 there were ten pairs and everything from
 * ClientID on sat four bytes late - unnoticed while all of it was zero, and
 * wrong for the first login that carries an SSPI token.
 */
class Login7LayoutTest {

    @Test
    void anIntegratedLoginCarriesItsTokenWhereTheSpecSays() throws Exception {
        byte[] token = {0x60, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        byte[] login = capture(token);
        assertEquals(0x80, login[25] & 0x80, "fIntSecurity in OptionFlags2");
        int userLength = u16(login, 36 + 4 + 2);
        int passwordLength = u16(login, 36 + 8 + 2);
        assertEquals(0, userLength, "no user name with an integrated login");
        assertEquals(0, passwordLength, "no password with an integrated login");
        int sspiAt = u16(login, 78);
        int sspiLength = u16(login, 80);
        assertEquals(token.length, sspiLength);
        byte[] carried = new byte[sspiLength];
        System.arraycopy(login, sspiAt, carried, 0, sspiLength);
        assertArrayEquals(token, carried);
        assertEquals(0, u32(login, 90), "cbSSPILong only for a token of 64 KiB or more");
        assertEquals(0, u16(login, 72) | u16(login, 74) | u16(login, 76), "ClientID is zero");
    }

    @Test
    void aPasswordLoginHasNoSspiAndTheFirstFieldRightAfterTheTable() throws Exception {
        byte[] login = capture(null);
        assertEquals(0, login[25] & 0x80, "no fIntSecurity");
        assertEquals(0, u16(login, 78), "no SSPI offset");
        assertEquals(0, u16(login, 80), "no SSPI length");
        // The table ends at 36 + 9*4 + 22 = 94: the host name starts there.
        assertEquals(94, u16(login, 36));
    }

    /** LOGIN7 as the server would receive it, without the 8-byte TDS header. */
    private static byte[] capture(byte[] sspi) throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<byte[]> received = CompletableFuture.supplyAsync(() -> {
                try (Socket s = server.accept(); InputStream in = s.getInputStream()) {
                    byte[] header = in.readNBytes(8);
                    int length = ((header[2] & 0xff) << 8) | (header[3] & 0xff);
                    return in.readNBytes(length - 8);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            try (TdsChannel channel = TdsChannel.connect("127.0.0.1", server.getLocalPort(),
                    5000)) {
                Login7.send(channel, new Login7.Settings("db.example", "master", "alice",
                        new StaticSecret()), null, sspi);
            }
            return received.get();
        }
    }

    private static int u16(byte[] b, int at) {
        return (b[at] & 0xff) | (b[at + 1] & 0xff) << 8;
    }

    private static int u32(byte[] b, int at) {
        return u16(b, at) | u16(b, at + 2) << 16;
    }

    /** A password for the layout only - it goes to a local socket and nowhere else. */
    private static final class StaticSecret implements space.seclume.secret.SecretProvider {
        @Override
        public int writeSecret(java.lang.foreign.MemorySegment target) {
            byte[] value = {'p', 'w'};
            java.lang.foreign.MemorySegment.copy(value, 0, target,
                    java.lang.foreign.ValueLayout.JAVA_BYTE, 0, value.length);
            return value.length;
        }

        @Override
        public int maxSecretLength() {
            return 16;
        }
    }
}
