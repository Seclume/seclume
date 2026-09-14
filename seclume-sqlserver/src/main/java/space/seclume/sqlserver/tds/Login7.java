package space.seclume.sqlserver.tds;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.sql.SQLException;

import space.seclume.internal.Utf;
import space.seclume.internal.WireBuffer;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.sqlserver.auth.TdsPassword;

/**
 * The login packet, LOGIN7.
 *
 * <p>The layout is a table: fixed fields first, then a pair of offset and
 * length for every string, and the strings themselves right at the end - all
 * in UTF-16LE. The offsets count from the start of the packet, and the lengths
 * are given in <b>characters</b>, not bytes. This is the spot where every
 * second driver has gone wrong once.
 *
 * <p>The password is the only value that is not simply re-encoded: it goes
 * through {@link TdsPassword}, and the whole path from the
 * {@link SecretProvider} into the send buffer runs in native memory. The send
 * buffer is zeroed afterwards.
 *
 * <p>Follows {@code MS-TDS}, the open specification.
 */
public final class Login7 {

    /** Connection settings. The password is not in here, only its source. */
    public record Settings(String host, String database, String user, SecretProvider secret,
                           String applicationName, String clientHostName) {

        public Settings(String host, String database, String user, SecretProvider secret) {
            this(host, database, user, secret, "seclume", "seclume");
        }
    }

    /** This many string fields are in the table. */
    private static final int FIELD_COUNT = 10;
    /** Fixed fields before the table: length up to and including ClientLCID. */
    private static final int FIXED_SIZE = 36;
    /** ClientID (6), SSPI pair (4), AtchDBFile pair (4), ChangePassword pair (4), cbSSPI (4). */
    private static final int TRAILER_SIZE = 6 + 4 + 4 + 4 + 4;

    private Login7() {
    }

    /**
     * Writes LOGIN7 and sends it.
     *
     * @throws SQLException if the secret source does not deliver
     */
    public static void send(TdsChannel channel, Settings settings)
            throws IOException, SQLException {
        WireBuffer out = channel.begin();
        int start = out.position();

        // The fixed fields. The total length is filled in later.
        out.putIntLe(0);                              // length, comes last
        out.putIntLe(Tds.VERSION_7_4);
        out.putIntLe(channel.packetSize());
        out.putIntLe(0x00000001);                     // client program version
        out.putIntLe((int) ProcessHandle.current().pid());
        out.putIntLe(0);                              // connection id
        out.putByte((byte) 0xe0);                     // OptionFlags1: little-endian, ASCII
        out.putByte((byte) 0x03);                     // OptionFlags2: ODBC behaviour
        out.putByte((byte) 0x00);                     // TypeFlags
        out.putByte((byte) 0x00);                     // OptionFlags3
        out.putIntLe(0);                              // time zone
        out.putIntLe(0);                              // LCID

        // The table of offsets and lengths - as placeholders for now.
        int tableAt = out.position();
        out.putZeroes(FIELD_COUNT * 4 + TRAILER_SIZE);

        // The values, in exactly the order the table prescribes.
        int[] offsets = new int[FIELD_COUNT];
        int[] lengths = new int[FIELD_COUNT];

        offsets[0] = out.position() - start;
        lengths[0] = putUtf16(out, settings.clientHostName());
        offsets[1] = out.position() - start;
        lengths[1] = putUtf16(out, settings.user());

        // The password: straight from its source into the buffer, obfuscated.
        offsets[2] = out.position() - start;
        lengths[2] = putPassword(out, settings.secret());

        offsets[3] = out.position() - start;
        lengths[3] = putUtf16(out, settings.applicationName());
        offsets[4] = out.position() - start;
        lengths[4] = putUtf16(out, settings.host());
        offsets[5] = out.position() - start;
        lengths[5] = 0;                               // extension: none
        offsets[6] = out.position() - start;
        lengths[6] = putUtf16(out, "seclume");       // client library name
        offsets[7] = out.position() - start;
        lengths[7] = 0;                               // language: the server default
        offsets[8] = out.position() - start;
        lengths[8] = putUtf16(out, settings.database());
        offsets[9] = out.position() - start;
        lengths[9] = 0;                               // SSPI: not here

        // Fill in the table. The lengths count **characters**, not bytes -
        // including the password. This is where it easily goes wrong: the
        // offsets are byte offsets, the lengths right next to them are not.
        int at = tableAt;
        for (int i = 0; i < FIELD_COUNT; i++) {
            putShortAt(out, at, offsets[i]);
            putShortAt(out, at + 2, lengths[i] / 2);
            at += 4;
        }
        // ClientID: six bytes, zero here - a MAC address would be an
        // identifying mark the server does not need.
        at += 6;
        putShortAt(out, at, 0);                       // SSPI offset
        putShortAt(out, at + 2, 0);                   // SSPI length
        at += 4;
        putShortAt(out, at, 0);                       // AtchDBFile
        putShortAt(out, at + 2, 0);
        at += 4;
        putShortAt(out, at, 0);                       // ChangePassword
        putShortAt(out, at + 2, 0);

        int total = out.position() - start;
        out.putUnsignedLeAt(start, total, 4);
        channel.send(Tds.TYPE_LOGIN7);
    }

    /** One string in UTF-16LE; returns the length in bytes. */
    private static int putUtf16(WireBuffer out, String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        byte[] utf8 = text.getBytes(java.nio.charset.StandardCharsets.UTF_8); // seclume-allow: host and user names, protocol text and never a secret
        int at = out.position();
        out.putZeroes(Utf.utf16LeUpperBound(utf8.length));
        int written = Utf.utf8ToUtf16Le(MemorySegment.ofArray(utf8), 0, utf8.length,
                out.segment(), at);
        out.position(at + written);
        return written;
    }

    /**
     * The password - from its source, obfuscated, without a detour via the heap.
     *
     * @return the length in bytes
     */
    private static int putPassword(WireBuffer out, SecretProvider secret) throws SQLException {
        try (SecretScope password = SecretScope.fromProvider(secret)) {
            int at = out.position();
            int room = Utf.utf16LeUpperBound(password.length());
            out.putZeroes(room);
            int written = TdsPassword.obfuscate(password.secret(), 0, password.length(),
                    out.segment(), at);
            out.position(at + written);
            return written;
        }
    }

    private static void putShortAt(WireBuffer out, int at, int value) {
        out.putByteAt(at, (byte) value);
        out.putByteAt(at + 1, (byte) (value >>> 8));
    }

    /** The size of the fixed fields - for tests and for explanation. */
    public static int fixedSize() {
        return FIXED_SIZE;
    }
}
