package space.seclume.sqlserver.tds;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * What SQL Server needs to put a session's state back on a new connection -
 * its "idle connection resiliency" (MS-TDS 2.2.6.4, feature SESSIONRECOVERY).
 *
 * <p>The client asks for the feature at login and the server answers with the
 * state the session started in: database, collation, language and a set of
 * numbered values the client does not interpret. From then on every answer
 * that changed something carries a {@code SESSIONSTATE} token with the new
 * values and a sequence number, and a flag saying whether the server could
 * still recover the session at all - a temporary table, a cursor, an
 * {@code EXECUTE AS}, a lock held by the session clears it.
 *
 * <p>When the connection is gone, a new login carries both halves back - what
 * the session started with and what changed since - and the server builds a
 * new session in that state: the same database, language and {@code SET}
 * options. It is a <b>new</b> session: another session id, and no
 * transaction, which is why this is used only on a connection that was idle.
 *
 * <p>The values are the server's description of {@code SET} options and the
 * like - protocol state, not secrets - kept as the server sent them.
 */
public final class RecoveryState {

    /** The feature's number in LOGIN7 and FEATUREEXTACK. */
    static final int FEATURE = 0x01;
    private static final int IDS = 256;

    private final String initialDatabase;
    private final byte[] initialCollation;
    private final String initialLanguage;
    private final byte[][] initial = new byte[IDS][];

    private final byte[][] changed = new byte[IDS][];
    private final long[] changedAt = new long[IDS];
    private String language;
    private byte[] collation;
    private boolean recoverable = true;
    private long recoverableAt = -1;

    private RecoveryState(String database, byte[] collation, String language) {
        this.initialDatabase = database;
        this.initialCollation = collation;
        this.initialLanguage = language;
        java.util.Arrays.fill(changedAt, -1);
    }

    /**
     * The server's acknowledgement at login - the initial values, nothing
     * else - and what the login's ENVCHANGE tokens said about database,
     * collation and language.
     */
    static RecoveryState fromAcknowledgement(byte[] data, String database, byte[] collation,
                                             String language) {
        Reader in = new Reader(data);
        RecoveryState state = new RecoveryState(database == null ? "" : database,
                collation == null ? new byte[0] : collation, language == null ? "" : language);
        while (in.more()) {
            int id = in.u8();
            state.initial[id] = in.bytes(in.stateLength());
        }
        return state;
    }

    /**
     * One {@code SESSIONSTATE} token: newer values win, older ones - a token
     * the server sent before one already applied - are dropped.
     *
     * @param set the token's state values, after sequence number and status
     */
    void apply(long sequence, boolean stillRecoverable, byte[] set) {
        if (sequence >= recoverableAt) {
            recoverable = stillRecoverable;
            recoverableAt = sequence;
        }
        Reader in = new Reader(set);
        while (in.more()) {
            int id = in.u8();
            byte[] value = in.bytes(in.stateLength());
            if (sequence >= changedAt[id]) {
                changed[id] = value;
                changedAt[id] = sequence;
            }
        }
    }

    /** An {@code ENVCHANGE} of the language. */
    void language(String value) {
        language = value;
    }

    /** An {@code ENVCHANGE} of the collation. */
    void collation(byte[] value) {
        collation = value;
    }

    /**
     * A RESETCONNECTION went through: the server is back where the session
     * started, and what changed before is no longer to be restored.
     */
    void reset() {
        java.util.Arrays.fill(changed, null);
        java.util.Arrays.fill(changedAt, -1);
        language = null;
        collation = null;
        recoverable = true;
        recoverableAt = -1;
    }

    /** Whether the server said it could still recover the session. */
    public boolean recoverable() {
        return recoverable;
    }

    /**
     * The feature data of a recovering login: the initial state and the
     * changes since, each with its length in front.
     *
     * @param database the database the session is in now
     */
    byte[] featureData(String database) {
        ByteArrayOutputStream start = new ByteArrayOutputStream(); // seclume-allow: SET options and names the server described, not a secret
        utf16(start, initialDatabase);
        bytes(start, initialCollation);
        utf16(start, initialLanguage);
        values(start, initial);

        ByteArrayOutputStream now = new ByteArrayOutputStream(); // seclume-allow: as above
        utf16(now, database == null || database.equals(initialDatabase) ? "" : database);
        bytes(now, collation == null || java.util.Arrays.equals(collation, initialCollation)
                ? new byte[0] : collation);
        utf16(now, language == null || language.equals(initialLanguage) ? "" : language);
        values(now, changed);

        ByteArrayOutputStream all = new ByteArrayOutputStream(); // seclume-allow: as above
        int32(all, start.size());
        all.writeBytes(start.toByteArray());
        int32(all, now.size());
        all.writeBytes(now.toByteArray());
        return all.toByteArray();
    }

    private static void values(ByteArrayOutputStream out, byte[][] values) {
        for (int id = 0; id < IDS; id++) {
            byte[] value = values[id];
            if (value == null) {
                continue;
            }
            out.write(id);
            if (value.length < 0xff) {
                out.write(value.length);
            } else {
                out.write(0xff);
                int32(out, value.length);
            }
            out.writeBytes(value);
        }
    }

    private static void utf16(ByteArrayOutputStream out, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_16LE); // seclume-allow: a database or language name
        out.write(text.length());
        out.writeBytes(bytes);
    }

    private static void bytes(ByteArrayOutputStream out, byte[] value) {
        out.write(value.length);
        out.writeBytes(value);
    }

    private static void int32(ByteArrayOutputStream out, int value) {
        out.write(value);
        out.write(value >>> 8);
        out.write(value >>> 16);
        out.write(value >>> 24);
    }

    /** Over a byte array, refusing to run past it - the data came off the wire. */
    private static final class Reader {
        private final byte[] data;
        private int at;

        Reader(byte[] data) {
            this.data = data;
        }

        boolean more() {
            return at < data.length;
        }

        int u8() {
            need(1);
            return data[at++] & 0xff;
        }

        /** A BYTE, or 0xFF and a DWORD. */
        int stateLength() {
            int length = u8();
            if (length != 0xff) {
                return length;
            }
            need(4);
            int value = (data[at] & 0xff) | (data[at + 1] & 0xff) << 8
                    | (data[at + 2] & 0xff) << 16 | (data[at + 3] & 0xff) << 24;
            at += 4;
            if (value < 0) {
                throw new IllegalArgumentException("a session state value of " + value
                        + " bytes");
            }
            return value;
        }

        byte[] bytes(int length) {
            need(length);
            byte[] value = java.util.Arrays.copyOfRange(data, at, at + length); // seclume-allow: a SET option's state
            at += length;
            return value;
        }

        String utf16(int chars) {
            need(chars * 2);
            // seclume-allow: a database or language name
            String text = new String(data, at, chars * 2, StandardCharsets.UTF_16LE); // seclume-allow: a name
            at += chars * 2;
            return text;
        }

        private void need(int bytes) {
            if (bytes < 0 || at + bytes > data.length) {
                throw new IllegalArgumentException("the session recovery data ends at "
                        + data.length + ", " + bytes + " more bytes wanted at " + at);
            }
        }
    }
}
