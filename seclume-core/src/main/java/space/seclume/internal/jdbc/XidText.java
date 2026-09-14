package space.seclume.internal.jdbc;

import javax.transaction.xa.Xid;

/**
 * A transaction id as text, and back.
 *
 * <p>Two-phase commit needs a name the server can keep between the
 * {@code prepare} and the {@code commit} - across a crash of the application,
 * because that is the whole point. PostgreSQL takes that name as a string in
 * {@code PREPARE TRANSACTION}, MySQL as one in {@code XA START}. JTA hands out
 * an {@link Xid} instead: a format id and two byte arrays.
 *
 * <p>So it is written as {@code formatId:gtrid:bqual}, the two arrays in
 * hexadecimal. Hexadecimal and not base64 for one reason: every server accepts
 * it inside a quoted string without escaping, and it reads back byte for byte.
 * The name has to survive a restart of the application, so it must not depend
 * on anything but the id itself.
 *
 * <p>Any transaction manager's id round-trips; one that this driver did not
 * write is recognised as such and reported as unknown rather than guessed at.
 */
public final class XidText {

    /** The longest name the servers accept - PostgreSQL stops at 200. */
    public static final int MAX_LENGTH = 200;

    private XidText() {
    }

    /** The id as the server will keep it. */
    public static String of(Xid xid) {
        StringBuilder text = new StringBuilder(64); // seclume-allow: a transaction name, not a secret
        text.append(xid.getFormatId()).append(':');
        appendHex(text, xid.getGlobalTransactionId());
        text.append(':');
        appendHex(text, xid.getBranchQualifier());
        if (text.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("this transaction id is too long for the server: "
                    + text.length() + " characters, at most " + MAX_LENGTH
                    + " - shorten the global transaction id");
        }
        return text.toString();
    }

    /** Reads one back; {@code null} if it was not written by this driver. */
    public static Xid parse(String text) {
        int first = text.indexOf(':');
        int second = text.indexOf(':', first + 1);
        if (first < 0 || second < 0) {
            return null;
        }
        try {
            int formatId = Integer.parseInt(text.substring(0, first));
            byte[] global = fromHex(text.substring(first + 1, second)); // seclume-allow: a transaction id, not a secret
            byte[] branch = fromHex(text.substring(second + 1)); // seclume-allow: a transaction id, not a secret
            if (global == null || branch == null) {
                return null;
            }
            return new Recovered(formatId, global, branch);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static void appendHex(StringBuilder text, byte[] bytes) {
        if (bytes == null) {
            return;
        }
        for (byte value : bytes) {
            text.append(Character.forDigit((value >> 4) & 0xf, 16));
            text.append(Character.forDigit(value & 0xf, 16));
        }
    }

    private static byte[] fromHex(String text) {
        if (text.length() % 2 != 0) {
            return null;
        }
        byte[] bytes = new byte[text.length() / 2]; // seclume-allow: a transaction id, not a secret
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(text.charAt(i * 2), 16);
            int low = Character.digit(text.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                return null;
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return bytes;
    }

    /** What {@code recover} hands back to the transaction manager. */
    public record Recovered(int formatId, byte[] global, byte[] branch) implements Xid {

        @Override
        public int getFormatId() {
            return formatId;
        }

        @Override
        public byte[] getGlobalTransactionId() {
            return global;
        }

        @Override
        public byte[] getBranchQualifier() {
            return branch;
        }

        @Override
        public String toString() {
            return XidText.of(this);
        }
    }
}
