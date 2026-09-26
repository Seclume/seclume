package space.seclume.oracle.net;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import space.seclume.internal.WireBuffer;

/**
 * The first login stage - the client names the user, the server answers with
 * the material for the password.
 *
 * <p>Nothing derived from the password goes over the wire here yet. The client
 * only says who it wants to be; the server answers with a session key, a salt
 * and the iteration counts, and above all with the <b>verifier type</b>, which
 * decides which of the two schemes applies - the 11g one or the 12c one.
 *
 * <p>The message layout:
 *
 * <pre>
 *   1   message type = 3 (FUNCTION)
 *   1   function = 118
 *   n   1, length of the user name, and the login mode, as numbers
 *   1   a single byte 1 - the one field here that is not length-prefixed
 *   n   number of pairs and a 1, as numbers
 *   n   the user name, length-prefixed
 *   n   the pairs
 * </pre>
 *
 * <p>The five numbers before the name look like padding and are not: Oracle
 * writes a pointer as a 1 wherever a field is present at all. Leave one out
 * and everything after it shifts - and the server hangs up without an error
 * packet, which is Oracle's answer to nearly every mistake.
 */
public final class TtcAuth {

    /** More pairs than this in a login answer would not be one. */
    private static final int MAX_PARAMETERS = 32;
    /** Longer than this is not a parameter name. */
    private static final int MAX_NAME_LENGTH = 64;

    /** The login mode of the first stage. */
    private static final int AUTH_MODE_PHASE_ONE = 1;

    /** What the server answers with - none of it is a secret in itself. */
    public record Challenge(String sessionKey, String salt, String saltForComboKey,
                            int verifierType, int generationCount, int derivationCount) {

        /** Whether the server expects the 12c scheme. */
        public boolean is12c() {
            return verifierType == 0x4815;
        }
    }

    private TtcAuth() {
    }

    /**
     * Sends the first login stage and reads the answer.
     *
     * @param user the database user; not a secret, and it goes over as text
     */
    public static Challenge phaseOne(NsChannel channel, String user) throws IOException {
        WireBuffer out = channel.beginData();
        putPhaseOne(out, user);
        channel.sendData();
        return readChallenge(channel);
    }

    /**
     * Writes the first login stage into a buffer that is already open.
     *
     * <p>Separate from {@link #phaseOne} because {@code FAST_AUTH} puts the
     * same bytes into a larger packet.
     */
    static void putPhaseOne(WireBuffer out, String user) {
        List<TtcParameters.Pair> pairs = List.of(
                new TtcParameters.Pair("AUTH_TERMINAL", "unknown", 0),
                new TtcParameters.Pair("AUTH_PROGRAM_NM", "seclume", 0),
                new TtcParameters.Pair("AUTH_MACHINE", "seclume", 0),
                new TtcParameters.Pair("AUTH_PID", "1", 0),
                new TtcParameters.Pair("AUTH_SID", "seclume", 0));

        out.putByte((byte) TtcMessage.TYPE_FUNCTION);
        out.putByte((byte) TtcMessage.FUNC_AUTH_PHASE_ONE);
        TtcParameters.putNumber(out, 1);
        TtcParameters.putNumber(out, user.length());
        TtcParameters.putNumber(out, AUTH_MODE_PHASE_ONE);
        // A single byte, not a number - the one field in this header that is
        // not length-prefixed. Leaving it out shifts everything after it, and
        // the server answers with a MARKER instead of a reason.
        out.putByte((byte) 1);
        TtcParameters.putNumber(out, pairs.size());
        TtcParameters.putNumber(out, 1);
        TtcParameters.putText(out, user);
        for (TtcParameters.Pair pair : pairs) {
            TtcParameters.putPair(out, pair.name(), pair.value(), pair.flags());
        }
    }

    /**
     * Reads the answer and picks the login parameters out of it.
     *
     * <p>The server answers a {@code FAST_AUTH} with everything at once: its
     * protocol version, its own type list, and only then the parameters with
     * the challenge. The first two are of no interest here - but they cannot
     * be skipped by arithmetic either, because their length is not written
     * anywhere and their trailers are not fully understood yet.
     *
     * <p>So the parameter message is found by its signature: the type byte 8,
     * a plausible number of pairs, and a first name that reads like one -
     * upper case and underscores, which every {@code AUTH_...} key is. If that
     * is not found, this fails loudly instead of interpreting bytes it does
     * not recognise.
     *
     * <p>An open point: once the server's capabilities are needed, the two
     * leading messages have to be parsed properly, and then this search
     * disappears.
     */
    static Challenge readChallenge(NsChannel channel) throws IOException {
        int packetType = channel.nextPacket();
        if (packetType != NsPacket.TYPE_DATA) {
            throw new IOException("expected a DATA packet after the login, got "
                    + NsPacket.typeName(packetType));
        }
        WireBuffer in = channel.packet();
        int start = in.position();
        int end = in.limit();
        for (int at = start; at + 1 < end; at++) {
            // at + 1 < end, not at < end: the next byte is looked at below,
            // and a type byte in the very last position of the packet has no
            // message behind it anyway. Without the bound this asks WireBuffer
            // for a byte past the limit, and since the bounds check went in
            // that is a Truncated - a search giving up with an error instead
            // of a result.
            if (in.getByte(at) != TtcMessage.TYPE_PARAMETER) {
                continue;
            }
            if (in.getByte(at + 1) == TtcMessage.TYPE_ERROR) {
                continue;
            }
            in.position(at + 1);
            long count = TtcParameters.number(in);
            if (count < 1 || count > MAX_PARAMETERS || !looksLikeAName(in)) {
                continue;
            }
            in.position(at + 1);
            return readParameters(in, (int) TtcParameters.number(in));
        }
        throw new IOException("the server sent no login parameters - "
                + "the answer was " + (end - start) + " bytes long");
    }

    /** Whether a parameter name follows at the current position. */
    private static boolean looksLikeAName(WireBuffer in) {
        int at = in.position();
        try {
            int length = (int) TtcParameters.number(in);
            if (length < 4 || length > MAX_NAME_LENGTH) {
                return false;
            }
            if ((in.getByte() & 0xff) != length) {
                return false;
            }
            for (int i = 0; i < length; i++) {
                int c = in.getByte() & 0xff;
                if ((c < 'A' || c > 'Z') && c != '_' && (c < '0' || c > '9')) {
                    return false;
                }
            }
            return true;
        } catch (RuntimeException e) {
            // A misread length runs off the end of the buffer - which only
            // says that this was not the parameter message.
            return false;
        } finally {
            in.position(at);
        }
    }

    /** Reads the pairs and picks out what the password derivation needs. */
    private static Challenge readParameters(WireBuffer in, int count) throws IOException {
        List<TtcParameters.Pair> answer = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            answer.add(TtcParameters.readPair(in));
        }
        if (answer.isEmpty()) {
            throw new IOException("the server sent no login parameters");
        }

        String sessionKey = "";
        String salt = "";
        String comboSalt = "";
        int verifierType = 0;
        int generationCount = 0;
        int derivationCount = 0;
        for (TtcParameters.Pair pair : answer) {
            switch (pair.name()) {
                case "AUTH_SESSKEY" -> sessionKey = pair.value();
                case "AUTH_VFR_DATA" -> {
                    salt = pair.value();
                    // The verifier type rides in the flags of this pair, of
                    // all places - and it decides the whole scheme.
                    verifierType = (int) pair.flags();
                }
                case "AUTH_PBKDF2_CSK_SALT" -> comboSalt = pair.value();
                case "AUTH_PBKDF2_VGEN_COUNT" -> generationCount = number(pair.value());
                case "AUTH_PBKDF2_SDER_COUNT" -> derivationCount = number(pair.value());
                default -> {
                    // The database id is only of interest to a pool on the
                    // server side.
                }
            }
        }
        if (sessionKey.isEmpty()) {
            throw new IOException("the server sent no AUTH_SESSKEY");
        }
        return new Challenge(sessionKey, salt, comboSalt, verifierType,
                generationCount, derivationCount);
    }

    private static int number(String text) {
        try {
            return Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
