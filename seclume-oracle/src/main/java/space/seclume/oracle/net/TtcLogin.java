package space.seclume.oracle.net;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.sql.SQLException;

import space.seclume.internal.Entropy;
import space.seclume.internal.WireBuffer;
import space.seclume.oracle.auth.O5Login12c;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The second login stage - the one that touches the password.
 *
 * <p>Everything before this was preparation; here the password is used, and
 * this is the piece the whole library exists for. It never becomes a
 * {@code String}, never a {@code char[]}, never a heap {@code byte[]}: it comes
 * out of its source into native memory, is run through PBKDF2, AES and hex
 * there, and that memory is wiped afterwards.
 *
 * <p>The derivation, for a 32-byte session key:
 *
 * <ol>
 *   <li>{@code passwordKey = PBKDF2-SHA512(password, AUTH_VFR_DATA ‖
 *       "AUTH_PBKDF2_SPEEDY_KEY", AUTH_PBKDF2_VGEN_COUNT, 64)}</li>
 *   <li>{@code passwordHash = SHA512(passwordKey ‖ AUTH_VFR_DATA)[0..32]}</li>
 *   <li>the server's {@code AUTH_SESSKEY} decrypted with it gives its half;
 *       the client rolls its own 32 bytes and sends them encrypted the same
 *       way</li>
 *   <li>{@code comboKey = PBKDF2-SHA512(hex(clientHalf ‖ serverHalf),
 *       AUTH_PBKDF2_CSK_SALT, AUTH_PBKDF2_SDER_COUNT, 32)} - the halves as
 *       <b>upper-case hex text</b>, which is the detail that no description of
 *       this protocol mentions</li>
 *   <li>{@code AUTH_PASSWORD = hex(AES-CBC(comboKey, 16 random bytes ‖
 *       password))}</li>
 *   <li>{@code AUTH_PBKDF2_SPEEDY_KEY = hex(AES-CBC(comboKey, 16 random bytes ‖
 *       passwordKey))} - with this the server can check the password next time
 *       without the 4096 rounds</li>
 * </ol>
 *
 * <p>Established by measurement, not by guessing: see
 * {@code PROVENANCE.md}.
 */
public final class TtcLogin {

    /** The login mode of the second stage. */
    private static final int AUTH_MODE_PHASE_TWO = 0x0101;
    /** The salt that goes in front of an encrypted value. */
    private static final int SALT_LENGTH = 16;
    /** How many pairs the second stage sends. */
    private static final int PAIR_COUNT = 8;
    /** How many bytes of the speedy key travel. */
    private static final int SPEEDY_KEY_BYTES = 80;
    /** Oracle's identifier for AL32UTF8. */
    private static final String CHARSET = "873";
    /** How the session shows up in the server's own view of its clients. */
    private static final String DRIVER_NAME = "seclume thin : 0.1";
    /** The version as a packed number, the way Oracle counts. */
    private static final String DRIVER_VERSION = "67117056";
    /** Sessions start in UTC; anything else is a surprise waiting to happen. */
    private static final String ALTER_TIME_ZONE =
            "ALTER SESSION SET TIME_ZONE='+00:00'\0";

    private TtcLogin() {
    }

    /**
     * Sends the second stage and reads the answer.
     *
     * <p>The password lives from the first line of this method to the last,
     * and only in native memory. What the caller keeps is a
     * {@link SecretProvider} - the source, not the secret.
     */
    public static void phaseTwo(NsChannel channel, String user, SecretProvider secret,
                                TtcAuth.Challenge challenge, String connectString)
            throws IOException, SQLException {
        if (!challenge.is12c()) {
            throw new IOException("this server wants the 11g verifier (0x"
                    + Integer.toHexString(challenge.verifierType())
                    + "), which seclume does not send");
        }
        int keyLength = challenge.sessionKey().length() / 2;
        if (keyLength != O5Login12c.SESSION_KEY_LENGTH_32) {
            throw new IOException("the server sent a session key of " + keyLength
                    + " bytes; seclume has only established the 32-byte derivation");
        }

        try (Arena arena = Arena.ofConfined();
             SecretScope password = SecretScope.fromProvider(secret)) {
            MemorySegment verifier = hexToBytes(arena, challenge.salt());
            MemorySegment cskSalt = hexToBytes(arena, challenge.saltForComboKey());
            MemorySegment serverEncrypted = hexToBytes(arena, challenge.sessionKey());

            MemorySegment passwordKey = arena.allocate(O5Login12c.DERIVED_LENGTH);
            MemorySegment passwordHash = arena.allocate(O5Login12c.PASSWORD_HASH_LENGTH);
            MemorySegment serverHalf = arena.allocate(keyLength);
            MemorySegment clientHalf = arena.allocate(keyLength);
            MemorySegment clientEncrypted = arena.allocate(keyLength);
            MemorySegment comboKey = arena.allocate(O5Login12c.COMBO_KEY_LENGTH);
            MemorySegment salt = arena.allocate(SALT_LENGTH);
            try {
                O5Login12c.passwordKey(password.secret(), 0, password.length(),
                        verifier, 0, (int) verifier.byteSize(),
                        challenge.generationCount(), passwordKey, 0);
                O5Login12c.passwordHashFrom(passwordKey, 0, verifier, 0,
                        (int) verifier.byteSize(), passwordHash, 0);

                O5Login12c.decryptSessionKey(passwordHash, 0, serverEncrypted, 0,
                        keyLength, serverHalf, 0);
                Entropy.fill(clientHalf);
                O5Login12c.encryptSessionKey(passwordHash, 0, clientHalf, 0,
                        keyLength, clientEncrypted, 0);

                O5Login12c.comboKey32(clientHalf, 0, serverHalf, 0,
                        cskSalt, 0, (int) cskSalt.byteSize(),
                        challenge.derivationCount(), comboKey, 0);

                WireBuffer out = channel.beginData();
                putHeader(out, user);
                putHexPair(out, "AUTH_SESSKEY", clientEncrypted, keyLength, 1);

                Entropy.fill(salt);
                putEncryptedPair(out, "AUTH_PBKDF2_SPEEDY_KEY", comboKey, salt,
                        passwordKey, O5Login12c.DERIVED_LENGTH, SPEEDY_KEY_BYTES * 2);

                Entropy.fill(salt);
                putEncryptedPair(out, "AUTH_PASSWORD", comboKey, salt,
                        password.secret(), password.length(), Integer.MAX_VALUE);

                TtcParameters.putPair(out, "SESSION_CLIENT_CHARSET", CHARSET, 0);
                TtcParameters.putPair(out, "SESSION_CLIENT_DRIVER_NAME", DRIVER_NAME, 0);
                TtcParameters.putPair(out, "SESSION_CLIENT_VERSION", DRIVER_VERSION, 0);
                // The time zone has to be set here, not later: a session that
                // starts in the server's zone and is moved afterwards has
                // already written timestamps in the wrong one.
                TtcParameters.putPair(out, "AUTH_ALTER_SESSION", ALTER_TIME_ZONE, 1);
                TtcParameters.putPair(out, "AUTH_CONNECT_STRING", connectString, 0);
                channel.sendData();
            } finally {
                // Everything derived from the password goes too - the hash is
                // as good as the password for this server.
                passwordKey.fill((byte) 0);
                passwordHash.fill((byte) 0);
                serverHalf.fill((byte) 0);
                clientHalf.fill((byte) 0);
                comboKey.fill((byte) 0);
                salt.fill((byte) 0);
            }
        }
        readAnswer(channel);
    }

    /** The header of the second stage - the pairs follow the user name. */
    private static void putHeader(WireBuffer out, String user) {
        out.putByte((byte) TtcMessage.TYPE_FUNCTION);
        out.putByte((byte) TtcMessage.FUNC_AUTH_PHASE_TWO);
        // Two bytes, not one: the reference client writes this first field
        // with a fixed width, and a minimal encoding shifts everything after
        // it. Found by comparing the bytes, not by reading a description.
        TtcParameters.putNumberWide(out, 1, 2);
        TtcParameters.putNumber(out, user.length());
        TtcParameters.putNumber(out, AUTH_MODE_PHASE_TWO);
        out.putByte((byte) 1);                     // the one field that is not a number
        TtcParameters.putNumber(out, PAIR_COUNT);
        TtcParameters.putNumber(out, 1);
        TtcParameters.putText(out, user);
    }

    /**
     * A pair whose value is upper-case hex of native bytes.
     *
     * <p>The hex is written straight into the send buffer - there is no
     * {@code String} in between, because for the session key there must not
     * be one.
     */
    private static void putHexPair(WireBuffer out, String name, MemorySegment value,
                                   int length, long flags) {
        TtcParameters.putNumber(out, name.length());
        TtcParameters.putText(out, name);
        TtcParameters.putNumber(out, length * 2L);
        out.putByte((byte) (length * 2));
        for (int i = 0; i < length; i++) {
            int b = value.get(java.lang.foreign.ValueLayout.JAVA_BYTE, i) & 0xff;
            out.putByte(hexDigit(b >>> 4));
            out.putByte(hexDigit(b & 0x0f));
        }
        TtcParameters.putNumber(out, flags);
    }

    /**
     * A pair whose value is salt and content, AES-encrypted and hex-encoded.
     *
     * <p>The encryption happens in a scratch buffer that is wiped afterwards,
     * and only the hex text reaches the send buffer - which then goes over the
     * wire and is overwritten by the next message.
     */
    private static void putEncryptedPair(WireBuffer out, String name, MemorySegment comboKey,
                                         MemorySegment salt, MemorySegment content,
                                         int contentLength, int maxHexLength) {
        int room = (SALT_LENGTH + contentLength + 16) * 2;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment hex = arena.allocate(room);
            try {
                int written = O5Login12c.encryptedPassword(comboKey, 0, content, 0,
                        contentLength, salt, 0, hex, 0);
                int length = Math.min(written, maxHexLength);
                TtcParameters.putNumber(out, name.length());
                TtcParameters.putText(out, name);
                TtcParameters.putNumber(out, length);
                out.putByte((byte) length);
                out.putBytes(hex, 0, length);
                TtcParameters.putNumber(out, 0);
            } finally {
                hex.fill((byte) 0);
            }
        }
    }

    private static byte hexDigit(int value) {
        return (byte) (value < 10 ? '0' + value : 'A' + value - 10);
    }

    /** Hex text from the server into native bytes. */
    private static MemorySegment hexToBytes(Arena arena, String hex) {
        MemorySegment out = arena.allocate(hex.length() / 2);
        for (int i = 0; i < hex.length() / 2; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            out.set(java.lang.foreign.ValueLayout.JAVA_BYTE, i, (byte) ((high << 4) | low));
        }
        return out;
    }

    /**
     * Reads the answer to the second stage.
     *
     * <p>A successful login is answered with parameters about the session; a
     * failed one with an error message. Anything else means the message was
     * malformed - and then it is better to say so than to carry on with a
     * session that may not exist.
     */
    private static void readAnswer(NsChannel channel) throws IOException, SQLException {
        int packetType = channel.nextPacket();
        if (packetType != NsPacket.TYPE_DATA) {
            throw new IOException("expected a DATA packet after the login, got "
                    + NsPacket.typeName(packetType));
        }
        WireBuffer in = channel.packet();
        int end = in.limit();
        for (int at = in.position(); at < end; at++) {
            int type = in.getByte(at) & 0xff;
            if (type == TtcMessage.TYPE_ERROR) {
                throw new SQLException("the server refused the login", "28000");
            }
            if (type == TtcMessage.TYPE_PARAMETER) {
                return;
            }
        }
        throw new IOException("the server neither confirmed nor refused the login");
    }
}
