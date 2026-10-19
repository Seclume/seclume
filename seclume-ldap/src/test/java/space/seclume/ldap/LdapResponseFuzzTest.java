package space.seclume.ldap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * What an LDAP server answers to StartTLS and to a SASL bind is read by
 * seclume itself, before TLS and Kerberos are settled - from a server that
 * may be anybody's. Whatever bytes arrive, the framing and the parser answer
 * or throw an {@link IOException}; never another exception, never a read past
 * the message.
 */
class LdapResponseFuzzTest {

    private static final int BIND_RESPONSE = 0x61;
    private static final int EXTENDED_RESPONSE = 0x78;
    private static final int ROUNDS = Integer.getInteger("seclume.ldap.fuzz.rounds", 50_000);

    /** A BindResponse in progress: result 14, a server token for the next GSSAPI step. */
    private static final byte[] BIND = hex("301d020102" + "6118" + "0a010e" + "0400" + "0400"
            + "870f" + "600102030405060708090a0b0c0d0e");                 // creds, 15 bytes
    /** StartTLS accepted: result 0, the OID in responseName. */
    private static final byte[] START_TLS = hex("3024020101781f0a0100040004008a16"
            + "312e332e362e312e342e312e313436362e3230303337");

    private static byte[] hex(String text) {
        return java.util.HexFormat.of().parseHex(text);
    }

    /** Framing, then the response, as the socket does them; only IOException may come out. */
    private static LdapSocket.ParsedResult read(byte[] message, int tag) {
        try {
            int length = LdapSocket.messageLength(message, message.length, 1 << 20);
            if (length < 0 || length > message.length) {
                return null;                     // the socket would read on
            }
            return LdapSocket.response(message, length, tag);
        } catch (IOException refused) {
            return null;
        } catch (RuntimeException | StackOverflowError | OutOfMemoryError other) {
            fail("not an IOException: " + other, other);
            return null;
        }
    }

    @Test
    void realResponsesAreRead() {
        LdapSocket.ParsedResult bind = read(BIND, BIND_RESPONSE);
        assertEquals(14, bind.resultCode(), "SASL bind in progress");
        assertArrayEquals(Arrays.copyOfRange(BIND, BIND.length - 15, BIND.length),
                bind.serverSaslCreds());
        LdapSocket.ParsedResult startTls = read(START_TLS, EXTENDED_RESPONSE);
        assertEquals(0, startTls.resultCode());
        assertTrue(read(START_TLS, BIND_RESPONSE) == null, "an ExtendedResponse is no BindResponse");
    }

    /** The cases a hostile server would try first, each refused with an IOException. */
    @Test
    void lengthsThatLieAreRefused() {
        byte[] huge = BIND.clone();
        huge[1] = (byte) 0x84;                          // four length bytes follow: up to 4 GiB
        huge = concat(Arrays.copyOf(huge, 2), hex("ffffffff"), Arrays.copyOfRange(BIND, 2,
                BIND.length));
        assertTrue(read(huge, BIND_RESPONSE) == null);
        byte[] inner = BIND.clone();
        inner[15] = 0x7f;                                // the creds claim more than there is
        assertTrue(read(inner, BIND_RESPONSE) == null);
        byte[] rc = BIND.clone();
        rc[8] = 0x00;                                    // a result code of no bytes
        assertTrue(read(rc, BIND_RESPONSE) == null);
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] all = new byte[length];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, all, at, part.length);
            at += part.length;
        }
        return all;
    }

    @Test
    void mutatedResponsesAreReadOrRefused() {
        List<byte[]> seeds = List.of(BIND, START_TLS);
        long seed = Long.getLong("seclume.ldap.fuzz.seed", 0x5EC_1DA9);
        Random random = new Random(seed);
        for (int round = 0; round < ROUNDS; round++) {
            byte[] message = seeds.get(round % 2).clone();
            for (int e = 1 + random.nextInt(4); e > 0 && message.length > 0; e--) {
                int at = random.nextInt(message.length);
                switch (random.nextInt(5)) {
                    case 0 -> message[at] = (byte) random.nextInt(256);
                    case 1 -> message[at] = (byte) (0x80 | random.nextInt(6)); // long lengths
                    case 2 -> message[at] = (byte) random.nextInt(0x30);       // short lengths
                    case 3 -> message = Arrays.copyOf(message, at);
                    default -> message = concat(message, new byte[random.nextInt(8)]);
                }
            }
            byte[] copy = message.clone();
            try {
                read(message, round % 2 == 0 ? BIND_RESPONSE : EXTENDED_RESPONSE);
            } catch (AssertionError broken) {
                throw new AssertionError("seed " + seed + " round " + round + ": "
                        + broken.getMessage(), broken);
            }
            assertArrayEquals(copy, message, "the parser changed its input");
        }
    }
}
