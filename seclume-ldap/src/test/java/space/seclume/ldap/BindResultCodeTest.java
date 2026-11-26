package space.seclume.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * The bind response the Kerberos path hands on to JNDI wrote the server's
 * result code into one byte: 256 went on as 0, and the application took a
 * refused bind for a successful one. It is written as BER writes an integer
 * now, and every code arrives as the server sent it.
 */
class BindResultCodeTest {

    private static final int BIND_RESPONSE = 0x61;

    @Test
    void everyResultCodeArrivesAsItWasSent() throws Exception {
        byte[] messageId = {0x02, 0x01, 0x07};
        for (int code : new int[] {0, 14, 49, 127, 128, 255, 256, 4096, 65_536}) {
            byte[] encoded = LdapSocket.encodeBindResponse(messageId,
                    new LdapSocket.ParsedResult(code, new byte[0], new byte[0], "", null));
            assertEquals(code, LdapSocket.response(encoded, encoded.length, BIND_RESPONSE)
                    .resultCode(), "result code " + code);
        }
    }
}
