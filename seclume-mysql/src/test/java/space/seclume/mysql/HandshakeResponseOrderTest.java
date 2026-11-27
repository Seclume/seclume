package space.seclume.mysql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.secret.SecretProvider;

/**
 * The HandshakeResponse41 as the server reads it, field by field in the
 * order of the protocol: capabilities, packet size, character set, filler,
 * user, the authentication answer, the database, the plugin, and the
 * connection attributes - each where the capabilities say, and the values as
 * they were set. A field out of place is read as the next one by the server:
 * a database name taken for a plugin, an attribute for a database.
 */
class HandshakeResponseOrderTest {

    private static final String USER = "seclume_test";
    private static final String PASSWORD = "ein Testpasswort";

    private static int lengthEncoded(byte[] packet, int[] at) {
        int first = packet[at[0]++] & 0xff;
        if (first < 0xfb) {
            return first;
        }
        if (first == 0xfc) {
            int value = (packet[at[0]] & 0xff) | (packet[at[0] + 1] & 0xff) << 8;
            at[0] += 2;
            return value;
        }
        throw new AssertionError("an attribute length of form 0x" + Integer.toHexString(first));
    }

    private static String cString(byte[] packet, int[] at) {
        int end = at[0];
        while (packet[end] != 0) {
            end++;
        }
        String value = new String(packet, at[0], end - at[0], StandardCharsets.UTF_8);
        at[0] = end + 1;
        return value;
    }

    @Test
    void theFieldsArriveInTheProtocolsOrderAsSet() throws Exception {
        try (FakeMySqlServer server = new FakeMySqlServer(USER, PASSWORD)) {
            server.start();
            byte[] bytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
            SecretProvider secret = new space.seclume.secret.CallbackSecretProvider(256, target -> {
                for (int i = 0; i < bytes.length; i++) {
                    target.set(java.lang.foreign.ValueLayout.JAVA_BYTE, i, bytes[i]);
                }
                return bytes.length;
            });
            MySession.Settings settings = new MySession.Settings("127.0.0.1", server.port(),
                    "orders_db", USER, secret)
                    .withTls(space.seclume.internal.jdbc.TlsMode.PREFER).allowingLegacyHash();
            try (MySession session = MySession.open(settings)) {
                assertNotNull(session.serverVersion());
            }
            byte[] login = server.lastLogin();
            assertNotNull(login, "no HandshakeResponse arrived");
            int capabilities = (login[0] & 0xff) | (login[1] & 0xff) << 8
                    | (login[2] & 0xff) << 16 | (login[3] & 0xff) << 24;
            assertTrue((capabilities & MyCapabilities.PROTOCOL_41) != 0, "protocol 4.1");
            assertTrue((capabilities & MyCapabilities.CONNECT_WITH_DB) != 0,
                    "a database was set, and the capabilities do not say one follows");
            int[] at = {4 + 4 + 1 + 23};
            assertEquals(USER, cString(login, at), "the user first");
            int answer = login[at[0]++] & 0xff;
            assertEquals(20, answer, "a native hash is 20 bytes");
            at[0] += answer;
            assertEquals("orders_db", cString(login, at), "the database after the answer");
            assertEquals("mysql_native_password", cString(login, at), "then the plugin");
            if ((capabilities & MyCapabilities.CONNECT_ATTRS) != 0) {
                int total = lengthEncoded(login, at);
                int end = at[0] + total;
                assertEquals(login.length, end, "the attributes end the packet");
                Map<String, String> attributes = new LinkedHashMap<>();
                while (at[0] < end) {
                    String name = new String(login, at[0] + 1, login[at[0]] & 0xff,
                            StandardCharsets.UTF_8);
                    at[0] += 1 + (login[at[0]] & 0xff);
                    int length = login[at[0]] & 0xff;
                    String value = new String(login, at[0] + 1, length, StandardCharsets.UTF_8);
                    at[0] += 1 + length;
                    assertTrue(attributes.put(name, value) == null, name + " twice");
                }
                assertEquals("seclume", attributes.get("_client_name"), attributes.toString());
            } else {
                assertEquals(login.length, at[0], "nothing after the plugin");
            }
        }
    }
}
