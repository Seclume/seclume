package space.seclume.nats;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * The password or token goes into the value of {@code "pass"} or
 * {@code "auth_token"} of the client's CONNECT line and nowhere else. The
 * placeholder is on the client's heap and is not a secret; given as the
 * connection's name - which the NATS server logs and shows on its monitoring
 * port - it had the real password written there in its place.
 */
class ConnectLineTest {

    private static final String P = "seclume-nats-logs-in-itself";

    private static byte[] line(String json) {
        return ("CONNECT " + json + "\r\n").getBytes(StandardCharsets.UTF_8);
    }

    private static int slot(String json, NatsSettings.AuthMode mode) {
        return ConnectLine.credentialSlot(line(json), mode, P);
    }

    private static int at(String json, String before) {
        return ("CONNECT " + json).indexOf(before) + before.length();
    }

    @Test
    void thePasswordIsTheValueOfPass() {
        String json = "{\"verbose\":false,\"lang\":\"java\",\"user\":\"orders\",\"pass\":\"" + P
                + "\",\"echo\":true}";
        assertEquals(at(json, "\"pass\":\""), slot(json, NatsSettings.AuthMode.PASSWORD));
    }

    @Test
    void theTokenIsTheValueOfAuthToken() {
        String json = "{\"auth_token\":\"" + P + "\",\"lang\":\"java\"}";
        assertEquals(at(json, "\"auth_token\":\""), slot(json, NatsSettings.AuthMode.TOKEN));
    }

    @Test
    void theModeDecidesTheKey() {
        String pass = "{\"pass\":\"" + P + "\"}";
        String token = "{\"auth_token\":\"" + P + "\"}";
        assertEquals(-1, slot(pass, NatsSettings.AuthMode.TOKEN));
        assertEquals(-1, slot(token, NatsSettings.AuthMode.PASSWORD));
    }

    @Test
    void thePlaceholderAsTheNameBeforeThePasswordIsLeftAlone() {
        String json = "{\"name\":\"" + P + "\",\"user\":\"orders\",\"pass\":\"" + P + "\"}";
        int slot = slot(json, NatsSettings.AuthMode.PASSWORD);
        assertEquals(at(json, "\"pass\":\""), slot);
        assertEquals(json.lastIndexOf(P) + "CONNECT ".length(), slot);
    }

    @Test
    void thePlaceholderAnywhereButTheSlotIsNotTheSlot() {
        for (String json : new String[] {
            "{\"name\":\"" + P + "\"}",
            "{\"user\":\"" + P + "\"}",
            "{\"user\":\"orders\",\"pass\":\"x" + P + "\"}",
            "{\"user\":\"orders\",\"pass\":\"" + P + "x\"}",
            "{\"xpass\":\"" + P + "\"}",
            "{\"pass\" :\"" + P + "\"}",
            "{}",
        }) {
            assertEquals(-1, slot(json, NatsSettings.AuthMode.PASSWORD), json);
        }
    }

    @Test
    void aNameThatSpellsOutTheSlotIsEscapedAndSoNotTheSlot() {
        // jnats writes a name of  x","pass":"<placeholder>  JSON-escaped.
        String name = "x\\\",\\\"pass\\\":\\\"" + P;
        String json = "{\"name\":\"" + name + "\",\"user\":\"orders\"}";
        assertEquals(-1, slot(json, NatsSettings.AuthMode.PASSWORD));
        String both = "{\"name\":\"" + name + "\",\"pass\":\"" + P + "\"}";
        assertEquals(at(both, ",\"pass\":\""), slot(both, NatsSettings.AuthMode.PASSWORD));
    }

    @Test
    void theKeyMustStartAMember() {
        // Inside another string, unescaped quotes would end it - JSON never
        // writes this, and a needle not after { or , is not taken.
        String json = "{\"a\":\"b\"pass\":\"" + P + "\"}";
        assertEquals(-1, slot(json, NatsSettings.AuthMode.PASSWORD));
    }

    @Test
    void theJsonEscapingOfTheSecretIsCountedAsItIsWritten() {
        byte[] secret = {'a', '"', '\\', '/', '\b', '\f', '\n', '\r', '\t', 0x01, 0x1f, (byte) 0xC3,
            (byte) 0xA9};
        String expected = "a\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0001\\u001fé";
        try (java.lang.foreign.Arena arena = java.lang.foreign.Arena.ofConfined()) {
            java.lang.foreign.MemorySegment in = arena.allocate(secret.length);
            java.lang.foreign.MemorySegment.copy(secret, 0, in,
                    java.lang.foreign.ValueLayout.JAVA_BYTE, 0, secret.length);
            int length = ConnectLine.jsonEscapedLength(in, secret.length);
            assertEquals(expected.getBytes(StandardCharsets.UTF_8).length, length);
            java.lang.foreign.MemorySegment out = arena.allocate(length);
            assertEquals(length, ConnectLine.writeJsonEscaped(in, secret.length, out, 0));
            assertEquals(expected, new String(out.toArray(java.lang.foreign.ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8));
        }
    }
}
