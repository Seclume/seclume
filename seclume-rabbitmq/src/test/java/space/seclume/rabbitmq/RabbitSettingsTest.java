package space.seclume.rabbitmq;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class RabbitSettingsTest {

    private static final String SECRET = "user=app&provider=file&path=/run/secrets/rabbit";

    @Test
    void defaultsAndVirtualHosts() {
        RabbitSettings s = RabbitSettings.of("amqps://mq.example.com?" + SECRET);
        assertEquals(5671, s.port);
        assertEquals("/", s.virtualHost);
        assertEquals("app", s.user);
        assertEquals("orders", RabbitSettings.of("amqps://mq.example.com/orders?" + SECRET)
                .virtualHost);
        assertEquals("/", RabbitSettings.of("amqps://mq.example.com/%2F?" + SECRET).virtualHost);
        assertEquals(15671, RabbitSettings.of("amqps://mq.example.com:15671?" + SECRET).port);
    }

    @Test
    void refusals() {
        assertMessage("amqps://", () -> RabbitSettings.of("amqp://mq.example.com?" + SECRET));
        assertMessage("in front of the host",
                () -> RabbitSettings.of("amqps://app:pw@mq.example.com?" + SECRET));
        assertMessage("needs user=", () -> RabbitSettings.of(
                "amqps://mq.example.com?provider=file&path=/x"));
        assertMessage("no secret named", () -> RabbitSettings.of("amqps://mq.example.com?user=a"));
        assertMessage("timeout", () -> RabbitSettings.of("amqps://mq.example.com?timeout=x&"
                + SECRET));
    }

    private static void assertMessage(String part, org.junit.jupiter.api.function.Executable e) {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, e);
        assertTrue(thrown.getMessage().contains(part), thrown.getMessage());
    }
}
