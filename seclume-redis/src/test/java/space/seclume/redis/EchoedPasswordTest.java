package space.seclume.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisConnectionException;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.protocol.ProtocolVersion;
import redis.clients.jedis.exceptions.JedisConnectionException;

/**
 * A server that does not know a command answers with the command's
 * arguments. Redis 5 has no {@code HELLO}, and to Lettuce's
 * {@code HELLO 3 AUTH default password} - the password written in from native
 * memory - it says
 *
 * <pre>-ERR unknown command `HELLO`, with args beginning with: `3`, `AUTH`, `default`, `password`,</pre>
 *
 * <p>Found in the review of 11.11.2026: Lettuce made a {@code String} of that
 * line - the message of the exception a connection attempt ends with, or of
 * the one it catches before it falls back to {@code AUTH} - and so did the
 * login for Jedis, of a server that does not know {@code AUTH}. The password
 * was on the heap and in whatever logs the exception.
 *
 * <p>The server here is a script that answers as Redis 5 does: with what it
 * was sent. What the client is told must name the command and not the
 * password.
 */
@Timeout(60)
class EchoedPasswordTest {

    @TempDir
    static Path directory;
    private static Path secretFile;

    @BeforeAll
    static void secret() throws IOException {
        secretFile = directory.resolve("redis");
        Files.writeString(secretFile, "echoed-" + UUID.randomUUID());
    }

    private static String password() throws IOException {
        return Files.readString(secretFile);
    }

    private static String url(Redis5 server) {
        return "redis://127.0.0.1:" + server.port() + "?provider=file&path="
                + secretFile.toString().replace('\\', '/');
    }

    /** Every message of {@code failure}, its causes and what they suppressed. */
    private static String everyMessage(Throwable failure) {
        StringBuilder all = new StringBuilder();
        List<Throwable> seen = new ArrayList<>();
        collect(failure, all, seen);
        return all.toString();
    }

    private static void collect(Throwable failure, StringBuilder all, List<Throwable> seen) {
        if (failure == null || seen.contains(failure) || seen.size() > 50) {
            return;
        }
        seen.add(failure);
        all.append(failure).append('\n');
        collect(failure.getCause(), all, seen);
        for (Throwable suppressed : failure.getSuppressed()) {
            collect(suppressed, all, seen);
        }
    }

    @Test
    void lettuceIsNotToldThePasswordByAServerWithoutHello() throws Exception {
        try (Redis5 server = new Redis5(true)) {
            RedisClient client = SeclumeLettuce.client(url(server));
            try {
                // RESP3 or nothing: the refusal of HELLO is what connect() ends with.
                client.setOptions(ClientOptions.builder()
                        .protocolVersion(ProtocolVersion.RESP3).build());
                RedisConnectionException refused =
                        assertThrows(RedisConnectionException.class, client::connect);
                String told = everyMessage(refused);
                assertTrue(server.echoed.get() > 0, "the server was not sent the password: " + told);
                assertTrue(told.contains("unknown command"), told);
                assertFalse(told.contains(password()),
                        "the password came back in the server's answer and into the exception");
            } finally {
                client.shutdown();
            }
        }
    }

    @Test
    void lettuceStillFallsBackToAuthAndWorks() throws Exception {
        try (Redis5 server = new Redis5(true)) {
            RedisClient client = SeclumeLettuce.client(url(server));
            try (StatefulRedisConnection<String, String> connection = client.connect()) {
                assertEquals("PONG", connection.sync().ping());
                assertEquals("OK", connection.sync().set("k", "v"));
                assertEquals("v", connection.sync().get("k"));
            } finally {
                client.shutdown();
            }
            assertTrue(server.echoed.get() > 0, "HELLO was not refused with its arguments");
            assertTrue(server.loggedIn.get() > 0, "AUTH did not follow");
        }
    }

    @Test
    void theLoginForJedisIsNotToldThePasswordByAServerWithoutAuth() throws Exception {
        try (Redis5 server = new Redis5(false)) {
            SeclumeRedisSocketFactory sockets = SeclumeRedisSocketFactory.of(url(server));
            JedisConnectionException refused =
                    assertThrows(JedisConnectionException.class, sockets::createSocket);
            String told = everyMessage(refused);
            assertTrue(server.echoed.get() > 0, "the server was not sent the password: " + told);
            assertTrue(told.contains("unknown command"), told);
            assertFalse(told.contains(password()),
                    "the password came back in the server's answer and into the exception");
        }
    }

    /**
     * Answers as Redis 5 does: no {@code HELLO}, and a command it does not
     * know named with its arguments, up to 128 bytes of them. With
     * {@code auth}, {@code AUTH password} logs in; without, that is unknown too.
     */
    private static final class Redis5 implements Closeable {

        private final ServerSocket listener;
        private final boolean auth;
        final AtomicInteger echoed = new AtomicInteger();
        final AtomicInteger loggedIn = new AtomicInteger();
        private final java.util.Map<String, String> values =
                new java.util.concurrent.ConcurrentHashMap<>();

        Redis5(boolean auth) throws IOException {
            this.auth = auth;
            this.listener = new ServerSocket(0, 20, InetAddress.getLoopbackAddress());
            Thread.ofVirtual().start(this::accept);
        }

        int port() {
            return listener.getLocalPort();
        }

        private void accept() {
            while (!listener.isClosed()) {
                try {
                    Socket client = listener.accept();
                    Thread.ofVirtual().start(() -> serve(client));
                } catch (IOException closed) {
                    return;
                }
            }
        }

        private void serve(Socket client) {
            try (client) {
                InputStream in = new BufferedInputStream(client.getInputStream());
                OutputStream out = client.getOutputStream();
                String expected = password();
                while (true) {
                    List<String> command = command(in);
                    if (command == null) {
                        return;
                    }
                    String name = command.get(0).toUpperCase(Locale.ROOT);
                    String answer;
                    if (name.equals("AUTH") && auth) {
                        boolean right = command.get(command.size() - 1).equals(expected);
                        if (right) {
                            loggedIn.incrementAndGet();
                        }
                        answer = right ? "+OK\r\n" : "-WRONGPASS invalid username-password pair\r\n";
                    } else if (name.equals("PING")) {
                        answer = "+PONG\r\n";
                    } else if (name.equals("CLIENT") || name.equals("SELECT")) {
                        answer = "+OK\r\n";
                    } else if (name.equals("SET")) {
                        values.put(command.get(1), command.get(2));
                        answer = "+OK\r\n";
                    } else if (name.equals("GET")) {
                        String value = values.get(command.get(1));
                        answer = value == null ? "$-1\r\n" : "$" + value.length() + "\r\n" + value + "\r\n";
                    } else {
                        // processCommand() of Redis 5: the arguments, 128 bytes of them
                        StringBuilder arguments = new StringBuilder();
                        for (int i = 1; i < command.size() && arguments.length() < 128; i++) {
                            String argument = command.get(i);
                            arguments.append('`').append(argument, 0,
                                    Math.min(argument.length(), 128 - arguments.length()))
                                    .append("`, ");
                        }
                        if (command.contains(expected)) {
                            echoed.incrementAndGet();
                        }
                        answer = "-ERR unknown command `" + command.get(0)
                                + "`, with args beginning with: " + arguments + "\r\n";
                    }
                    out.write(answer.getBytes(StandardCharsets.UTF_8));
                    out.flush();
                }
            } catch (IOException | RuntimeException gone) {
                // the client hung up
            }
        }

        /** One command - an array of bulk strings - or null at the end. */
        private static List<String> command(InputStream in) throws IOException {
            String header = line(in);
            if (header == null || !header.startsWith("*")) {
                return null;
            }
            int count = Integer.parseInt(header.substring(1));
            List<String> command = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                String length = line(in);
                if (length == null || !length.startsWith("$")) {
                    return null;
                }
                byte[] value = in.readNBytes(Integer.parseInt(length.substring(1)));
                line(in);
                command.add(new String(value, StandardCharsets.UTF_8));
            }
            return command.isEmpty() ? null : command;
        }

        private static String line(InputStream in) throws IOException {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            for (int b; (b = in.read()) >= 0; ) {
                if (b == '\n') {
                    String text = line.toString(StandardCharsets.UTF_8);
                    return text.endsWith("\r") ? text.substring(0, text.length() - 1) : text;
                }
                line.write(b);
            }
            return null;
        }

        @Override
        public void close() throws IOException {
            listener.close();
        }
    }
}
