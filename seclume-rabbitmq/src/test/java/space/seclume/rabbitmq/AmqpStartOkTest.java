package space.seclume.rabbitmq;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.SocketException;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.TlsLayer;
import space.seclume.internal.Transport;

/**
 * What {@link AmqpSocket} sends of the client's handshake, without a broker:
 * the protocol header and every frame as the client wrote them, except
 * Connection.Start-Ok, whose PLAIN response - {@code \0user\0placeholder} -
 * goes out with the real password and the lengths that follow from it. And
 * what it refuses to send: another mechanism, a password of the client's own,
 * and a Start-Ok whose lengths do not add up.
 */
class AmqpStartOkTest {

    private static final String PASSWORD = "the-real-password";
    private static final byte[] HEADER = {'A', 'M', 'Q', 'P', 0, 0, 9, 1};

    @TempDir
    Path dir;

    /** A TLS layer that is a buffer: what was written to it, in order. */
    private static final class Written implements TlsLayer {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        boolean closed;

        @Override
        public void write(ByteBuffer plain) {
            byte[] copy = new byte[plain.remaining()];
            plain.get(copy);
            bytes.writeBytes(copy);
        }

        @Override
        public int read(ByteBuffer target) {
            return -1;
        }

        @Override
        public X509Certificate peerCertificate() {
            return null;
        }

        @Override
        public String description() {
            return "written";
        }

        @Override
        public boolean movable() {
            return false;
        }

        @Override
        public void replaceTransport(Transport replacement) {
        }

        @Override
        public void discard() {
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    private Written wire;
    private AmqpSocket socket;

    private OutputStream connected(String user, String password) throws IOException {
        Path file = Files.createTempFile(dir, "rabbit", ".pw");
        Files.writeString(file, password);
        RabbitSettings settings = RabbitSettings.of("amqps://mq.example.com?user="
                + URLEncoder.encode(user, StandardCharsets.UTF_8)
                + "&provider=file&path=" + file);
        wire = new Written();
        socket = new AmqpSocket(settings, wire);
        return socket.getOutputStream();
    }

    private OutputStream connected() throws IOException {
        return connected("app", PASSWORD);
    }

    // ---- frames, as the client writes them ----------------------------------------

    private static byte[] frame(int type, int channel, byte[] payload) {
        ByteBuffer b = ByteBuffer.allocate(7 + payload.length + 1);
        b.put((byte) type).putShort((short) channel).putInt(payload.length).put(payload)
                .put((byte) 0xCE);
        return b.array();
    }

    private static byte[] shortString(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[1 + bytes.length];
        out[0] = (byte) bytes.length;
        System.arraycopy(bytes, 0, out, 1, bytes.length);
        return out;
    }

    private static byte[] longString(byte[] bytes) {
        return ByteBuffer.allocate(4 + bytes.length).putInt(bytes.length).put(bytes).array();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    private static byte[] plain(String user, String password) {
        return ("\0" + user + "\0" + password).getBytes(StandardCharsets.UTF_8);
    }

    /** A client-properties table: one long-string field, padded to {@code size} bytes. */
    private static byte[] properties(int size) {
        byte[] value = new byte[Math.max(0, size - 1 - 7 - 1 - 4)];
        Arrays.fill(value, (byte) 'x');
        return concat(shortString("product"), new byte[] {'S'}, longString(value));
    }

    private static byte[] startOkPayload(byte[] table, String mechanism, byte[] response,
            String locale) {
        return concat(new byte[] {0, 10, 0, 11}, longString(table), shortString(mechanism),
                longString(response), shortString(locale));
    }

    private static byte[] startOk(String user, String password) {
        return frame(1, 0, startOkPayload(properties(64), "PLAIN", plain(user, password),
                "en_US"));
    }

    private static byte[] startOk() {
        return startOk("app", SeclumeRabbit.PLACEHOLDER);
    }

    private static byte[] expected(byte[]... after) {
        return concat(concat(HEADER, startOk("app", PASSWORD)), concat(after));
    }

    // ---- what goes through --------------------------------------------------------

    @Test
    void theStartOkCarriesThePasswordWithTheLengthsThatFollowFromIt() throws Exception {
        connected().write(concat(HEADER, startOk()));
        byte[] sent = wire.bytes.toByteArray();
        assertArrayEquals(HEADER, Arrays.copyOf(sent, 8));
        ByteBuffer f = ByteBuffer.wrap(sent, 8, sent.length - 8).slice();
        assertEquals(1, f.get());
        assertEquals(0, f.getShort());
        int size = f.getInt();
        assertEquals(sent.length - 8 - 8, size, "the frame's size is the new payload's");
        assertEquals(10, f.getShort());
        assertEquals(11, f.getShort());
        byte[] table = new byte[f.getInt()];
        f.get(table);
        assertArrayEquals(properties(64), table);
        byte[] mechanism = new byte[f.get()];
        f.get(mechanism);
        assertEquals("PLAIN", new String(mechanism, StandardCharsets.US_ASCII));
        byte[] response = new byte[f.getInt()];
        f.get(response);
        assertArrayEquals(plain("app", PASSWORD), response);
        byte[] locale = new byte[f.get()];
        f.get(locale);
        assertEquals("en_US", new String(locale, StandardCharsets.US_ASCII));
        assertEquals((byte) 0xCE, f.get());
        assertEquals(0, f.remaining());
    }

    @Test
    void writesSplitAnywhereGiveTheSameBytes() throws Exception {
        byte[] stream = concat(HEADER, startOk(), frame(8, 0, new byte[0]));
        byte[] expected = expected(frame(8, 0, new byte[0]));
        for (int cut = 0; cut <= stream.length; cut++) {
            OutputStream out = connected();
            out.write(stream, 0, cut);
            out.write(stream, cut, stream.length - cut);
            assertArrayEquals(expected, wire.bytes.toByteArray(), "split at " + cut);
        }
        OutputStream out = connected();
        for (byte b : stream) {
            out.write(b);
        }
        assertArrayEquals(expected, wire.bytes.toByteArray(), "byte by byte");
    }

    @Test
    void framesBeforeTheStartOkGoThroughAsTheyAre() throws Exception {
        byte[] heartbeat = frame(8, 0, new byte[0]);
        byte[] otherMethod = frame(1, 0, new byte[] {0, 10, 0, 61});      // Connection.Blocked-ish
        connected().write(concat(HEADER, heartbeat, otherMethod, startOk()));
        assertArrayEquals(concat(HEADER, heartbeat, otherMethod, startOk("app", PASSWORD)),
                wire.bytes.toByteArray());
    }

    @Test
    void aStartOkOnAnotherChannelIsNotTheLogin() throws Exception {
        // Only channel 0 carries Connection methods; a look-alike elsewhere is data.
        byte[] lookalike = frame(1, 1, startOkPayload(properties(16), "PLAIN",
                plain("app", SeclumeRabbit.PLACEHOLDER), "en_US"));
        connected().write(concat(HEADER, lookalike, startOk()));
        assertArrayEquals(concat(HEADER, lookalike, startOk("app", PASSWORD)),
                wire.bytes.toByteArray());
    }

    @Test
    void afterTheStartOkThePlaceholderIsLeftAlone() throws Exception {
        // A message body that happens to hold the placeholder - and a second
        // Start-Ok, which a client does not send - go out as they are.
        byte[] body = frame(3, 1, SeclumeRabbit.PLACEHOLDER.getBytes(StandardCharsets.US_ASCII));
        OutputStream out = connected();
        out.write(concat(HEADER, startOk()));
        out.write(body);
        out.write(startOk());
        assertArrayEquals(expected(body, startOk()), wire.bytes.toByteArray());
    }

    @Test
    void largeClientPropertiesInOneWriteOrByteByByte() throws Exception {
        byte[] big = frame(1, 0, startOkPayload(properties(120_000), "PLAIN",
                plain("app", SeclumeRabbit.PLACEHOLDER), "en_US"));
        byte[] stream = concat(HEADER, big);
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            connected().write(stream);
            int one = wire.bytes.size();
            OutputStream out = connected();
            for (byte b : stream) {
                out.write(b);
            }
            assertEquals(one, wire.bytes.size());
            assertEquals(stream.length + PASSWORD.length() - SeclumeRabbit.PLACEHOLDER.length(),
                    one);
        });
    }

    @Test
    void aUserNameOutsideAsciiIsCountedInBytes() throws Exception {
        String user = "bénédicte-ü";
        connected(user, PASSWORD).write(concat(HEADER, startOk(user, SeclumeRabbit.PLACEHOLDER)));
        assertArrayEquals(concat(HEADER, startOk(user, PASSWORD)), wire.bytes.toByteArray());
    }

    @Test
    void aPasswordOutsideAsciiIsCountedInBytes() throws Exception {
        String password = "pässwörd-€";
        connected("app", password).write(concat(HEADER, startOk()));
        assertArrayEquals(concat(HEADER, startOk("app", password)), wire.bytes.toByteArray());
    }

    // ---- what does not go out ----------------------------------------------------

    private void refused(byte[] startOk, String message) throws Exception {
        refused("app", PASSWORD, startOk, message);
    }

    private void refused(String user, String password, byte[] startOk, String message)
            throws Exception {
        OutputStream out = connected(user, password);
        IOException e = assertThrows(IOException.class, () -> out.write(concat(HEADER, startOk)));
        assertTrue(e.getMessage().contains(message), e.getMessage());
        assertArrayEquals(HEADER, wire.bytes.toByteArray(), "nothing but the header went out");
        assertTrue(socket.isClosed(), "the socket is closed after a refusal");
        assertTrue(wire.closed);
        assertThrows(SocketException.class, () -> out.write(frame(8, 0, new byte[0])));
        assertArrayEquals(HEADER, wire.bytes.toByteArray());
        assertFalse(new String(wire.bytes.toByteArray(), StandardCharsets.ISO_8859_1)
                .contains(password));
    }

    @Test
    void anotherMechanismIsRefused() throws Exception {
        refused(frame(1, 0, startOkPayload(properties(16), "AMQPLAIN",
                plain("app", SeclumeRabbit.PLACEHOLDER), "en_US")), "rather than PLAIN");
    }

    @Test
    void aPasswordOrUserOfTheClientsOwnIsRefused() throws Exception {
        refused(startOk("app", "hunter2"), "user or password of its own");
        refused(startOk("other", SeclumeRabbit.PLACEHOLDER), "user or password of its own");
        refused(frame(1, 0, startOkPayload(properties(16), "PLAIN",
                plain("app", SeclumeRabbit.PLACEHOLDER + "x"), "en_US")),
                "user or password of its own");
        refused(frame(1, 0, startOkPayload(properties(16), "PLAIN", new byte[0], "en_US")),
                "user or password of its own");
    }

    @Test
    void aPasswordWithANulIsRefused() throws Exception {
        refused("app", "pass\0word", startOk(), "holds a NUL");
    }

    @Test
    void aStartOkWhoseLengthsDoNotAddUpIsRefused() throws Exception {
        byte[] good = startOkPayload(properties(16), "PLAIN",
                plain("app", SeclumeRabbit.PLACEHOLDER), "en_US");
        int tableAt = 4;
        int mechanismAt = tableAt + 4 + properties(16).length;
        int responseAt = mechanismAt + 1 + "PLAIN".length();

        for (int lie : new int[] {-1, Integer.MIN_VALUE, Integer.MAX_VALUE, good.length}) {
            byte[] bad = good.clone();
            ByteBuffer.wrap(bad).putInt(tableAt, lie);
            refused(frame(1, 0, bad), "client properties");
        }
        for (int lie : new int[] {-1, Integer.MIN_VALUE, good.length - responseAt - 3}) {
            byte[] bad = good.clone();
            ByteBuffer.wrap(bad).putInt(responseAt, lie);
            refused(frame(1, 0, bad), "response");
        }
        byte[] longMechanism = good.clone();
        longMechanism[mechanismAt] = (byte) 0xFF;
        refused(frame(1, 0, longMechanism), "mechanism that runs past");

        // Cut short: no room for the table's length, the mechanism, the response's length.
        refused(frame(1, 0, Arrays.copyOf(good, tableAt + 2)), "client properties");
        refused(frame(1, 0, Arrays.copyOf(good, mechanismAt)), "before its mechanism");
        refused(frame(1, 0, Arrays.copyOf(good, responseAt + 1)), "response");

        byte[] noEnd = frame(1, 0, good);
        noEnd[noEnd.length - 1] = 0;
        refused(noEnd, "frame-end octet");
    }

    @Test
    void anOversizedHandshakeFrameIsRefusedFromItsHeader() throws Exception {
        OutputStream out = connected();
        byte[] header = {1, 0, 0, 0, 0x02, 0, 1};                  // 128 KiB + 1
        IOException e = assertThrows(IOException.class, () -> out.write(concat(HEADER, header)));
        assertTrue(e.getMessage().contains("131073 bytes"), e.getMessage());
        assertArrayEquals(HEADER, wire.bytes.toByteArray());
        byte[] negative = {1, 0, 0, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        OutputStream again = connected();
        assertThrows(IOException.class, () -> again.write(concat(HEADER, negative)));
        assertArrayEquals(HEADER, wire.bytes.toByteArray());
    }

    @Test
    void theHeaderAloneGoesOutAsItArrives() throws Exception {
        OutputStream out = connected();
        out.write(HEADER, 0, 3);
        assertArrayEquals(Arrays.copyOf(HEADER, 3), wire.bytes.toByteArray());
        out.write(HEADER, 3, 5);
        assertArrayEquals(HEADER, wire.bytes.toByteArray());
        out.write(new byte[0]);
        assertArrayEquals(HEADER, wire.bytes.toByteArray());
    }
}
