package space.seclume.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import space.seclume.tls.ScriptedTlsServer.Outgoing;

/**
 * One fuzz case against what a server sends <b>after</b> the handshake,
 * under the application key: the part neither sweep of
 * {@code ServerHelloFuzzTest} reaches. The handshake itself is the legal
 * one; the input then becomes a list of records, each sealed correctly and
 * each saying something the input chose - application data, an alert, any
 * handshake message (a KeyUpdate, a NewSessionTicket, bytes), a content type
 * that does not exist, a key rotated without a KeyUpdate.
 *
 * <p>What must hold, for every input:
 *
 * <ul>
 *   <li>reading ends in data, an orderly end of stream or an
 *       {@link IOException} - no index out of bounds, no
 *       {@code IllegalStateException}, no loop that never returns;
 *   <li><b>what reaches the application is exactly a prefix of the
 *       application data the server sent</b>, in order: nothing from a
 *       handshake message, an alert or an unknown record type is ever handed
 *       over as data.
 * </ul>
 */
final class PostHandshakeRecords {

    private static final String HOSTNAME = "db.example.com";
    /** Reads before a case counts as spinning - far above any legal input. */
    private static final int READS = 100_000;

    private PostHandshakeRecords() {
    }

    /** The records an input stands for, and the application data among them. */
    record Script(List<Outgoing> records, byte[] data) {
    }

    static Script script(byte[] input) {
        List<Outgoing> records = new ArrayList<>();
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        data.writeBytes(ScriptedTlsServer.GREETING);
        int i = 0;
        while (i < input.length && records.size() < 12) {
            int op = input[i++] & 0xff;
            int length = i < input.length ? input[i++] & 0xff : 0;
            if ((op & 0x40) != 0 && i < input.length) {
                length = (length << 6) | (input[i++] & 0x3f);        // up to 16 KiB
            }
            byte[] body = Arrays.copyOfRange(input, i, Math.min(input.length, i + length));
            i += body.length;
            boolean rotate = (op & 0x80) != 0;
            Outgoing record = switch (op & 7) {
                case 0 -> new Outgoing(23, body, rotate);
                case 1 -> new Outgoing(21, body, rotate);
                case 2 -> new Outgoing(22, body, rotate);
                case 3 -> new Outgoing(22, new byte[] {24, 0, 0, 1,
                    body.length > 0 ? body[0] : 0}, rotate || body.length == 0 || body[0] == 0
                        || body[0] == 1);
                case 4 -> new Outgoing(22, withHeader(Handshake.NEW_SESSION_TICKET, body), rotate);
                case 5 -> new Outgoing(body.length > 0 ? body[0] & 0xff : 0,
                        Arrays.copyOfRange(body, Math.min(1, body.length), body.length), rotate);
                case 6 -> new Outgoing(20, body, rotate);
                default -> new Outgoing(23, new byte[0], rotate);
            };
            records.add(record);
            data.writeBytes(applicationData(record));
        }
        return new Script(records, data.toByteArray());
    }

    /**
     * What a receiver following RFC 8446 section 5.4 reads as application
     * data from one record - which is not always what the sender meant. The
     * record carries {@code body || type} and the receiver takes the last byte
     * that is not zero as the type, everything before it as the content. So a
     * record the server labels 0 whose body ends in {@code 17 00 00} is, on
     * the wire, application data with padding, and a correct client delivers
     * it: the first finding of this harness, 30.09.2026, was this, in the
     * harness.
     */
    static byte[] applicationData(Outgoing record) {
        byte[] body = record.body();
        byte[] inner = Arrays.copyOf(body, body.length + 1);
        inner[body.length] = (byte) record.contentType();
        int at = inner.length - 1;
        while (at >= 0 && inner[at] == 0) {
            at--;
        }
        if (at < 0 || (inner[at] & 0xff) != 23) {
            return new byte[0];
        }
        return Arrays.copyOf(inner, at);
    }

    /** A handshake message: type, three bytes of length, body. */
    private static byte[] withHeader(int type, byte[] body) {
        byte[] message = new byte[4 + body.length];
        message[0] = (byte) type;
        message[1] = (byte) (body.length >>> 16);
        message[2] = (byte) (body.length >>> 8);
        message[3] = (byte) body.length;
        System.arraycopy(body, 0, message, 4, body.length);
        return message;
    }

    /**
     * Runs one input; returns normally when the case ended the way a library
     * has to end, throws {@link AssertionError} when it did not.
     *
     * @return the bytes the application received
     */
    static byte[] run(byte[] input, EncryptedFlight.Material material) {
        Script script = script(input);
        ScriptedTlsServer server = new ScriptedTlsServer(ScriptedTlsServer.COMPLETE,
                material.leaf(), material.key(), false, null, script.records());
        TlsConnection connection;
        try {
            connection = ClientHandshake.connect(server, HOSTNAME, material.trust());
        } catch (IOException | RuntimeException | Error handshake) {
            // The handshake is the legal one; nothing in the input touches it.
            throw new AssertionError("the untouched handshake failed", handshake);
        }
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        try (connection) {
            ByteBuffer buffer = ByteBuffer.allocate(4096);
            int reads = 0;
            while (true) {
                if (++reads > READS) {
                    throw new AssertionError("still reading after " + READS + " reads: "
                            + script.records().size() + " records");
                }
                buffer.clear();
                int count;
                try {
                    count = connection.read(buffer);
                } catch (IOException expected) {
                    break;                        // what a hostile record has to end in
                } catch (RuntimeException | Error wrong) {
                    throw new AssertionError("a hostile record ended in " + wrong
                            + " rather than an IOException", wrong);
                }
                if (count < 0) {
                    break;
                }
                received.write(buffer.array(), 0, count);
            }
        }
        byte[] got = received.toByteArray();
        byte[] sent = script.data();
        if (got.length > sent.length || !Arrays.equals(got, 0, got.length, sent, 0, got.length)) {
            throw new AssertionError("the application received " + got.length
                    + " bytes that are not a prefix of the " + sent.length
                    + " bytes of application data the server sent");
        }
        return got;
    }
}
