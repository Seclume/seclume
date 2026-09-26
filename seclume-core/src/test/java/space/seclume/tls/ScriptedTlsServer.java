package space.seclume.tls;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.NativeP256;
import space.seclume.internal.Transport;

/**
 * A TLS 1.3 server that says exactly what it is told to, in the order it is
 * told to - including orders no real server would use.
 *
 * <p>Every message it sends is <b>correct where it stands</b>: the
 * CertificateVerify signs the transcript as it is at that point, the Finished
 * is computed over whatever went before it, and the whole flight is sealed
 * under the real server handshake key. So when a client accepts one of these
 * flights, it is not because a MAC or a signature happened to be wrong; it is
 * because the client did not insist on the <b>order</b> RFC 8446 section 4.4
 * prescribes. That is the property this exists to test, and a server built on
 * a real TLS library cannot be made to break it on purpose.
 *
 * <p>It is a {@link Transport}, and single-threaded: the client's ClientHello
 * arrives through {@link #write}, and the whole answer is queued before the
 * client first calls {@link #read}. Once the queue is empty the connection
 * reads as closed. What the client sends back after that is decrypted under
 * the client handshake key, so a test can see which alert the client sent
 * when it gave up.
 *
 * <p>Built from this package's own pieces - {@link RecordStream}'s framing via
 * {@link RecordProtection}, {@link KeySchedule}, {@link TranscriptHash} and
 * {@link Finished} - each of which is proven separately against RFC 8448 and
 * against JSSE. A key exchange on P-256 and TLS_AES_128_GCM_SHA256 only.
 */
final class ScriptedTlsServer implements Transport {

    /** The messages a server's encrypted flight can consist of. */
    enum Step {
        ENCRYPTED_EXTENSIONS, CERTIFICATE_REQUEST, CERTIFICATE, CERTIFICATE_VERIFY, FINISHED
    }

    /** The flight RFC 8446 section 4.4 prescribes without a PSK. */
    static final List<Step> COMPLETE = List.of(Step.ENCRYPTED_EXTENSIONS, Step.CERTIFICATE,
            Step.CERTIFICATE_VERIFY, Step.FINISHED);

    /** The same with a request for a client certificate in its one legal place. */
    static final List<Step> COMPLETE_WITH_REQUEST = List.of(Step.ENCRYPTED_EXTENSIONS,
            Step.CERTIFICATE_REQUEST, Step.CERTIFICATE, Step.CERTIFICATE_VERIFY, Step.FINISHED);

    /** What the server sends as application data once its Finished is out. */
    static final byte[] GREETING = "hello from the scripted server"
            .getBytes(java.nio.charset.StandardCharsets.US_ASCII); // seclume-allow: test data

    private static final HashAlgorithm HASH = HashAlgorithm.SHA_256;
    private static final int KEY_LENGTH = 16;

    private final List<Step> script;
    private final byte[] leaf;
    private final PrivateKey key;
    private final boolean recordPerMessage;
    private final UnaryOperator<byte[]> tamper;
    private final List<Outgoing> afterHandshake;

    private final Arena arena = Arena.ofShared();
    private final ByteArrayOutputStream fromClient = new ByteArrayOutputStream();
    private ByteBuffer toClient = ByteBuffer.allocate(0);
    private boolean helloSeen;
    private boolean open = true;

    private RecordProtection clientHandshakeReader;
    private RecordProtection clientApplicationReader;
    private int alertReceived = -1;
    private boolean clientFinishedSeen;
    private final List<Integer> clientMessages = new ArrayList<>();

    /**
     * One record the server sends once the handshake is over, under its
     * application key.
     *
     * @param rotateAfter move to the next generation of that key after this
     *                    record - what a server does right after its own
     *                    KeyUpdate
     */
    record Outgoing(int contentType, byte[] body, boolean rotateAfter) {

        static Outgoing handshake(byte[] message) {
            return new Outgoing(22, message, false);
        }

        static Outgoing keyUpdate(int requestUpdate) {
            return new Outgoing(22, new byte[] {24, 0, 0, 1, (byte) requestUpdate}, true);
        }

        static Outgoing data(byte[] bytes) {
            return new Outgoing(23, bytes, false);
        }
    }

    /**
     * @param script           the flight, in order
     * @param leaf             the DER certificate to present
     * @param key              the key belonging to it, P-256
     * @param recordPerMessage one record per message instead of one for the flight
     * @param tamper           replaces the flight's plaintext before it is sealed, or null
     */
    ScriptedTlsServer(List<Step> script, byte[] leaf, PrivateKey key, boolean recordPerMessage,
            UnaryOperator<byte[]> tamper) {
        this(script, leaf, key, recordPerMessage, tamper, List.of());
    }

    /**
     * @param afterHandshake records to send after the greeting, under the
     *                       server's application key
     */
    ScriptedTlsServer(List<Step> script, byte[] leaf, PrivateKey key, boolean recordPerMessage,
            UnaryOperator<byte[]> tamper, List<Outgoing> afterHandshake) {
        this.script = List.copyOf(script);
        this.leaf = leaf.clone();
        this.key = key;
        this.recordPerMessage = recordPerMessage;
        this.tamper = tamper;
        this.afterHandshake = List.copyOf(afterHandshake);
    }

    ScriptedTlsServer(List<Step> script, byte[] leaf, PrivateKey key) {
        this(script, leaf, key, false, null);
    }

    /** The alert description the client sent, or -1 if it sent none. */
    int alertReceived() {
        return alertReceived;
    }

    /** Whether the client got as far as sending its own Finished. */
    boolean clientFinishedSeen() {
        return clientFinishedSeen;
    }

    /** The handshake message types the client sent after its Finished, in order. */
    List<Integer> clientMessagesAfterFinished() {
        return List.copyOf(clientMessages);
    }

    // ---- Transport --------------------------------------------------------

    @Override
    public int read(ByteBuffer into) {
        if (!toClient.hasRemaining()) {
            return -1;
        }
        int count = Math.min(into.remaining(), toClient.remaining());
        into.put(toClient.slice(toClient.position(), count));
        toClient.position(toClient.position() + count);
        return count;
    }

    @Override
    public int write(ByteBuffer from) {
        int count = from.remaining();
        byte[] bytes = new byte[count];
        from.get(bytes);
        fromClient.write(bytes, 0, count);
        consume();
        return count;
    }

    @Override
    public boolean isOpen() {
        return open;
    }

    @Override
    public void close() {
        open = false;
        if (clientHandshakeReader != null) {
            clientHandshakeReader.close();
            clientHandshakeReader = null;
        }
        if (clientApplicationReader != null) {
            clientApplicationReader.close();
            clientApplicationReader = null;
        }
    }

    // ---- what the client sent ----------------------------------------------

    private void consume() {
        byte[] all = fromClient.toByteArray();
        int at = 0;
        while (all.length - at >= RecordProtection.HEADER) {
            int type = all[at] & 0xff;
            int length = ((all[at + 3] & 0xff) << 8) | (all[at + 4] & 0xff);
            if (all.length - at < RecordProtection.HEADER + length) {
                break;
            }
            byte[] body = java.util.Arrays.copyOfRange(all, at + RecordProtection.HEADER,
                    at + RecordProtection.HEADER + length);
            if (!helloSeen && type == 22) {
                helloSeen = true;
                answer(body);
            } else if (type == 21 && length >= 2) {
                alertReceived = body[1] & 0xff;
            } else if (type == 23 && clientHandshakeReader != null) {
                opened(java.util.Arrays.copyOfRange(all, at,
                        at + RecordProtection.HEADER + length));
            }
            at += RecordProtection.HEADER + length;
        }
        fromClient.reset();
        fromClient.write(all, at, all.length - at);
    }

    private void opened(byte[] record) {
        RecordProtection reader = clientFinishedSeen ? clientApplicationReader : clientHandshakeReader;
        if (reader == null) {
            return;
        }
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment in = scratch.allocate(record.length);
            MemorySegment.copy(record, 0, in, ValueLayout.JAVA_BYTE, 0, record.length);
            MemorySegment out = scratch.allocate(record.length);
            RecordProtection.Opened result = reader.open(in, 0, record.length, out, 0);
            if (result == null) {
                return;
            }
            if (result.contentType() == 21 && result.length() >= 2) {
                alertReceived = out.get(ValueLayout.JAVA_BYTE, 1) & 0xff;
            } else if (result.contentType() == 22 && result.length() >= 1) {
                int type = out.get(ValueLayout.JAVA_BYTE, 0) & 0xff;
                if (!clientFinishedSeen && type == Handshake.FINISHED) {
                    clientFinishedSeen = true;
                } else if (clientFinishedSeen) {
                    clientMessages.add(type);
                    if (type == 24 && clientApplicationReader != null) {
                        RecordProtection next = clientApplicationReader.next();
                        clientApplicationReader.close();
                        clientApplicationReader = next;
                    }
                }
            }
        }
    }

    // ---- the answer ---------------------------------------------------------

    private void answer(byte[] clientHelloBody) {
        MemorySegment hello = arena.allocate(RecordProtection.HEADER + clientHelloBody.length);
        MemorySegment.copy(clientHelloBody, 0, hello, ValueLayout.JAVA_BYTE, 0,
                clientHelloBody.length);
        int helloLength = clientHelloBody.length;

        MemorySegment clientShare = p256Share(hello);
        ByteArrayOutputStream wire = new ByteArrayOutputStream();

        try (NativeP256 exchange = NativeP256.generate();
                TranscriptHash transcript = new TranscriptHash(HASH);
                KeySchedule schedule = KeySchedule.withoutPsk(HASH)) {
            MemorySegment serverShare = arena.allocate(NativeP256.PUBLIC_SIZE);
            exchange.publicKey(serverShare);
            MemorySegment shared = arena.allocate(NativeP256.SECRET_SIZE);
            exchange.derive(clientShare, shared);

            byte[] serverHello = serverHello(hello, serverShare);
            record(wire, 22, serverHello);
            record(wire, 20, new byte[] {1});        // the middlebox-compatibility CCS

            MemorySegment digest = arena.allocate(HASH.digestLength());
            transcript.update(hello, 0, helloLength);
            transcript.update(MemorySegment.ofArray(serverHello), 0, serverHello.length);
            transcript.current(digest, 0);
            schedule.deriveHandshakeSecret(shared);
            schedule.deriveHandshakeTrafficSecrets(digest);
            shared.fill((byte) 0);

            clientHandshakeReader = RecordProtection.fromSecret(HASH,
                    schedule.clientHandshakeTrafficSecret(), KEY_LENGTH);

            List<byte[]> flight = new ArrayList<>();
            boolean finished = false;
            for (Step step : script) {
                byte[] message = message(step, transcript, schedule, digest);
                transcript.update(MemorySegment.ofArray(message), 0, message.length);
                flight.add(message);
                finished |= step == Step.FINISHED;
            }

            try (RecordProtection writer = RecordProtection.fromSecret(HASH,
                    schedule.serverHandshakeTrafficSecret(), KEY_LENGTH)) {
                if (tamper != null) {
                    sealed(wire, writer, 22, tamper.apply(concatenate(flight)));
                } else if (recordPerMessage) {
                    for (byte[] message : flight) {
                        sealed(wire, writer, 22, message);
                    }
                } else {
                    sealed(wire, writer, 22, concatenate(flight));
                }
            }

            if (finished && tamper == null) {
                // Application data straight after the Finished, as a server
                // may: the client can only read it with keys derived over the
                // same transcript this server used.
                transcript.current(digest, 0);
                schedule.deriveMasterSecret();
                schedule.deriveApplicationTrafficSecrets(digest);
                clientApplicationReader = RecordProtection.fromSecret(HASH,
                        schedule.clientApplicationTrafficSecret(), KEY_LENGTH);
                RecordProtection application = RecordProtection.fromSecret(HASH,
                        schedule.serverApplicationTrafficSecret(), KEY_LENGTH);
                try {
                    sealed(wire, application, 23, GREETING);
                    for (Outgoing record : afterHandshake) {
                        sealed(wire, application, record.contentType(), record.body());
                        if (record.rotateAfter()) {
                            RecordProtection next = application.next();
                            application.close();
                            application = next;
                        }
                    }
                } finally {
                    application.close();
                }
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("the scripted server could not sign", e);
        }
        toClient = ByteBuffer.wrap(wire.toByteArray());
    }

    private byte[] message(Step step, TranscriptHash transcript, KeySchedule schedule,
            MemorySegment digest) throws GeneralSecurityException {
        return switch (step) {
            case ENCRYPTED_EXTENSIONS -> new byte[] {Handshake.ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0};
            case CERTIFICATE_REQUEST -> new byte[] {Handshake.CERTIFICATE_REQUEST, 0, 0, 11,
                0,                                    // empty context
                0, 8,                                 // extensions
                0, 13, 0, 4, 0, 2, 4, 3};             // signature_algorithms: ecdsa_secp256r1_sha256
            case CERTIFICATE -> {
                try (Arena scratch = Arena.ofConfined()) {
                    List<byte[]> chain = List.of(leaf);
                    MemorySegment out = scratch.allocate(
                            CertificateMessage.sizeFor(new byte[0], chain));
                    int length = CertificateMessage.write(out, new byte[0], chain);
                    yield out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
                }
            }
            case CERTIFICATE_VERIFY -> {
                transcript.current(digest, 0);
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(key);
                signer.update(HandshakeSignature.content(true,
                        digest.toArray(ValueLayout.JAVA_BYTE)));
                byte[] signature = signer.sign();
                try (Arena scratch = Arena.ofConfined()) {
                    MemorySegment out = scratch.allocate(Handshake.HEADER + 4L + signature.length);
                    int length = CertificateVerifyMessage.write(out,
                            HandshakeSignature.ECDSA_SECP256R1_SHA256, signature);
                    yield out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
                }
            }
            case FINISHED -> {
                transcript.current(digest, 0);
                try (Arena scratch = Arena.ofConfined()) {
                    MemorySegment verifyData = scratch.allocate(HASH.digestLength());
                    Finished.compute(schedule, schedule.serverHandshakeTrafficSecret(), digest,
                            verifyData);
                    byte[] message = new byte[Handshake.HEADER + HASH.digestLength()];
                    message[0] = Handshake.FINISHED;
                    message[3] = (byte) HASH.digestLength();
                    MemorySegment.copy(verifyData, ValueLayout.JAVA_BYTE, 0, message,
                            Handshake.HEADER, HASH.digestLength());
                    yield message;
                }
            }
        };
    }

    /** The client's P-256 key share, wherever in its list it is. */
    private static MemorySegment p256Share(MemorySegment hello) {
        int[] length = new int[1];
        long extensions = Handshake.clientHelloExtensions(hello, Handshake.HEADER, length);
        MemorySegment[] found = {null};
        Handshake.extensions(hello, extensions, length[0], (type, at, size) -> {
            if (type != Handshake.EXTENSION_KEY_SHARE) {
                return;
            }
            long end = at + 2 + Handshake.u16(hello, at);
            long entry = at + 2;
            while (entry + 4 <= end) {
                int group = Handshake.u16(hello, entry);
                int keyLength = Handshake.u16(hello, entry + 2);
                if (group == ClientHello.SECP256R1 && keyLength == NativeP256.PUBLIC_SIZE) {
                    found[0] = hello.asSlice(entry + 4, keyLength);
                }
                entry += 4 + keyLength;
            }
        });
        if (found[0] == null) {
            throw new IllegalStateException("the ClientHello offered no P-256 share");
        }
        return found[0];
    }

    private static byte[] serverHello(MemorySegment clientHello, MemorySegment share) {
        int sessionLength = Handshake.sessionIdLength(clientHello, Handshake.HEADER);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x03);
        body.write(0x03);
        byte[] random = new byte[32];
        new java.security.SecureRandom().nextBytes(random);
        body.writeBytes(random);
        body.write(sessionLength);
        body.writeBytes(clientHello.asSlice(Handshake.sessionIdOffset(Handshake.HEADER),
                sessionLength).toArray(ValueLayout.JAVA_BYTE));
        body.write(ClientHello.AES_128_GCM_SHA256 >>> 8);
        body.write(ClientHello.AES_128_GCM_SHA256 & 0xff);
        body.write(0);                                        // compression
        byte[] key = share.toArray(ValueLayout.JAVA_BYTE);
        int extensions = 6 + 8 + key.length;
        body.write(extensions >>> 8);
        body.write(extensions & 0xff);
        body.writeBytes(new byte[] {0, 43, 0, 2, 3, 4});     // supported_versions: TLS 1.3
        body.writeBytes(new byte[] {0, 51, 0, (byte) (4 + key.length), 0, 23, 0,
            (byte) key.length});                               // key_share: P-256
        body.writeBytes(key);

        byte[] bytes = body.toByteArray();
        byte[] message = new byte[Handshake.HEADER + bytes.length];
        message[0] = Handshake.SERVER_HELLO;
        message[2] = (byte) (bytes.length >>> 8);
        message[3] = (byte) bytes.length;
        System.arraycopy(bytes, 0, message, Handshake.HEADER, bytes.length);
        return message;
    }

    private static byte[] concatenate(List<byte[]> messages) {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        messages.forEach(all::writeBytes);
        return all.toByteArray();
    }

    private static void record(ByteArrayOutputStream wire, int type, byte[] body) {
        wire.write(type);
        wire.write(0x03);
        wire.write(0x03);
        wire.write(body.length >>> 8);
        wire.write(body.length & 0xff);
        wire.writeBytes(body);
    }

    /** Seals {@code plain} under {@code writer}, split into records of at most 16 KiB. */
    private static void sealed(ByteArrayOutputStream wire, RecordProtection writer, int type,
            byte[] plain) {
        int at = 0;
        do {
            int chunk = Math.min(RecordStream.MAX_PLAINTEXT, plain.length - at);
            try (Arena scratch = Arena.ofConfined()) {
                MemorySegment in = scratch.allocate(Math.max(1, chunk));
                MemorySegment.copy(plain, at, in, ValueLayout.JAVA_BYTE, 0, chunk);
                MemorySegment out = scratch.allocate(RecordProtection.sealedLength(chunk));
                int length = writer.seal((byte) type, in, 0, chunk, out, 0);
                wire.writeBytes(out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE));
            }
            at += chunk;
        } while (at < plain.length);
    }
}
