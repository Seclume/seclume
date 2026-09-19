package space.seclume.tls;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.NativeP256;
import space.seclume.internal.Entropy;
import space.seclume.internal.Transport;
import space.seclume.secret.SecretScope;

/**
 * A complete TLS 1.3 client handshake, from ClientHello to the first
 * application record - the piece that turns everything else in this package
 * into a connection.
 *
 * <p>What it does not do is as much the design as what it does. There is no
 * PSK, no session resumption, no 0-RTT, no client certificate, no
 * HelloRetryRequest and one key-exchange group. Each of those is a branch
 * with its own transcript rules, and a branch that exists but is never
 * exercised is worse than one that is refused out loud - so the ones that
 * are missing say so when a server asks for them.
 *
 * <p><b>The transcript is the thing to be careful with.</b> Four of the
 * steps below take a hash of the handshake so far, and each wants it at a
 * different point: the traffic secrets after ServerHello, the server's
 * signature over everything up to and including Certificate, its Finished
 * over everything up to and including CertificateVerify, and the
 * application secrets and our own Finished over everything up to and
 * including its Finished. A message added to the transcript one step too
 * early still produces a perfectly plausible hash, and the only sign is a
 * peer that rejects a Finished it should have accepted. The order here is
 * therefore deliberate and commented at each step rather than left to be
 * re-derived.
 *
 * <p>Everything secret - the shared secret, every traffic secret, the
 * Finished keys - lives in native memory from the moment it exists, in
 * {@link KeySchedule} and {@link RecordProtection}. That is the reason this
 * exists instead of an {@code SSLEngine}.
 */
public final class ClientHandshake {

    /** RFC 8446 section 4.1.3: a ServerHello carrying this random is a HelloRetryRequest. */
    private static final byte[] HELLO_RETRY_REQUEST = {
        (byte) 0xCF, (byte) 0x21, (byte) 0xAD, (byte) 0x74, (byte) 0xE5, (byte) 0x9A,
        (byte) 0x61, (byte) 0x11, (byte) 0xBE, (byte) 0x1D, (byte) 0x8C, (byte) 0x02,
        (byte) 0x1E, (byte) 0x65, (byte) 0xB8, (byte) 0x91, (byte) 0xC2, (byte) 0xA2,
        (byte) 0x11, (byte) 0x16, (byte) 0x7A, (byte) 0xBB, (byte) 0x8C, (byte) 0x5E,
        (byte) 0x07, (byte) 0x9E, (byte) 0x09, (byte) 0xE2, (byte) 0xC8, (byte) 0xA8,
        (byte) 0x33, (byte) 0x9C};

    private ClientHandshake() {
    }

    /**
     * Connects and authenticates the server against {@code trust}.
     *
     * @param transport an open connection to the server; it becomes the
     *                  property of the returned {@link TlsConnection}
     * @param host      the name the connection was made to - used for SNI and
     *                  checked against the certificate. An IP address is
     *                  allowed and simply sends no SNI
     */
    public static TlsConnection connect(Transport transport, String host, CertificateTrust trust)
            throws IOException {
        if (trust == null) {
            throw new IllegalArgumentException("no trust: call connectWithoutAuthenticating if "
                    + "that is really what is wanted, so that it is visible at the call site");
        }
        return handshake(transport, host, trust);
    }

    /**
     * Connects <b>without checking who answered</b> - encryption against a
     * passive listener, nothing against an active one.
     *
     * <p>Named the long way round on purpose. It exists because the drivers
     * already offer a {@code require} mode that does exactly this, and
     * because a test fixture with a self-signed certificate needs it; it
     * should never be what a caller reaches for without deciding to.
     */
    public static TlsConnection connectWithoutAuthenticating(Transport transport, String host)
            throws IOException {
        return handshake(transport, host, null);
    }

    private static TlsConnection handshake(Transport transport, String host, CertificateTrust trust)
            throws IOException {
        RecordStream records = new RecordStream(transport);
        boolean done = false;
        try (Arena arena = Arena.ofConfined();
                NativeP256 keyExchange = NativeP256.generate();
                SecretScope shared = SecretScope.allocate(32)) {

            // ---- ClientHello ------------------------------------------------
            MemorySegment random = arena.allocate(32);
            MemorySegment sessionId = arena.allocate(32);
            Entropy.fill(random);
            Entropy.fill(sessionId);          // 32 bytes: the middlebox-compatibility shape
            MemorySegment publicShare = arena.allocate(65);
            keyExchange.publicKey(publicShare);

            MemorySegment hello = arena.allocate(1024);
            int helloLength = ClientHello.write(hello, 0, random, sessionId,
                    ClientHello.SECP256R1, publicShare, serverNameFor(host));
            records.write((byte) 22, hello, 0, helloLength);

            // ---- ServerHello ------------------------------------------------
            RecordStream.Incoming first = records.next();
            if (first.contentType() != 22
                    || Handshake.type(first.data(), first.offset()) != Handshake.SERVER_HELLO) {
                throw new IOException("the server answered the ClientHello with something that "
                        + "is not a ServerHello");
            }
            int serverHelloLength = Handshake.totalLength(first.data(), first.offset());
            if (serverHelloLength != first.length()) {
                throw new IOException("the ServerHello does not fill its record - this client "
                        + "does not reassemble a split ServerHello");
            }
            MemorySegment serverHello = arena.allocate(serverHelloLength);
            MemorySegment.copy(first.data(), first.offset(), serverHello, 0, serverHelloLength);
            ServerHelloFacts facts = readServerHello(serverHello, sessionId);

            // ---- the handshake keys -----------------------------------------
            keyExchange.derive(serverHello.asSlice(facts.keyShareAt(), facts.keyShareLength()),
                    shared.segment());

            HashAlgorithm hash = facts.hash();
            int keyLength = facts.keyLength();
            try (TranscriptHash transcript = new TranscriptHash(hash);
                    KeySchedule schedule = KeySchedule.withoutPsk(hash);
                    SecretScope digest = SecretScope.allocate(hash.digestLength())) {

                transcript.update(hello, 0, helloLength);
                transcript.update(serverHello, 0, serverHelloLength);
                transcript.current(digest.segment(), 0);         // ClientHello..ServerHello

                schedule.deriveHandshakeSecret(shared.segment());
                schedule.deriveHandshakeTrafficSecrets(digest.segment().asSlice(0, hash.digestLength()));
                records.readWith(RecordProtection.fromSecret(
                        hash, schedule.serverHandshakeTrafficSecret(), keyLength));

                // ---- the server's encrypted flight ------------------------
                readServerFlight(records, transcript, schedule, digest, hash, host, trust);

                // Everything through the server's Finished: the context for both
                // the application secrets and our own Finished.
                transcript.current(digest.segment(), 0);
                MemorySegment throughServerFinished =
                        digest.segment().asSlice(0, hash.digestLength());
                schedule.deriveMasterSecret();
                schedule.deriveApplicationTrafficSecrets(throughServerFinished);

                // ---- our Finished, still under the handshake key -----------
                records.writeChangeCipherSpec();
                records.writeWith(RecordProtection.fromSecret(
                        hash, schedule.clientHandshakeTrafficSecret(), keyLength));
                sendFinished(records, schedule, throughServerFinished, hash, arena);

                // ---- and from here on, application keys --------------------
                records.readWith(RecordProtection.fromSecret(
                        hash, schedule.serverApplicationTrafficSecret(), keyLength));
                records.writeWith(RecordProtection.fromSecret(
                        hash, schedule.clientApplicationTrafficSecret(), keyLength));
            }
            TlsConnection connection = new TlsConnection(transport, records);
            done = true;
            return connection;
        } finally {
            if (!done) {
                records.close();
            }
        }
    }

    /** What a ServerHello has to tell us, once it has been checked. */
    private record ServerHelloFacts(HashAlgorithm hash, int keyLength,
            long keyShareAt, int keyShareLength) {
    }

    private static ServerHelloFacts readServerHello(MemorySegment serverHello,
            MemorySegment sentSessionId) throws IOException {
        long body = Handshake.HEADER;
        if (serverHello.asSlice(Handshake.randomOffset(body), 32)
                .mismatch(MemorySegment.ofArray(HELLO_RETRY_REQUEST)) == -1) {
            throw new IOException("the server asked for a different key share "
                    + "(HelloRetryRequest); this client offers one group and does not retry");
        }
        int sessionLength = Handshake.sessionIdLength(serverHello, body);
        if (sessionLength != sentSessionId.byteSize()
                || serverHello.asSlice(Handshake.sessionIdOffset(body), sessionLength)
                        .mismatch(sentSessionId) != -1) {
            throw new IOException("the server echoed a different session id than the one sent - "
                    + "something between us is not passing the handshake through unchanged");
        }

        int suite = Handshake.cipherSuite(serverHello, body);
        HashAlgorithm hash = switch (suite) {
            case ClientHello.AES_128_GCM_SHA256 -> HashAlgorithm.SHA_256;
            case ClientHello.AES_256_GCM_SHA384 -> HashAlgorithm.SHA_384;
            default -> throw new IOException("the server chose cipher suite 0x"
                    + Integer.toHexString(suite) + ", which was not offered");
        };
        int keyLength = suite == ClientHello.AES_256_GCM_SHA384 ? 32 : 16;

        int[] extensionsLength = new int[1];
        long extensionsAt = Handshake.serverHelloExtensions(serverHello, body, extensionsLength);
        long[] share = {0, 0};
        boolean[] seen = {false, false};
        Handshake.extensions(serverHello, extensionsAt, extensionsLength[0], (type, at, length) -> {
            if (type == Handshake.EXTENSION_KEY_SHARE) {
                long[] out = new long[2];
                int group = Handshake.serverKeyShare(serverHello, at, out);
                if (group == ClientHello.SECP256R1 && out[1] == 65) {
                    share[0] = out[0];
                    share[1] = out[1];
                    seen[0] = true;
                }
            } else if (type == Handshake.EXTENSION_SUPPORTED_VERSIONS
                    && Handshake.selectedVersion(serverHello, at) == 0x0304) {
                seen[1] = true;
            }
        });
        if (!seen[1]) {
            throw new IOException("the server did not select TLS 1.3 - the header version means "
                    + "nothing, and supported_versions did not say 0x0304");
        }
        if (!seen[0]) {
            throw new IOException("the server sent no usable P-256 key share");
        }
        return new ServerHelloFacts(hash, keyLength, share[0], (int) share[1]);
    }

    /**
     * EncryptedExtensions, Certificate, CertificateVerify and Finished -
     * however many records they arrive in, and in whatever combination.
     */
    private static void readServerFlight(RecordStream records, TranscriptHash transcript,
            KeySchedule schedule, SecretScope digest, HashAlgorithm hash, String host,
            CertificateTrust trust) throws IOException {
        try (HandshakeReassembler flight = new HandshakeReassembler(1 << 20)) {
            List<X509Certificate> chain = new ArrayList<>();
            boolean[] finished = {false};
            IOException[] failure = {null};

            while (!finished[0] && failure[0] == null) {
                RecordStream.Incoming record = records.next();
                if (record.contentType() != 22) {
                    throw new IOException("a record of type " + record.contentType()
                            + " arrived during the server's handshake flight");
                }
                flight.append(record.data(), record.offset(), record.length());
                flight.drain((type, at, length) -> {
                    if (failure[0] != null) {
                        return;
                    }
                    try {
                        MemorySegment message = flight.segment();
                        int total = Handshake.HEADER + length;
                        long start = at - Handshake.HEADER;
                        switch (type) {
                            case Handshake.ENCRYPTED_EXTENSIONS ->
                                    transcript.update(message, start, total);
                            case Handshake.CERTIFICATE -> {
                                readCertificates(message, at, length, chain);
                                authenticate(chain, host, trust);
                                transcript.update(message, start, total);
                            }
                            case Handshake.CERTIFICATE_VERIFY -> {
                                // Signed over everything up to and including Certificate,
                                // so the hash is taken before this message is added.
                                transcript.current(digest.segment(), 0);
                                verifySignature(chain, message, at,
                                        digest.segment().asSlice(0, hash.digestLength()));
                                transcript.update(message, start, total);
                            }
                            case Handshake.FINISHED -> {
                                // Likewise: over everything up to and including
                                // CertificateVerify.
                                transcript.current(digest.segment(), 0);
                                if (!Finished.verify(schedule,
                                        schedule.serverHandshakeTrafficSecret(),
                                        digest.segment().asSlice(0, hash.digestLength()),
                                        message, at, length)) {
                                    throw new IOException("the server's Finished does not match "
                                            + "the handshake we saw - somebody changed a message "
                                            + "in flight");
                                }
                                transcript.update(message, start, total);
                                finished[0] = true;
                            }
                            case Handshake.CERTIFICATE_REQUEST -> throw new IOException(
                                    "the server asked for a client certificate, which this "
                                            + "client does not have");
                            default -> throw new IOException("handshake message of type " + type
                                    + " is not expected in a server's first flight");
                        }
                    } catch (IOException e) {
                        failure[0] = e;
                    }
                });
            }
            if (failure[0] != null) {
                throw failure[0];
            }
        }
    }

    private static void readCertificates(MemorySegment message, long body, int length,
            List<X509Certificate> chain) throws IOException {
        List<CertificateException> problem = new ArrayList<>(1);
        CertificateMessage.certificates(message, body, length, (at, size, extAt, extLength) -> {
            try {
                chain.add(Certificates.parse(message, at, size));
            } catch (CertificateException e) {
                problem.add(e);
            }
        });
        if (!problem.isEmpty()) {
            throw new IOException("the server sent a certificate that cannot be read",
                    problem.get(0));
        }
        if (chain.isEmpty()) {
            throw new IOException("the server sent an empty certificate list");
        }
    }

    private static void authenticate(List<X509Certificate> chain, String host,
            CertificateTrust trust) throws IOException {
        if (trust == null) {
            return;                           // connectWithoutAuthenticating, said out loud there
        }
        try {
            trust.checkServer(chain, host);
        } catch (CertificateException e) {
            throw new IOException("the server's certificate was refused: " + e.getMessage(), e);
        }
    }

    private static void verifySignature(List<X509Certificate> chain, MemorySegment message,
            long body, MemorySegment transcriptHash) throws IOException {
        if (chain.isEmpty()) {
            throw new IOException("a CertificateVerify arrived before any certificate");
        }
        int scheme = CertificateVerifyMessage.signatureScheme(message, body);
        int length = CertificateVerifyMessage.signatureLength(message, body);
        long at = CertificateVerifyMessage.signatureOffset(body);
        byte[] signature = message.asSlice(at, length).toArray(ValueLayout.JAVA_BYTE);
        byte[] hash = transcriptHash.toArray(ValueLayout.JAVA_BYTE);
        if (!HandshakeSignature.verifyServer(chain.get(0).getPublicKey(), hash, scheme, signature)) {
            throw new IOException("the server's CertificateVerify does not verify against its "
                    + "own certificate - it does not hold the key it presented");
        }
    }

    private static void sendFinished(RecordStream records, KeySchedule schedule,
            MemorySegment transcriptHash, HashAlgorithm hash, Arena arena) throws IOException {
        int length = hash.digestLength();
        MemorySegment message = arena.allocate(Handshake.HEADER + length);
        message.set(ValueLayout.JAVA_BYTE, 0, (byte) Handshake.FINISHED);
        message.set(ValueLayout.JAVA_BYTE, 1, (byte) 0);
        message.set(ValueLayout.JAVA_BYTE, 2, (byte) (length >>> 8));
        message.set(ValueLayout.JAVA_BYTE, 3, (byte) length);
        Finished.compute(schedule, schedule.clientHandshakeTrafficSecret(), transcriptHash,
                message.asSlice(Handshake.HEADER, length));
        records.write((byte) 22, message, 0, Handshake.HEADER + length);
    }

    /** SNI carries names, never addresses - an IP there is a protocol error. */
    private static String serverNameFor(String host) {
        if (host == null || host.isBlank()) {
            return null;
        }
        boolean looksLikeAddress = host.indexOf(':') >= 0
                || host.chars().allMatch(c -> (c >= '0' && c <= '9') || c == '.');
        return looksLikeAddress ? null : host;
    }
}
