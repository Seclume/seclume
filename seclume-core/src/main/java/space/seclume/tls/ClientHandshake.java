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
        return handshake(transport, host, trust, null);
    }

    /**
     * The same, proving who the client is as well.
     *
     * <p>Mutual TLS. The server asks with a {@code CertificateRequest} and
     * this answers with the identity's certificate chain and a signature over
     * the transcript - made by the identity, from a private key that is never
     * a Java object. See {@link ClientIdentity}.
     *
     * <p>Passing an identity does not force anything: a server that does not
     * ask never sees it. Conversely a server that asks while there is none
     * gets an empty certificate list and decides for itself whether that is
     * acceptable, which is the behaviour RFC 8446 prescribes and is more
     * useful than refusing on the client side.
     */
    public static TlsConnection connect(Transport transport, String host, CertificateTrust trust,
            ClientIdentity identity) throws IOException {
        if (trust == null) {
            throw new IllegalArgumentException("no trust: call connectWithoutAuthenticating if "
                    + "that is really what is wanted, so that it is visible at the call site");
        }
        return handshake(transport, host, trust, identity);
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
        return handshake(transport, host, null, null);
    }

    /** The same without checking the server, but proving who we are. */
    public static TlsConnection connectWithoutAuthenticating(Transport transport, String host,
            ClientIdentity identity) throws IOException {
        return handshake(transport, host, null, identity);
    }

    /**
     * Connects, proves who the client is if asked, and offers one application
     * protocol.
     *
     * <p>Named separately rather than folded into the calls above because
     * ALPN changes what a failure means: a server that does not select the
     * protocol is refused here, loudly, instead of being talked to in a
     * language it did not agree to. Today that matters for exactly one
     * caller - TDS 8.0, where {@code tds/8.0} is how SQL Server knows what
     * arrived on its port.
     *
     * @param trust    the anchors, or null for encryption without authentication
     * @param identity a client certificate, or null
     * @param alpn     the protocol name to offer and to require back
     */
    public static TlsConnection connect(Transport transport, String host,
            CertificateTrust trust, ClientIdentity identity, String alpn) throws IOException {
        return handshake(transport, host, trust, identity, alpn);
    }

    private static TlsConnection handshake(Transport transport, String host,
            CertificateTrust trust, ClientIdentity identity) throws IOException {
        return handshake(transport, host, trust, identity, null);
    }

    private static TlsConnection handshake(Transport transport, String host,
            CertificateTrust trust, ClientIdentity identity, String alpn) throws IOException {
        RecordStream records = new RecordStream(transport);
        List<X509Certificate> serverChain = new ArrayList<>();
        boolean done = false;
        boolean presented = false;
        try (Arena arena = Arena.ofConfined();
                NativeP256 keyExchange = NativeP256.generate();
                space.seclume.crypto.HybridMlKem hybrid = postQuantum()
                        ? space.seclume.crypto.HybridMlKem.generate() : null;
                SecretScope shared = SecretScope.allocate(space.seclume.crypto.HybridMlKem.SECRET)) {

            // ---- ClientHello ------------------------------------------------
            MemorySegment random = arena.allocate(32);
            MemorySegment sessionId = arena.allocate(32);
            Entropy.fill(random);
            Entropy.fill(sessionId);          // 32 bytes: the middlebox-compatibility shape
            MemorySegment publicShare = arena.allocate(65);
            keyExchange.publicKey(publicShare);

            MemorySegment hello = arena.allocate(2048);
            int helloLength;
            if (hybrid != null) {
                // The hybrid first, P-256 beside it: a server without the
                // hybrid picks P-256 at once - this client does not retry.
                MemorySegment hybridShare = arena.allocate(space.seclume.crypto.HybridMlKem.CLIENT_SHARE);
                hybrid.publicShare(hybridShare);
                helloLength = ClientHello.write(hello, 0, random, sessionId,
                        new int[] {ClientHello.X25519MLKEM768, ClientHello.SECP256R1},
                        new MemorySegment[] {hybridShare, publicShare}, serverNameFor(host), alpn);
            } else {
                helloLength = ClientHello.write(hello, 0, random, sessionId,
                        ClientHello.SECP256R1, publicShare, serverNameFor(host), alpn);
            }
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
            ServerHelloFacts facts = readServerHello(serverHello, sessionId, hybrid != null);

            // ---- the handshake keys -----------------------------------------
            MemorySegment serverShare = serverHello.asSlice(facts.keyShareAt(), facts.keyShareLength());
            MemorySegment secret;
            if (facts.group() == ClientHello.X25519MLKEM768) {
                hybrid.derive(serverShare, shared.segment());
                secret = shared.segment().asSlice(0, space.seclume.crypto.HybridMlKem.SECRET);
            } else {
                secret = shared.segment().asSlice(0, 32);
                keyExchange.derive(serverShare, secret);
            }

            HashAlgorithm hash = facts.hash();
            int keyLength = facts.keyLength();
            try (TranscriptHash transcript = new TranscriptHash(hash);
                    KeySchedule schedule = KeySchedule.withoutPsk(hash);
                    SecretScope digest = SecretScope.allocate(hash.digestLength())) {

                transcript.update(hello, 0, helloLength);
                transcript.update(serverHello, 0, serverHelloLength);
                transcript.current(digest.segment(), 0);         // ClientHello..ServerHello

                schedule.deriveHandshakeSecret(secret);
                schedule.deriveHandshakeTrafficSecrets(digest.segment().asSlice(0, hash.digestLength()));
                records.readWith(RecordProtection.fromSecret(
                        hash, schedule.serverHandshakeTrafficSecret(), keyLength));

                // ---- the server's encrypted flight ------------------------
                byte[] certificateRequest = readServerFlight(records, transcript, schedule,
                        digest, hash, host, trust, serverChain, alpn);

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

                MemorySegment beforeFinished = throughServerFinished;
                if (certificateRequest != null) {
                    // One version of the identity for the whole of this: the
                    // chain sent and the key signing have to belong together,
                    // and a rotation on disk may land in between.
                    identity = identity == null ? null : identity.forHandshake();
                    // Our own Certificate and CertificateVerify go into the
                    // transcript before the Finished, so the hash the Finished
                    // is computed over is no longer the one the application
                    // secrets came from. Both are read out of the same buffer,
                    // which is safe only because those secrets were derived
                    // from it two statements ago.
                    sendClientCertificate(records, transcript, certificateRequest, identity);
                    if (identity != null) {
                        transcript.current(digest.segment(), 0);
                        sendCertificateVerify(records, transcript, identity,
                                digest.segment().asSlice(0, hash.digestLength()), arena);
                    }
                    transcript.current(digest.segment(), 0);
                    beforeFinished = digest.segment().asSlice(0, hash.digestLength());
                }
                presented = certificateRequest != null && identity != null;
                try {
                    sendFinished(records, schedule, beforeFinished, hash, arena);
                } catch (TlsAlertException alert) {
                    throw alert;
                } catch (IOException gone) {
                    throw refusedAfterCertificate(gone, presented);
                }

                // ---- and from here on, application keys --------------------
                records.readWith(RecordProtection.fromSecret(
                        hash, schedule.serverApplicationTrafficSecret(), keyLength));
                records.writeWith(RecordProtection.fromSecret(
                        hash, schedule.clientApplicationTrafficSecret(), keyLength));
            }
            TlsConnection connection = new TlsConnection(transport, records);
            // Kept for channel binding, which asks for the certificate long
            // after the handshake that checked it - and for the preflight
            // report, which has to be able to say what was actually agreed
            // rather than what was offered.
            connection.describe(serverChain.isEmpty() ? null : serverChain.get(0),
                    facts.cipherSuite());
            if (presented) {
                // In TLS 1.3 the server judges our certificate after our
                // Finished, so its refusal usually meets the first read.
                connection.certificatePresented();
            }
            done = true;
            return connection;
        } finally {
            if (!done) {
                records.close();
            }
        }
    }

    /**
     * A connection that dies right after our certificate went out.
     *
     * <p>A server that does not accept a client certificate - an issuer it
     * does not trust, an expired one, the wrong key usage - sends an alert and
     * closes. But it closes with our Finished still unread in its socket, and
     * a TCP stack answers that with a reset, which on the client throws away
     * the alert that had already arrived. What is left is "connection reset",
     * which sends everybody looking at the network. The certificate is the
     * likelier cause, so it is named; the original is kept as the cause.
     */
    static IOException refusedAfterCertificate(IOException gone, boolean presented) {
        if (!presented) {
            return gone;
        }
        return new IOException(gone.getMessage() + " - right after the client certificate was "
                + "sent, which is how a server refuses one: check that it trusts the "
                + "certificate's issuer, and that the certificate is valid and meant for "
                + "client authentication", gone);
    }

    /** What a ServerHello has to tell us, once it has been checked. */
    private record ServerHelloFacts(HashAlgorithm hash, int keyLength,
            long keyShareAt, int keyShareLength, String cipherSuite, int group) {
    }

    /**
     * Whether to offer the post-quantum hybrid: where OpenSSL 3.5 is there,
     * unless {@code -Dseclume.tls.postQuantum=false} says otherwise.
     */
    private static boolean postQuantum() {
        return !"false".equalsIgnoreCase(System.getProperty("seclume.tls.postQuantum"))
                && space.seclume.crypto.HybridMlKem.available();
    }

    private static ServerHelloFacts readServerHello(MemorySegment serverHello,
            MemorySegment sentSessionId, boolean offeredHybrid) throws IOException {
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
        long[] share = {0, 0, 0};
        boolean[] seen = {false, false};
        Handshake.extensions(serverHello, extensionsAt, extensionsLength[0], (type, at, length) -> {
            if (type == Handshake.EXTENSION_KEY_SHARE) {
                long[] out = new long[2];
                int group = Handshake.serverKeyShare(serverHello, at, out);
                if (group == ClientHello.SECP256R1 && out[1] == 65
                        || offeredHybrid && group == ClientHello.X25519MLKEM768
                                && out[1] == space.seclume.crypto.HybridMlKem.SERVER_SHARE) {
                    share[0] = out[0];
                    share[1] = out[1];
                    share[2] = group;
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
            throw new IOException("the server sent no usable key share for a group that was "
                    + "offered (" + (offeredHybrid ? "X25519MLKEM768 or P-256" : "P-256") + ")");
        }
        String name = suite == ClientHello.AES_256_GCM_SHA384
                ? "TLS_AES_256_GCM_SHA384" : "TLS_AES_128_GCM_SHA256";
        if (share[2] == ClientHello.X25519MLKEM768) {
            name += " with X25519MLKEM768";
        }
        return new ServerHelloFacts(hash, keyLength, share[0], (int) share[1], name,
                (int) share[2]);
    }

    /**
     * EncryptedExtensions, Certificate, CertificateVerify, an optional
     * CertificateRequest and Finished - however many records they arrive in,
     * and in whatever combination.
     *
     * @return the request context if a {@code CertificateRequest} arrived -
     *         normally empty, which is not the same as absent - or
     *         {@code null} if the server did not ask for a client certificate
     */
    private static byte[] readServerFlight(RecordStream records, TranscriptHash transcript,
            KeySchedule schedule, SecretScope digest, HashAlgorithm hash, String host,
            CertificateTrust trust, List<X509Certificate> chain, String alpn)
            throws IOException {
        try (HandshakeReassembler flight = new HandshakeReassembler(1 << 20)) {
            boolean[] finished = {false};
            byte[][] certificateRequest = {null};
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
                            case Handshake.ENCRYPTED_EXTENSIONS -> {
                                checkSelectedProtocol(message, at, length, alpn);
                                transcript.update(message, start, total);
                            }
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
                            case Handshake.CERTIFICATE_REQUEST -> {
                                // Only noted here. The answer belongs in the
                                // client's own flight, which is written once
                                // this one has been read to its end.
                                certificateRequest[0] =
                                        CertificateMessage.requestContext(message, at);
                                transcript.update(message, start, total);
                            }
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
            return certificateRequest[0];
        }
    }

    /**
     * Our certificate, or the absence of one, said out loud.
     *
     * <p>An empty list is a valid answer and the only correct one when there
     * is no identity: the server asked, and silence would hang the handshake
     * while a refusal here would take a decision that belongs to the server.
     */
    private static void sendClientCertificate(RecordStream records, TranscriptHash transcript,
            byte[] context, ClientIdentity identity) throws IOException {
        List<byte[]> chain = identity == null ? List.of() : identity.chain();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment message = arena.allocate(CertificateMessage.sizeFor(context, chain));
            int length = CertificateMessage.write(message, context, chain);
            records.write((byte) 22, message, 0, length);
            transcript.update(message, 0, length);
        }
    }

    /**
     * The proof that we hold the key belonging to that certificate.
     *
     * <p>Signed over the transcript up to and including the Certificate just
     * sent - which is why the hash is taken by the caller before this message
     * is added to it, exactly the way the server's own CertificateVerify is
     * handled a few lines above.
     */
    private static void sendCertificateVerify(RecordStream records, TranscriptHash transcript,
            ClientIdentity identity, MemorySegment transcriptHash, Arena arena)
            throws IOException {
        byte[] content = HandshakeSignature.content(false,
                transcriptHash.toArray(ValueLayout.JAVA_BYTE));
        byte[] signature;
        try {
            signature = identity.sign(content);
        } catch (RuntimeException e) {
            throw new IOException("signing the client CertificateVerify failed: "
                    + e.getMessage(), e);
        }
        MemorySegment message = arena.allocate(Handshake.HEADER + 4L + signature.length);
        int length = CertificateVerifyMessage.write(message, identity.signatureScheme(), signature);
        records.write((byte) 22, message, 0, length);
        transcript.update(message, 0, length);
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

    /**
     * Did the server agree to the protocol we offered.
     *
     * <p>Only asked when one was offered. A server that selects nothing has
     * either ignored ALPN or does not support what was asked for, and in both
     * cases carrying on would mean speaking a protocol the other end never
     * agreed to - which for TDS 8.0 shows up as a connection that hangs
     * rather than as an error, because the server is waiting for something
     * else entirely.
     */
    private static void checkSelectedProtocol(MemorySegment message, long body, int length,
            String alpn) throws IOException {
        if (alpn == null) {
            return;
        }
        if (length < 2) {
            throw new IOException("the server sent no extensions, so it did not select \""
                    + alpn + "\"");
        }
        int extensionsLength = Handshake.u16(message, body);
        String[] selected = {null};
        Handshake.extensions(message, body + 2, extensionsLength, (type, at, size) -> {
            if (type != ClientHello.EXTENSION_ALPN || size < 3) {
                return;
            }
            // ProtocolNameList: two bytes of list length, then one length-
            // prefixed name. Exactly one, because exactly one was offered.
            int nameLength = message.get(ValueLayout.JAVA_BYTE, at + 2) & 0xff;
            if (nameLength > size - 3) {
                return;
            }
            StringBuilder name = new StringBuilder(nameLength);
            for (int i = 0; i < nameLength; i++) {
                name.append((char) (message.get(ValueLayout.JAVA_BYTE, at + 3 + i) & 0xff));
            }
            selected[0] = name.toString();
        });
        if (!alpn.equals(selected[0])) {
            throw new IOException("this client offered the application protocol \"" + alpn
                    + "\" and the server answered with "
                    + (selected[0] == null ? "none" : "\"" + selected[0] + "\"")
                    + " - carrying on would mean speaking a protocol it never agreed to");
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
