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
import space.seclume.crypto.NativeEcdh;
import space.seclume.internal.Entropy;
import space.seclume.internal.Transport;
import space.seclume.secret.SecretScope;

/**
 * A complete TLS 1.3 client handshake, from ClientHello to the first
 * application record - the piece that turns everything else in this package
 * into a connection. A server that answers with TLS 1.2 is carried on by
 * {@link Tls12Handshake}, in a deliberately small profile described there.
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

    /**
     * RFC 8446 section 4.1.3: a TLS 1.3 server that negotiates TLS 1.2 ends its
     * random with these eight bytes. Seen while we offered TLS 1.3, it means
     * somebody in between removed our offer - a downgrade, refused.
     */
    private static final byte[] DOWNGRADE_TLS12 = {
        0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};

    private ClientHandshake() {
    }

    /**
     * Which versions this client offers by default: TLS 1.3 and the TLS 1.2
     * profile, unless {@code -Dseclume.tls.tls12=false} keeps it to TLS 1.3.
     */
    static ClientHello.Offer defaultOffer() {
        return "false".equalsIgnoreCase(System.getProperty("seclume.tls.tls12"))
                ? ClientHello.Offer.TLS13 : ClientHello.Offer.TLS13_AND_12;
    }

    /**
     * Connects offering exactly the versions given - {@link ClientHello.Offer#TLS12}
     * for TDS 7.4, whose handshake inside the pre-login packets cannot be TLS 1.3.
     */
    public static TlsConnection connect(Transport transport, String host,
            CertificateTrust trust, ClientIdentity identity, String alpn,
            ClientHello.Offer offer) throws IOException {
        return handshake(transport, host, trust, identity, alpn, offer);
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
        return handshake(transport, host, trust, identity, alpn, defaultOffer());
    }

    private static TlsConnection handshake(Transport transport, String host,
            CertificateTrust trust, ClientIdentity identity, String alpn,
            ClientHello.Offer offer) throws IOException {
        boolean offers13 = offer != ClientHello.Offer.TLS12;
        boolean offers12 = offer != ClientHello.Offer.TLS13;
        RecordStream records = new RecordStream(transport);
        List<X509Certificate> serverChain = new ArrayList<>();
        boolean done = false;
        boolean presented = false;
        boolean helloAccepted = false;
        NativeEcdh retryKey = null;
        try (Arena arena = Arena.ofConfined();
                NativeEcdh p256 = offers13 ? NativeEcdh.generate(NativeEcdh.Group.P256) : null;
                NativeEcdh x25519 = offers13 ? NativeEcdh.generate(NativeEcdh.Group.X25519) : null;
                space.seclume.crypto.HybridMlKem hybrid = offers13 && postQuantum()
                        ? space.seclume.crypto.HybridMlKem.generate() : null;
                SecretScope shared = SecretScope.allocate(space.seclume.crypto.HybridMlKem.SECRET);
                HandshakeReassembler plainFlight = new HandshakeReassembler(1 << 20)) {

            // ---- ClientHello ------------------------------------------------
            MemorySegment random = arena.allocate(32);
            MemorySegment sessionId = arena.allocate(32);
            Entropy.fill(random);
            Entropy.fill(sessionId);          // 32 bytes: the middlebox-compatibility shape

            // Offered in this order: the post-quantum hybrid, X25519, P-256 and
            // P-384. Shares go with the first three, so that nearly every server
            // answers at once; P-384 costs nothing unless a server asks for it
            // with a HelloRetryRequest.
            int[] supportedGroups = hybrid != null
                    ? new int[] {ClientHello.X25519MLKEM768, ClientHello.X25519,
                            ClientHello.SECP256R1, ClientHello.SECP384R1}
                    : new int[] {ClientHello.X25519, ClientHello.SECP256R1, ClientHello.SECP384R1};
            int[] shareGroups;
            MemorySegment[] shares;
            if (!offers13) {
                shareGroups = new int[0];
                shares = new MemorySegment[0];
            } else {
                MemorySegment x25519Share = publicKey(x25519, arena);
                MemorySegment p256Share = publicKey(p256, arena);
                if (hybrid != null) {
                    MemorySegment hybridShare =
                            arena.allocate(space.seclume.crypto.HybridMlKem.CLIENT_SHARE);
                    hybrid.publicShare(hybridShare);
                    shareGroups = new int[] {ClientHello.X25519MLKEM768, ClientHello.X25519,
                            ClientHello.SECP256R1};
                    shares = new MemorySegment[] {hybridShare, x25519Share, p256Share};
                } else {
                    shareGroups = new int[] {ClientHello.X25519, ClientHello.SECP256R1};
                    shares = new MemorySegment[] {x25519Share, p256Share};
                }
            }
            MemorySegment hello = arena.allocate(4096);
            int helloLength = ClientHello.write(hello, 0, random, sessionId, supportedGroups,
                    shareGroups, shares, serverNameFor(host), alpn, offer, null);
            records.write((byte) 22, hello, 0, helloLength);

            // ---- ServerHello ------------------------------------------------
            MemorySegment serverHello = readServerHelloMessage(records, plainFlight, arena);
            int serverHelloLength = (int) serverHello.byteSize();

            // ---- a HelloRetryRequest, at most one ---------------------------
            MemorySegment firstHello = null;
            MemorySegment retryRequest = null;
            int retrySuite = -1;
            if (offers13 && isHelloRetryRequest(serverHello)) {
                if (plainFlight.buffered() > 0) {
                    throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                            "handshake bytes followed the HelloRetryRequest");
                }
                HelloRetry retry = readHelloRetry(serverHello, sessionId, supportedGroups,
                        shareGroups);
                records.helloRetried();
                retrySuite = retry.suite();
                firstHello = arena.allocate(helloLength);
                MemorySegment.copy(hello, 0, firstHello, 0, helloLength);
                retryRequest = serverHello;
                if (retry.group() >= 0) {
                    retryKey = NativeEcdh.generate(NativeEcdh.Group.of(retry.group()));
                    shareGroups = new int[] {retry.group()};
                    shares = new MemorySegment[] {publicKey(retryKey, arena)};
                }
                hello = arena.allocate(4096 + (retry.cookie() == null ? 0
                        : retry.cookie().byteSize()));
                helloLength = ClientHello.write(hello, 0, random, sessionId, supportedGroups,
                        shareGroups, shares, serverNameFor(host), alpn, offer, retry.cookie());
                records.write((byte) 22, hello, 0, helloLength);
                serverHello = readServerHelloMessage(records, plainFlight, arena);
                serverHelloLength = (int) serverHello.byteSize();
                if (isHelloRetryRequest(serverHello)) {
                    throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                            "a second HelloRetryRequest");
                }
                if (negotiatedVersion(serverHello, true, false) != 0x0304) {
                    throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                            "the ServerHello after a HelloRetryRequest is not TLS 1.3");
                }
            }

            if (negotiatedVersion(serverHello, offers13, offers12) == 0x0303) {
                if (offers13) {
                    refuseDowngrade(serverHello);
                }
                helloAccepted = true;
                TlsConnection connection = tls12(records, plainFlight, serverHello, hello,
                        helloLength, random, host, trust, identity, alpn, serverChain, arena);
                done = true;
                return connection;
            }
            if (plainFlight.buffered() > 0) {
                // RFC 8446 section 5.1: no handshake message may span a key
                // change, and the ServerHello is followed by one.
                throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                        "handshake bytes followed the TLS 1.3 ServerHello in the clear");
            }
            ServerHelloFacts facts = readServerHello(serverHello, sessionId, shareGroups);
            if (retrySuite >= 0 && facts.suite() != retrySuite) {
                throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                        "the ServerHello chose another cipher suite than its HelloRetryRequest");
            }
            helloAccepted = true;

            // ---- the handshake keys -----------------------------------------
            MemorySegment serverShare = serverHello.asSlice(facts.keyShareAt(), facts.keyShareLength());
            MemorySegment secret;
            try {
                if (facts.group() == ClientHello.X25519MLKEM768 && hybrid != null) {
                    hybrid.derive(serverShare, shared.segment());
                    secret = shared.segment().asSlice(0, space.seclume.crypto.HybridMlKem.SECRET);
                } else {
                    NativeEcdh key = facts.group() == ClientHello.X25519 && retryKey == null ? x25519
                            : facts.group() == ClientHello.SECP256R1 && retryKey == null ? p256
                            : retryKey;
                    if (key == null || key.group().id() != facts.group()) {
                        throw new IllegalStateException("no key for group " + facts.group());
                    }
                    secret = shared.segment().asSlice(0, key.group().secretSize());
                    key.derive(serverShare, secret);
                }
            } catch (IllegalArgumentException | IllegalStateException badShare) {
                // A point off the curve, a low-order X25519 key, an ML-KEM
                // ciphertext that does not decapsulate: the peer's share is
                // refused as TLS refuses it, not as an unchecked exception out
                // of the login path.
                TlsProtocolException refused = new TlsProtocolException(
                        TlsAlertException.ILLEGAL_PARAMETER,
                        "the server's key share was refused: " + badShare.getMessage());
                refused.initCause(badShare);
                throw refused;
            }

            HashAlgorithm hash = facts.hash();
            int keyLength = facts.keyLength();
            try (TranscriptHash transcript = new TranscriptHash(hash);
                    KeySchedule schedule = KeySchedule.withoutPsk(hash);
                    SecretScope digest = SecretScope.allocate(hash.digestLength())) {

                if (retryRequest != null) {
                    // RFC 8446 section 4.4.1: the first ClientHello is replaced by
                    // its hash, and the HelloRetryRequest follows it.
                    transcript.update(firstHello, 0, (int) firstHello.byteSize());
                    transcript.substituteWithMessageHash();
                    transcript.update(retryRequest, 0, (int) retryRequest.byteSize());
                }
                transcript.update(hello, 0, helloLength);
                transcript.update(serverHello, 0, serverHelloLength);
                transcript.current(digest.segment(), 0);         // ClientHello..ServerHello

                schedule.deriveHandshakeSecret(secret);
                schedule.deriveHandshakeTrafficSecrets(digest.segment().asSlice(0, hash.digestLength()));
                records.readWith(RecordProtection.fromSecret(
                        hash, schedule.serverHandshakeTrafficSecret(), keyLength));
                // Our handshake key is in force from here on, although the
                // first record under it is our Finished: an alert sent while
                // the server's flight is being refused has to go out under
                // it, because that is the key the server now reads with.
                records.writeWith(RecordProtection.fromSecret(
                        hash, schedule.clientHandshakeTrafficSecret(), keyLength));

                // ---- the server's encrypted flight ------------------------
                ServerFlight flight = readServerFlight(records, transcript, schedule,
                        digest, hash, host, trust, serverChain, alpn);
                byte[] certificateRequest = flight.certificateRequest();
                // The order above already makes this impossible to reach.
                // It is here so that a later change to that order - a PSK
                // branch, a resumption - cannot quietly bring back the
                // connection nobody authenticated.
                requireAuthenticatedServer(serverChain, flight.signatureVerified());

                // Everything through the server's Finished: the context for both
                // the application secrets and our own Finished.
                transcript.current(digest.segment(), 0);
                MemorySegment throughServerFinished =
                        digest.segment().asSlice(0, hash.digestLength());
                schedule.deriveMasterSecret();
                schedule.deriveApplicationTrafficSecrets(throughServerFinished);

                // ---- our Finished, still under the handshake key -----------
                records.writeChangeCipherSpec();

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
            records.established();
            TlsConnection connection = new TlsConnection(transport, records);
            // Kept for channel binding, which asks for the certificate long
            // after the handshake that checked it - and for the preflight
            // report, which has to be able to say what was actually agreed
            // rather than what was offered.
            connection.describe(serverChain.isEmpty() ? null : serverChain.get(0), "TLSv1.3",
                    facts.cipherSuite());
            if (presented) {
                // In TLS 1.3 the server judges our certificate after our
                // Finished, so its refusal usually meets the first read.
                connection.certificatePresented();
            }
            done = true;
            return connection;
        } catch (TlsProtocolException refused) {
            // Say why before hanging up; the server otherwise sees a reset.
            records.abort(refused.alert());
            if (!helloAccepted && (refused.alert() == TlsAlertException.PROTOCOL_VERSION
                    || refused.alert() == TlsAlertException.HANDSHAKE_FAILURE)) {
                throw new TlsVersionRefused(refused);    // TLS 1.2 chosen, or a HelloRetryRequest
            }
            throw refused;
        } catch (TlsAlertException | java.io.EOFException | java.net.SocketException gone) {
            // Before a ServerHello the server has judged nothing but the
            // ClientHello: no certificate has gone either way. Whatever it
            // answers - handshake_failure from OpenSSL and the JDK,
            // protocol_version, unexpected_message from the JDK without a
            // common group, or Schannel's silent close - means "not this TLS".
            if (!helloAccepted) {
                throw new TlsVersionRefused(gone);
            }
            throw gone;
        } catch (IndexOutOfBoundsException truncated) {
            // A length field that points past the message it is in. The
            // segment's bounds check stopped the read; what is left is to
            // say so as TLS does, rather than let an unchecked exception from
            // an unauthenticated peer escape into the caller's login path.
            records.abort(TlsAlertException.DECODE_ERROR);
            TlsProtocolException refused = new TlsProtocolException(TlsAlertException.DECODE_ERROR,
                    "a handshake message is shorter than its own length fields say");
            refused.initCause(truncated);
            throw refused;
        } finally {
            if (retryKey != null) {
                retryKey.close();
            }
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

    /**
     * Which version the ServerHello chose: {@code supported_versions} if it is
     * there, and then it has to say TLS 1.3; the header's {@code legacy_version}
     * otherwise, and then it has to say TLS 1.2 (RFC 8446 section 4.2.1).
     */
    private static int negotiatedVersion(MemorySegment serverHello, boolean offers13,
            boolean offers12) throws IOException {
        long body = Handshake.HEADER;
        int[] selected = {-1};
        long extensionsField = Handshake.sessionIdOffset(body)
                + Handshake.sessionIdLength(serverHello, body) + 3;
        if (extensionsField + 2 <= serverHello.byteSize()) {
            int extensionsLength = Handshake.u16(serverHello, extensionsField);
            long at = extensionsField + 2;
            long end = Math.min(serverHello.byteSize(), at + extensionsLength);
            while (end - at >= 4) {
                int type = Handshake.u16(serverHello, at);
                int length = Handshake.u16(serverHello, at + 2);
                if (type == Handshake.EXTENSION_SUPPORTED_VERSIONS && length == 2
                        && at + 6 <= end) {
                    selected[0] = Handshake.selectedVersion(serverHello, at + 4);
                }
                at += 4 + length;
            }
        }
        if (selected[0] == 0x0304 && offers13) {
            return 0x0304;
        }
        if (selected[0] >= 0) {
            throw new TlsProtocolException(selected[0] == 0x0303
                            ? TlsAlertException.ILLEGAL_PARAMETER : TlsAlertException.PROTOCOL_VERSION,
                    "the server's supported_versions says 0x" + Integer.toHexString(selected[0])
                            + ", which was not offered");
        }
        int legacy = Handshake.u16(serverHello, body);
        if (legacy == 0x0303 && offers12) {
            return 0x0303;
        }
        throw new TlsProtocolException(TlsAlertException.PROTOCOL_VERSION,
                "the server did not select "
                        + (offers12 ? (offers13 ? "TLS 1.3 or TLS 1.2" : "TLS 1.2") : "TLS 1.3")
                        + " - its ServerHello says 0x" + Integer.toHexString(legacy)
                        + " and no supported_versions");
    }

    /** The RFC 8446 downgrade sentinel, refused when TLS 1.3 was on offer. */
    private static void refuseDowngrade(MemorySegment serverHello) throws TlsProtocolException {
        long tail = Handshake.randomOffset(Handshake.HEADER) + 24;
        if (serverHello.asSlice(tail, 8).mismatch(MemorySegment.ofArray(DOWNGRADE_TLS12)) == -1) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the server negotiated TLS 1.2 and its random says it supports TLS 1.3 - "
                            + "somebody between us removed TLS 1.3 from the ClientHello");
        }
    }

    /** The TLS 1.2 path, from a checked ServerHello to an established connection. */
    private static TlsConnection tls12(RecordStream records, HandshakeReassembler plainFlight,
            MemorySegment serverHello, MemorySegment hello, int helloLength,
            MemorySegment clientRandom, String host,
            CertificateTrust trust, ClientIdentity identity, String alpn,
            List<X509Certificate> serverChain, Arena arena) throws IOException {
        records.tls12();
        long body = Handshake.HEADER;
        Tls12Handshake.Suite suite = Tls12Handshake.suite(Handshake.cipherSuite(serverHello, body));
        long compression = Handshake.sessionIdOffset(body)
                + Handshake.sessionIdLength(serverHello, body) + 2;
        if (serverHello.get(ValueLayout.JAVA_BYTE, compression) != 0) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the ServerHello names a compression method; none was offered");
        }
        Tls12Handshake.HelloExtensions extensions = Tls12Handshake.readServerHelloExtensions(
                serverHello, compression + 1, serverNameFor(host) != null, alpn);
        MemorySegment serverRandom = serverHello.asSlice(Handshake.randomOffset(body), 32);
        java.io.ByteArrayOutputStream log = null;
        if (identity != null) {
            // TLS 1.2 signs the handshake messages themselves, not their hash.
            log = new java.io.ByteArrayOutputStream();
            log.writeBytes(hello.asSlice(0, helloLength).toArray(ValueLayout.JAVA_BYTE));
            log.writeBytes(serverHello.toArray(ValueLayout.JAVA_BYTE));
        }
        Tls12Handshake.Outcome outcome;
        try (TranscriptHash transcript = new TranscriptHash(suite.hash())) {
            transcript.update(hello, 0, helloLength);
            transcript.update(serverHello, 0, (int) serverHello.byteSize());
            outcome = Tls12Handshake.finish(records, plainFlight, transcript, suite, clientRandom,
                    serverRandom, host, trust, identity, serverChain, log,
                    extensions.extendedMasterSecret(), arena);
        }
        records.established();
        TlsConnection connection = new TlsConnection(records.transport(), records);
        connection.describe(serverChain.isEmpty() ? null : serverChain.get(0), "TLSv1.2",
                outcome.cipherSuite());
        if (outcome.presented()) {
            connection.certificatePresented();
        }
        return connection;
    }

    /** A key's public half in native memory, sized for its group. */
    private static MemorySegment publicKey(NativeEcdh key, Arena arena) {
        MemorySegment out = arena.allocate(key.group().publicSize());
        key.publicKey(out);
        return out;
    }

    /**
     * The next complete handshake message in the clear, which has to be a
     * ServerHello - read as a message rather than as a record: a TLS 1.2 server
     * commonly sends ServerHello, Certificate, ServerKeyExchange and
     * ServerHelloDone in one record, and what follows the ServerHello stays in
     * the reassembler for the rest of the flight.
     */
    private static MemorySegment readServerHelloMessage(RecordStream records,
            HandshakeReassembler plainFlight, Arena arena) throws IOException {
        int length;
        while ((length = plainFlight.firstComplete()) < 0) {
            RecordStream.Incoming record = records.next();
            if (record.contentType() != 22) {
                throw new IOException("the server answered the ClientHello with something "
                        + "that is not a ServerHello");
            }
            plainFlight.append(record.data(), record.offset(), record.length());
        }
        if (Handshake.type(plainFlight.segment(), 0) != Handshake.SERVER_HELLO) {
            throw new IOException("the server answered the ClientHello with something that "
                    + "is not a ServerHello");
        }
        MemorySegment message = arena.allocate(length);
        MemorySegment.copy(plainFlight.segment(), 0, message, 0, length);
        plainFlight.discard(length);
        return message;
    }

    private static boolean isHelloRetryRequest(MemorySegment serverHello) {
        return serverHello.byteSize() >= Handshake.randomOffset(Handshake.HEADER) + 32
                && serverHello.asSlice(Handshake.randomOffset(Handshake.HEADER), 32)
                        .mismatch(MemorySegment.ofArray(HELLO_RETRY_REQUEST)) == -1;
    }

    /** What a HelloRetryRequest asks for: a suite, a group (or -1) and a cookie (or null). */
    private record HelloRetry(int suite, int group, MemorySegment cookie) {
    }

    /**
     * A HelloRetryRequest, read strictly (RFC 8446 section 4.1.4): TLS 1.3, a
     * suite that was offered, the session id echoed, and either a group that was
     * offered without a share or a cookie - a request that changes nothing is
     * refused, and so is one for a group a share was already sent for.
     */
    private static HelloRetry readHelloRetry(MemorySegment request, MemorySegment sentSessionId,
            int[] supportedGroups, int[] shareGroups) throws IOException {
        long body = Handshake.HEADER;
        int sessionLength = Handshake.sessionIdLength(request, body);
        if (sessionLength != sentSessionId.byteSize()
                || request.asSlice(Handshake.sessionIdOffset(body), sessionLength)
                        .mismatch(sentSessionId) != -1) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the HelloRetryRequest echoed a different session id");
        }
        int suite = Handshake.cipherSuite(request, body);
        if (suite != ClientHello.AES_128_GCM_SHA256 && suite != ClientHello.AES_256_GCM_SHA384) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the HelloRetryRequest names cipher suite 0x" + Integer.toHexString(suite)
                            + ", which was not offered");
        }
        long compression = Handshake.sessionIdOffset(body) + sessionLength + 2;
        if (request.get(ValueLayout.JAVA_BYTE, compression) != 0) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the HelloRetryRequest names a compression method");
        }
        long extensionsField = compression + 1;
        int[] group = {-1};
        boolean[] version = {false};
        MemorySegment[] cookie = {null};
        StrictExtensions.list(request, extensionsField,
                (int) (request.byteSize() - extensionsField), "the HelloRetryRequest",
                (type, at, length) -> {
                    if (type == Handshake.EXTENSION_SUPPORTED_VERSIONS) {
                        if (length != 2) {
                            throw StrictExtensions.decodeError("a supported_versions of "
                                    + length + " bytes");
                        }
                        version[0] = Handshake.u16(request, at) == 0x0304;
                    } else if (type == Handshake.EXTENSION_KEY_SHARE) {
                        if (length != 2) {
                            throw StrictExtensions.decodeError("a HelloRetryRequest key_share of "
                                    + length + " bytes; it names one group");
                        }
                        group[0] = Handshake.u16(request, at);
                    } else if (type == ClientHello.EXTENSION_COOKIE) {
                        if (length < 3 || Handshake.u16(request, at) != length - 2) {
                            throw StrictExtensions.decodeError("a malformed cookie");
                        }
                        cookie[0] = request.asSlice(at + 2, length - 2);
                    } else {
                        throw StrictExtensions.unsolicited("the HelloRetryRequest", type);
                    }
                });
        if (!version[0]) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "a HelloRetryRequest that does not select TLS 1.3");
        }
        if (group[0] >= 0) {
            boolean offered = java.util.Arrays.stream(supportedGroups).anyMatch(g -> g == group[0]);
            boolean shared = java.util.Arrays.stream(shareGroups).anyMatch(g -> g == group[0]);
            if (!offered || shared || NativeEcdh.Group.of(group[0]) == null) {
                throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                        "the HelloRetryRequest asks for group 0x" + Integer.toHexString(group[0])
                                + (shared ? ", which already had a share"
                                        : ", which was not offered"));
            }
        } else if (cookie[0] == null) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "a HelloRetryRequest that asks for nothing");
        }
        return new HelloRetry(suite, group[0], cookie[0]);
    }

    /** What a ServerHello has to tell us, once it has been checked. */
    private record ServerHelloFacts(HashAlgorithm hash, int keyLength,
            long keyShareAt, int keyShareLength, String cipherSuite, int group, int suite) {
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
            MemorySegment sentSessionId, int[] sentShares) throws IOException {
        long body = Handshake.HEADER;
        if (serverHello.asSlice(Handshake.randomOffset(body), 32)
                .mismatch(MemorySegment.ofArray(HELLO_RETRY_REQUEST)) == -1) {
            throw new TlsProtocolException(TlsAlertException.HANDSHAKE_FAILURE,
                    "the server asked for a different key share (HelloRetryRequest); this "
                            + "client offers its groups up front and does not retry");
        }
        int sessionLength = Handshake.sessionIdLength(serverHello, body);
        if (sessionLength != sentSessionId.byteSize()
                || serverHello.asSlice(Handshake.sessionIdOffset(body), sessionLength)
                        .mismatch(sentSessionId) != -1) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the server echoed a different session id than the one sent - "
                            + "something between us is not passing the handshake through unchanged");
        }

        int suite = Handshake.cipherSuite(serverHello, body);
        HashAlgorithm hash = switch (suite) {
            case ClientHello.AES_128_GCM_SHA256 -> HashAlgorithm.SHA_256;
            case ClientHello.AES_256_GCM_SHA384 -> HashAlgorithm.SHA_384;
            default -> throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the server chose cipher suite 0x" + Integer.toHexString(suite)
                            + ", which was not offered");
        };
        int keyLength = suite == ClientHello.AES_256_GCM_SHA384 ? 32 : 16;

        // legacy_version is deliberately not checked. RFC 8446 section 4.2.1:
        // with supported_versions present, "clients MUST ignore the
        // ServerHello.legacy_version value" - and this client requires that
        // extension to say 0x0304 below, so the header cannot negotiate
        // anything. Refusing a header other than 0x0303 broke that MUST
        // (TLS-Anvil 8446-oysw9PbeiT, 28.09.2026; OpenSSL's client ignores it
        // as well).
        long compression = Handshake.sessionIdOffset(body) + sessionLength + 2;
        if (serverHello.get(ValueLayout.JAVA_BYTE, compression) != 0) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the ServerHello names a compression method; TLS 1.3 has none");
        }
        long extensionsField = compression + 1;
        long[] share = {0, 0, 0};
        boolean[] seen = {false, false};
        // RFC 8446 section 4.2: the extensions fill the rest of the message
        // exactly, each appears once and fills itself exactly, and the
        // server answers only what was offered - key_share and
        // supported_versions, nothing else (no PSK is ever offered).
        StrictExtensions.list(serverHello, extensionsField,
                (int) (serverHello.byteSize() - extensionsField), "the ServerHello",
                (type, at, length) -> {
                    if (type == Handshake.EXTENSION_KEY_SHARE) {
                        if (length < 4) {
                            throw StrictExtensions.decodeError("a key_share of " + length
                                    + " bytes");
                        }
                        long[] out = new long[2];
                        int group = Handshake.serverKeyShare(serverHello, at, out);
                        if (4 + out[1] != length) {
                            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                                    "the key share does not fill its extension");
                        }
                        if (shareLength(group) == out[1]
                                && java.util.Arrays.stream(sentShares).anyMatch(g -> g == group)) {
                            share[0] = out[0];
                            share[1] = out[1];
                            share[2] = group;
                            seen[0] = true;
                        }
                    } else if (type == Handshake.EXTENSION_SUPPORTED_VERSIONS) {
                        if (length != 2) {
                            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                                    "a supported_versions of " + length + " bytes in the "
                                            + "ServerHello; it is one version");
                        }
                        seen[1] = Handshake.selectedVersion(serverHello, at) == 0x0304;
                    } else {
                        throw StrictExtensions.unsolicited("the ServerHello", type);
                    }
                });
        if (!seen[1]) {
            throw new TlsProtocolException(TlsAlertException.PROTOCOL_VERSION,
                    "the server did not select TLS 1.3 - the header version means "
                            + "nothing, and supported_versions did not say 0x0304");
        }
        if (!seen[0]) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the server sent no usable key share for a group a share was sent "
                            + "for");
        }
        String name = suite == ClientHello.AES_256_GCM_SHA384
                ? "TLS_AES_256_GCM_SHA384" : "TLS_AES_128_GCM_SHA256";
        if (share[2] == ClientHello.X25519MLKEM768) {
            name += " with X25519MLKEM768";
        } else {
            name += " with " + NativeEcdh.Group.of((int) share[2]);
        }
        return new ServerHelloFacts(hash, keyLength, share[0], (int) share[1], name,
                (int) share[2], suite);
    }

    /** How long a server's key share is for {@code group}; -1 for one never offered. */
    private static long shareLength(int group) {
        if (group == ClientHello.X25519MLKEM768) {
            return space.seclume.crypto.HybridMlKem.SERVER_SHARE;
        }
        NativeEcdh.Group known = NativeEcdh.Group.of(group);
        return known == null ? -1 : known.publicSize();
    }

    /** What the server's flight left behind for the rest of the handshake. */
    private record ServerFlight(byte[] certificateRequest, boolean signatureVerified) {
    }

    /**
     * Where the server's flight stands: which message may come next.
     *
     * <p>RFC 8446 section 4.4, for a handshake without a PSK - the only kind
     * this client makes: EncryptedExtensions, then optionally
     * CertificateRequest, then Certificate, CertificateVerify and Finished,
     * each exactly once. Certificate and CertificateVerify are not optional
     * (section 4.4.2), whether or not the certificate is then checked
     * against a trust store: without them the server has proved nothing at
     * all, and the encryption is with whoever answered.
     */
    private enum Expect {
        ENCRYPTED_EXTENSIONS("EncryptedExtensions"),
        CERTIFICATE_OR_REQUEST("Certificate or CertificateRequest"),
        CERTIFICATE("Certificate"),
        CERTIFICATE_VERIFY("CertificateVerify"),
        FINISHED("Finished"),
        NOTHING("nothing more");

        private final String wanted;

        Expect(String wanted) {
            this.wanted = wanted;
        }
    }

    /**
     * EncryptedExtensions, an optional CertificateRequest, Certificate,
     * CertificateVerify and Finished - however many records they arrive in,
     * and in exactly that order.
     *
     * <p><b>The order is the security property.</b> Each message is checked
     * where it stands, and a client that merely reacts to whatever arrives
     * checks nothing that is not sent: a server - or anybody in the middle -
     * that goes from EncryptedExtensions straight to a Finished of its own
     * making was accepted by the version before this one, with a trust store
     * set and {@code peerCertificate()} null. Review, 26.09.2026. So every
     * message is refused unless it is the one that is due, with
     * {@code unexpected_message} as RFC 8446 prescribes.
     *
     * @return the request context if a {@code CertificateRequest} arrived -
     *         normally empty, which is not the same as absent - or
     *         {@code null} if the server did not ask for a client
     *         certificate; and whether a CertificateVerify was verified
     */
    private static ServerFlight readServerFlight(RecordStream records, TranscriptHash transcript,
            KeySchedule schedule, SecretScope digest, HashAlgorithm hash, String host,
            CertificateTrust trust, List<X509Certificate> chain, String alpn)
            throws IOException {
        try (HandshakeReassembler flight = new HandshakeReassembler(1 << 20)) {
            Expect[] expect = {Expect.ENCRYPTED_EXTENSIONS};
            boolean[] verified = {false};
            byte[][] certificateRequest = {null};
            IOException[] failure = {null};

            while (expect[0] != Expect.NOTHING && failure[0] == null) {
                RecordStream.Incoming record = records.next();
                if (record.contentType() != 22) {
                    throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                            "a record of type " + record.contentType() + " arrived during the "
                                    + "server's handshake flight, where " + expect[0].wanted
                                    + " was due");
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
                        Expect now = expect[0];
                        switch (type) {
                            case Handshake.ENCRYPTED_EXTENSIONS -> {
                                due(now == Expect.ENCRYPTED_EXTENSIONS, type, now);
                                readEncryptedExtensions(message, at, length, alpn,
                                        serverNameFor(host) != null);
                                transcript.update(message, start, total);
                                expect[0] = Expect.CERTIFICATE_OR_REQUEST;
                            }
                            case Handshake.CERTIFICATE_REQUEST -> {
                                due(now == Expect.CERTIFICATE_OR_REQUEST, type, now);
                                // Only noted here. The answer belongs in the
                                // client's own flight, which is written once
                                // this one has been read to its end.
                                certificateRequest[0] =
                                        CertificateMessage.requestContext(message, at);
                                transcript.update(message, start, total);
                                expect[0] = Expect.CERTIFICATE;
                            }
                            case Handshake.CERTIFICATE -> {
                                due(now == Expect.CERTIFICATE_OR_REQUEST
                                        || now == Expect.CERTIFICATE, type, now);
                                CertificateMessage.checkServerCertificate(message, at, length);
                                readCertificates(message, at, length, chain);
                                authenticate(chain, host, trust);
                                transcript.update(message, start, total);
                                expect[0] = Expect.CERTIFICATE_VERIFY;
                            }
                            case Handshake.CERTIFICATE_VERIFY -> {
                                due(now == Expect.CERTIFICATE_VERIFY, type, now);
                                // Signed over everything up to and including Certificate,
                                // so the hash is taken before this message is added.
                                // Checked with or without a trust store: the signature
                                // is what proves the server holds the key it presented.
                                CertificateVerifyMessage.checkShape(message, at, length);
                                transcript.current(digest.segment(), 0);
                                verifySignature(chain, message, at,
                                        digest.segment().asSlice(0, hash.digestLength()));
                                verified[0] = true;
                                transcript.update(message, start, total);
                                expect[0] = Expect.FINISHED;
                            }
                            case Handshake.FINISHED -> {
                                due(now == Expect.FINISHED, type, now);
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
                                expect[0] = Expect.NOTHING;
                            }
                            default -> throw new TlsProtocolException(
                                    TlsAlertException.UNEXPECTED_MESSAGE,
                                    "handshake message of type " + type + " is not part of a "
                                            + "server's first flight; " + now.wanted
                                            + " was due");
                        }
                    } catch (IOException e) {
                        failure[0] = e;
                    }
                });
            }
            if (failure[0] != null) {
                throw failure[0];
            }
            if (flight.buffered() > 0) {
                // RFC 8446 section 5.1: handshake messages must not span a key
                // change, and the server's Finished is one.
                throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                        "handshake bytes followed the server's Finished under the same key");
            }
            return new ServerFlight(certificateRequest[0], verified[0]);
        }
    }

    /** Refuses a message that is not the one due at this point of the flight. */
    private static void due(boolean inOrder, int type, Expect expected)
            throws TlsProtocolException {
        if (!inOrder) {
            throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                    "the server sent " + messageName(type) + " where RFC 8446 section 4.4 "
                            + "requires " + expected.wanted);
        }
    }

    private static String messageName(int type) {
        return switch (type) {
            case Handshake.ENCRYPTED_EXTENSIONS -> "EncryptedExtensions";
            case Handshake.CERTIFICATE_REQUEST -> "CertificateRequest";
            case Handshake.CERTIFICATE -> "Certificate";
            case Handshake.CERTIFICATE_VERIFY -> "CertificateVerify";
            case Handshake.FINISHED -> "Finished";
            default -> "handshake message " + type;
        };
    }

    /**
     * The second lock on the same door: no application secret is derived
     * for a server that has not shown a certificate and proved, with a
     * verified CertificateVerify, that it holds the key in it.
     *
     * <p>Unconditional rather than only with a trust store. This client never
     * offers a PSK, so there is no handshake in which a server legitimately
     * skips both - and {@code connectWithoutAuthenticating} gives up the check
     * of <em>who</em> the key belongs to, not the proof that the server holds
     * one.
     */
    static void requireAuthenticatedServer(List<X509Certificate> chain,
            boolean signatureVerified) throws TlsProtocolException {
        if (chain.isEmpty() || !signatureVerified) {
            throw new TlsProtocolException(TlsAlertException.HANDSHAKE_FAILURE,
                    "the server finished its handshake without "
                            + (chain.isEmpty() ? "a certificate" : "a verified CertificateVerify")
                            + " - refusing to derive keys for a peer nobody authenticated");
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
     * Extensions that exist in TLS 1.3 but never in EncryptedExtensions
     * (RFC 8446 section 4.2, the table): one of these there is an
     * {@code illegal_parameter}, anything else not asked for an
     * {@code unsupported_extension}.
     */
    private static final java.util.Set<Integer> NEVER_IN_ENCRYPTED_EXTENSIONS = java.util.Set.of(
            13, 21, 41, 43, 44, 45, 47, 48, 49, 50, 51);

    /**
     * EncryptedExtensions, read strictly - and whether the server agreed to
     * the protocol we offered.
     *
     * <p>Strictly, because TLS-Anvil (27.09.2026) showed this client taking
     * an EncryptedExtensions whose lengths did not add up, or that carried a
     * padding, supported_versions or GREASE extension, and carrying on. The
     * message is covered by the Finished, so a man in the middle could not
     * have used that; RFC 8446 still says to abort, and does not say why it
     * would be safe not to.
     *
     * <p>What the server may answer: server_name (empty, if one was sent),
     * supported_groups (its preferences, for next time) and ALPN if it was
     * offered. A server that selects no protocol when one was offered has
     * either ignored ALPN or does not support it, and carrying on would mean
     * speaking a protocol it never agreed to - for TDS 8.0 a connection that
     * hangs rather than an error.
     */
    private static void readEncryptedExtensions(MemorySegment message, long body, int length,
            String alpn, boolean sentServerName) throws IOException {
        String[] selected = {null};
        StrictExtensions.list(message, body, length, "the EncryptedExtensions",
                (type, at, size) -> {
                    if (type == Handshake.EXTENSION_SERVER_NAME && sentServerName) {
                        if (size != 0) {
                            throw StrictExtensions.decodeError(
                                    "a server_name answer that is not empty");
                        }
                    } else if (type == Handshake.EXTENSION_SUPPORTED_GROUPS) {
                        if (size < 2 || Handshake.u16(message, at) != size - 2
                                || (size - 2) % 2 != 0) {
                            throw StrictExtensions.decodeError("a malformed supported_groups");
                        }
                    } else if (type == ClientHello.EXTENSION_ALPN && alpn != null) {
                        // ProtocolNameList with exactly one name, since one was offered.
                        if (size < 3 || Handshake.u16(message, at) != size - 2) {
                            throw StrictExtensions.decodeError("a malformed ALPN answer");
                        }
                        int nameLength = message.get(ValueLayout.JAVA_BYTE, at + 2) & 0xff;
                        if (nameLength == 0 || nameLength != size - 3) {
                            throw StrictExtensions.decodeError(
                                    "an ALPN answer that is not exactly one protocol name");
                        }
                        StringBuilder name = new StringBuilder(nameLength);
                        for (int i = 0; i < nameLength; i++) {
                            name.append((char) (message.get(ValueLayout.JAVA_BYTE, at + 3 + i)
                                    & 0xff));
                        }
                        selected[0] = name.toString();
                    } else if (NEVER_IN_ENCRYPTED_EXTENSIONS.contains(type)) {
                        throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                                "extension " + type + " has no place in EncryptedExtensions");
                    } else {
                        throw StrictExtensions.unsolicited("the EncryptedExtensions", type);
                    }
                });
        if (alpn == null) {
            return;
        }
        if (!alpn.equals(selected[0])) {
            throw new IOException("this client offered the application protocol \"" + alpn
                    + "\" and the server answered with "
                    + (selected[0] == null ? "none" : "\"" + selected[0] + "\"")
                    + " - carrying on would mean speaking a protocol it never agreed to");
        }
    }

    static void authenticate(List<X509Certificate> chain, String host,
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
