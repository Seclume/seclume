package space.seclume.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import space.seclume.crypto.ConstantTime;
import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.NativeP256;
import space.seclume.secret.SecretScope;

/**
 * The TLS 1.2 half of {@link ClientHandshake}: what happens after a server
 * answered our ClientHello with a TLS 1.2 ServerHello.
 *
 * <p>A deliberately small profile, and the smallness is the security argument:
 *
 * <ul>
 *   <li><b>ECDHE on P-256</b>, with the same native key pair the TLS 1.3 key
 *       share used - no static RSA key exchange, so no Bleichenbacher oracle
 *       and forward secrecy always;</li>
 *   <li><b>AES-GCM</b> records ({@link RecordProtection#forTls12}) - no CBC, no
 *       MAC-then-encrypt, so no padding oracle and no Lucky13;</li>
 *   <li><b>the extended master secret</b> (RFC 7627) is required, and a server
 *       that does not offer it is refused - the master secret is then bound to
 *       this handshake's transcript;</li>
 *   <li><b>secure renegotiation</b> (RFC 5746) is required of the server, and
 *       this client never renegotiates;</li>
 *   <li>no resumption, no session tickets, no compression.</li>
 * </ul>
 *
 * <p>What is secret lives where it does for TLS 1.3: the ECDH shared secret
 * and the master secret in {@link SecretScope}s, the key block wiped once the
 * two {@link RecordProtection}s have taken their halves, the Finished values
 * computed into native memory. The PRF is ours ({@link Tls12Prf}); the
 * certificate chain and the ServerKeyExchange signature are checked by the JDK
 * over public data.
 *
 * <p><b>The order is checked, message by message</b> - Certificate,
 * ServerKeyExchange, an optional CertificateRequest, ServerHelloDone - with
 * {@code unexpected_message} for anything else, for the reason the TLS 1.3
 * flight does: a client that reacts to whatever arrives checks nothing that is
 * not sent.
 */
final class Tls12Handshake {

    /** RFC 4492: named_curve, followed by the curve's id. */
    private static final int NAMED_CURVE = 3;
    private static final int SERVER_KEY_EXCHANGE = 12;
    private static final int SERVER_HELLO_DONE = 14;
    private static final int CLIENT_KEY_EXCHANGE = 16;
    private static final int HELLO_REQUEST = 0;
    private static final int MASTER_SECRET = 48;
    private static final int VERIFY_DATA = 12;
    private static final int SALT = 4;

    private Tls12Handshake() {
    }

    /** What a TLS 1.2 ServerHello settled. */
    record Suite(int id, HashAlgorithm hash, int keyLength, boolean ecdsa, String name) {
    }

    /** What the handshake leaves behind for {@link TlsConnection#describe}. */
    record Outcome(String cipherSuite, boolean presented) {
    }

    /** The suite a TLS 1.2 ServerHello chose, if it is one this client offered. */
    static Suite suite(int id) throws TlsProtocolException {
        return switch (id) {
            case ClientHello.ECDHE_ECDSA_AES_256_GCM_SHA384 -> new Suite(id, HashAlgorithm.SHA_384,
                    32, true, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
            case ClientHello.ECDHE_RSA_AES_256_GCM_SHA384 -> new Suite(id, HashAlgorithm.SHA_384,
                    32, false, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
            case ClientHello.ECDHE_ECDSA_AES_128_GCM_SHA256 -> new Suite(id, HashAlgorithm.SHA_256,
                    16, true, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
            case ClientHello.ECDHE_RSA_AES_128_GCM_SHA256 -> new Suite(id, HashAlgorithm.SHA_256,
                    16, false, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
            default -> throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the server chose TLS 1.2 cipher suite 0x" + Integer.toHexString(id)
                            + ", which was not offered");
        };
    }

    /**
     * Checks a TLS 1.2 ServerHello's extensions: the extended master secret
     * and secure renegotiation present, nothing unasked for.
     *
     * @return the protocol the server selected by ALPN, or null
     */
    static String readServerHelloExtensions(MemorySegment serverHello, long extensionsField,
            boolean sentServerName, String alpn) throws IOException {
        boolean[] seen = {false, false};             // extended master secret, renegotiation_info
        String[] selected = {null};
        if (extensionsField == serverHello.byteSize()) {
            throw new TlsProtocolException(TlsAlertException.HANDSHAKE_FAILURE,
                    "the TLS 1.2 server sent no extensions - it supports neither the extended "
                            + "master secret (RFC 7627) nor secure renegotiation (RFC 5746), "
                            + "and this client requires both");
        }
        StrictExtensions.list(serverHello, extensionsField,
                (int) (serverHello.byteSize() - extensionsField), "the ServerHello",
                (type, at, length) -> {
                    if (type == ClientHello.EXTENSION_EXTENDED_MASTER_SECRET) {
                        if (length != 0) {
                            throw StrictExtensions.decodeError("an extended_master_secret of "
                                    + length + " bytes");
                        }
                        seen[0] = true;
                    } else if (type == ClientHello.EXTENSION_RENEGOTIATION_INFO) {
                        // An initial handshake: an empty renegotiated_connection.
                        if (length != 1 || serverHello.get(ValueLayout.JAVA_BYTE, at) != 0) {
                            throw new TlsProtocolException(TlsAlertException.HANDSHAKE_FAILURE,
                                    "a renegotiation_info that is not empty in an initial "
                                            + "handshake");
                        }
                        seen[1] = true;
                    } else if (type == ClientHello.EXTENSION_EC_POINT_FORMATS) {
                        int count = length < 1 ? -1 : serverHello.get(ValueLayout.JAVA_BYTE, at) & 0xff;
                        if (count < 1 || count != length - 1) {
                            throw StrictExtensions.decodeError("a malformed ec_point_formats");
                        }
                        boolean uncompressed = false;
                        for (int i = 0; i < count; i++) {
                            uncompressed |= serverHello.get(ValueLayout.JAVA_BYTE, at + 1 + i) == 0;
                        }
                        if (!uncompressed) {
                            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                                    "the server's ec_point_formats leave out the uncompressed "
                                            + "form, the only one offered");
                        }
                    } else if (type == Handshake.EXTENSION_SERVER_NAME && sentServerName) {
                        if (length != 0) {
                            throw StrictExtensions.decodeError("a server_name answer that is not "
                                    + "empty");
                        }
                    } else if (type == ClientHello.EXTENSION_ALPN && alpn != null) {
                        selected[0] = alpnName(serverHello, at, length);
                    } else {
                        throw StrictExtensions.unsolicited("the ServerHello", type);
                    }
                });
        if (!seen[0]) {
            throw new TlsProtocolException(TlsAlertException.HANDSHAKE_FAILURE,
                    "the TLS 1.2 server does not support the extended master secret (RFC 7627); "
                            + "without it the master secret is not bound to this handshake, "
                            + "and this client refuses to derive one");
        }
        if (!seen[1]) {
            throw new TlsProtocolException(TlsAlertException.HANDSHAKE_FAILURE,
                    "the TLS 1.2 server does not support secure renegotiation (RFC 5746)");
        }
        if (alpn != null && !alpn.equals(selected[0])) {
            throw new IOException("this client offered the application protocol \"" + alpn
                    + "\" and the server answered with "
                    + (selected[0] == null ? "none" : "\"" + selected[0] + "\"")
                    + " - carrying on would mean speaking a protocol it never agreed to");
        }
        return selected[0];
    }

    private static String alpnName(MemorySegment message, long at, int size)
            throws TlsProtocolException {
        if (size < 3 || Handshake.u16(message, at) != size - 2) {
            throw StrictExtensions.decodeError("a malformed ALPN answer");
        }
        int nameLength = message.get(ValueLayout.JAVA_BYTE, at + 2) & 0xff;
        if (nameLength == 0 || nameLength != size - 3) {
            throw StrictExtensions.decodeError("an ALPN answer that is not exactly one protocol "
                    + "name");
        }
        StringBuilder name = new StringBuilder(nameLength);
        for (int i = 0; i < nameLength; i++) {
            name.append((char) (message.get(ValueLayout.JAVA_BYTE, at + 3 + i) & 0xff));
        }
        return name.toString();
    }

    /** Which message of the server's flight is due. */
    private enum Expect {
        CERTIFICATE("Certificate"),
        SERVER_KEY_EXCHANGE("ServerKeyExchange"),
        REQUEST_OR_DONE("CertificateRequest or ServerHelloDone"),
        DONE("ServerHelloDone"),
        NOTHING("nothing more");

        private final String wanted;

        Expect(String wanted) {
            this.wanted = wanted;
        }
    }

    /**
     * Runs the rest of a TLS 1.2 handshake, from the server's Certificate to
     * its Finished.
     *
     * @param flight       the server's plaintext handshake bytes, with the
     *                     ServerHello already taken off the front; whatever
     *                     else its record held is still in there
     * @param transcript   holding ClientHello and ServerHello
     * @param clientRandom our random
     * @param serverRandom the server's
     * @param keyExchange  our P-256 key pair - the one the ClientHello offered
     * @param handshakeLog every handshake message so far in order, when a
     *                     client certificate may have to be proved; else null
     */
    static Outcome finish(RecordStream records, HandshakeReassembler flight,
            TranscriptHash transcript, Suite suite, MemorySegment clientRandom,
            MemorySegment serverRandom, NativeP256 keyExchange, String host,
            CertificateTrust trust, ClientIdentity identity, List<X509Certificate> chain,
            ByteArrayOutputStream handshakeLog, Arena arena) throws IOException {
        HashAlgorithm hash = suite.hash();
        MemorySegment serverPoint = arena.allocate(NativeP256.PUBLIC_SIZE);
        Expect[] expect = {Expect.CERTIFICATE};
        CertificateRequest[] request = {null};
        boolean[] signed = {false};
        IOException[] failure = {null};

        // ---- the server's flight, in the clear ------------------------------
        while (expect[0] != Expect.NOTHING) {
            flight.drain((type, at, length) -> {
                if (failure[0] != null) {
                    return;
                }
                try {
                    MemorySegment message = flight.segment();
                    long start = at - Handshake.HEADER;
                    int total = Handshake.HEADER + length;
                    Expect now = expect[0];
                    switch (type) {
                        case Handshake.CERTIFICATE -> {
                            due(now == Expect.CERTIFICATE, type, now);
                            readCertificates(message, at, length, chain);
                            requireKeyFor(suite, chain.get(0));
                            ClientHandshake.authenticate(chain, host, trust);
                            expect[0] = Expect.SERVER_KEY_EXCHANGE;
                        }
                        case SERVER_KEY_EXCHANGE -> {
                            due(now == Expect.SERVER_KEY_EXCHANGE, type, now);
                            readServerKeyExchange(message, at, length, clientRandom, serverRandom,
                                    chain.get(0), serverPoint);
                            signed[0] = true;
                            expect[0] = Expect.REQUEST_OR_DONE;
                        }
                        case Handshake.CERTIFICATE_REQUEST -> {
                            due(now == Expect.REQUEST_OR_DONE, type, now);
                            request[0] = CertificateRequest.read(message, at, length);
                            expect[0] = Expect.DONE;
                        }
                        case SERVER_HELLO_DONE -> {
                            due(now == Expect.REQUEST_OR_DONE || now == Expect.DONE, type, now);
                            if (length != 0) {
                                throw StrictExtensions.decodeError("a ServerHelloDone of " + length
                                        + " bytes");
                            }
                            expect[0] = Expect.NOTHING;
                        }
                        default -> throw new TlsProtocolException(
                                TlsAlertException.UNEXPECTED_MESSAGE,
                                "the server sent " + messageName(type) + " where "
                                        + now.wanted + " was due");
                    }
                    transcript.update(message, start, total);
                    log(handshakeLog, message, start, total);
                } catch (IOException e) {
                    failure[0] = e;
                }
            });
            if (failure[0] != null) {
                throw failure[0];
            }
            if (expect[0] == Expect.NOTHING) {
                break;
            }
            RecordStream.Incoming record = records.next();
            if (record.contentType() != 22) {
                throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                        "a record of type " + record.contentType() + " arrived during the "
                                + "server's handshake flight, where " + expect[0].wanted
                                + " was due");
            }
            flight.append(record.data(), record.offset(), record.length());
        }
        if (flight.buffered() > 0) {
            throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                    "handshake bytes followed the ServerHelloDone before this client's turn");
        }
        ClientHandshake.requireAuthenticatedServer(chain, signed[0]);

        // ---- our flight -----------------------------------------------------
        boolean presented = false;
        ClientIdentity signer = null;
        if (request[0] != null) {
            signer = identity == null ? null : identity.forHandshake();
            if (signer != null && !request[0].accepts(signer.signatureScheme())) {
                // The server would refuse a signature it did not ask for;
                // saying so here is clearer than its handshake_failure.
                throw new IOException("the server asked for a client certificate signed with "
                        + request[0].schemes() + ", and this client's key signs with 0x"
                        + Integer.toHexString(signer.signatureScheme()));
            }
            sendCertificate(records, transcript, handshakeLog, signer, arena);
        }

        try (SecretScope shared = SecretScope.allocate(NativeP256.SECRET_SIZE);
                SecretScope master = SecretScope.allocate(MASTER_SECRET);
                SecretScope digest = SecretScope.allocate(hash.digestLength())) {
            // A scope may be larger than asked for; every use takes exactly its length.
            MemorySegment premaster = shared.segment().asSlice(0, NativeP256.SECRET_SIZE);
            MemorySegment masterSecret = master.segment().asSlice(0, MASTER_SECRET);
            MemorySegment hashed = digest.segment().asSlice(0, hash.digestLength());
            try {
                keyExchange.derive(serverPoint, premaster);
            } catch (IllegalArgumentException | IllegalStateException badPoint) {
                TlsProtocolException refused = new TlsProtocolException(
                        TlsAlertException.ILLEGAL_PARAMETER,
                        "the server's ECDH point was refused: " + badPoint.getMessage());
                refused.initCause(badPoint);
                throw refused;
            }
            sendClientKeyExchange(records, transcript, handshakeLog, keyExchange, arena);

            // RFC 7627: the master secret from the hash of everything up to and
            // including ClientKeyExchange - not from the two randoms.
            transcript.current(hashed, 0);
            Tls12Prf.derive(hash, premaster, "extended master secret", hashed,
                    masterSecret, 0, MASTER_SECRET);
            premaster.fill((byte) 0);

            if (signer != null) {
                sendCertificateVerify(records, transcript, handshakeLog, signer, arena);
                presented = true;
            }

            RecordProtection[] keys = keyBlock(suite, masterSecret, clientRandom, serverRandom);
            RecordProtection serverKeys = keys[1];
            try {
                records.writeChangeCipherSpec();
                records.writeWith(keys[0]);

                transcript.current(hashed, 0);
                MemorySegment finished = arena.allocate(Handshake.HEADER + VERIFY_DATA);
                finished.set(ValueLayout.JAVA_BYTE, 0, (byte) Handshake.FINISHED);
                finished.set(ValueLayout.JAVA_BYTE, 3, (byte) VERIFY_DATA);
                Tls12Prf.derive(hash, masterSecret, "client finished", hashed,
                        finished, Handshake.HEADER, VERIFY_DATA);
                try {
                    records.write((byte) 22, finished, 0, Handshake.HEADER + VERIFY_DATA);
                } catch (TlsAlertException alert) {
                    throw alert;
                } catch (IOException gone) {
                    throw ClientHandshake.refusedAfterCertificate(gone, presented);
                }
                transcript.update(finished, 0, Handshake.HEADER + VERIFY_DATA);

                // ---- the server's ChangeCipherSpec and Finished ----------------
                RecordStream.Incoming change;
                try {
                    change = records.next();
                } catch (TlsAlertException alert) {
                    throw alert;
                } catch (IOException gone) {
                    throw ClientHandshake.refusedAfterCertificate(gone, presented);
                }
                if (change.contentType() != 20) {
                    throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                            "the server answered our Finished with a record of type "
                                    + change.contentType() + " where ChangeCipherSpec was due");
                }
                records.readWith(serverKeys);
                serverKeys = null;

                RecordStream.Incoming record = records.next();
                if (record.contentType() != 22 || record.length() != Handshake.HEADER + VERIFY_DATA
                        || Handshake.type(record.data(), record.offset()) != Handshake.FINISHED
                        || Handshake.length(record.data(), record.offset()) != VERIFY_DATA) {
                    throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                            "the server's first record under its new keys is not exactly its "
                                    + "Finished");
                }
                transcript.current(hashed, 0);
                MemorySegment expected = arena.allocate(VERIFY_DATA);
                try {
                    Tls12Prf.derive(hash, masterSecret, "server finished", hashed, expected, 0,
                            VERIFY_DATA);
                    if (!ConstantTime.equals(expected, 0, record.data(),
                            record.offset() + Handshake.HEADER, VERIFY_DATA)) {
                        throw new TlsProtocolException(TlsAlertException.DECRYPT_ERROR,
                                "the server's Finished does not match the handshake we saw - "
                                        + "somebody changed a message in flight");
                    }
                } finally {
                    expected.fill((byte) 0);
                }
            } finally {
                if (serverKeys != null) {
                    serverKeys.close();
                }
            }
        }
        return new Outcome(suite.name(), presented);
    }

    /**
     * The key block (RFC 5246 section 6.3), for AES-GCM: two keys and two
     * four-byte salts, no MAC keys. Taken straight into the two directions'
     * protections and wiped.
     *
     * @return the client's write protection, then the server's
     */
    private static RecordProtection[] keyBlock(Suite suite, MemorySegment master,
            MemorySegment clientRandom, MemorySegment serverRandom) {
        int keyLength = suite.keyLength();
        int length = 2 * keyLength + 2 * SALT;
        try (SecretScope block = SecretScope.allocate(length)) {
            MemorySegment bytes = block.segment().asSlice(0, length);
            Tls12Prf.derive(suite.hash(), master, "key expansion",
                    new MemorySegment[] {serverRandom, clientRandom}, bytes, 0, length);
            RecordProtection client = RecordProtection.forTls12(suite.hash(), bytes, 0,
                    keyLength, 2L * keyLength);
            RecordProtection server;
            try {
                server = RecordProtection.forTls12(suite.hash(), bytes, keyLength, keyLength,
                        2L * keyLength + SALT);
            } catch (RuntimeException e) {
                client.close();
                throw e;
            }
            bytes.fill((byte) 0);
            return new RecordProtection[] {client, server};
        }
    }

    /** The certificate's key has to be the kind the suite authenticates with. */
    private static void requireKeyFor(Suite suite, X509Certificate leaf)
            throws TlsProtocolException {
        boolean ok = suite.ecdsa() ? leaf.getPublicKey() instanceof ECPublicKey
                : leaf.getPublicKey() instanceof RSAPublicKey;
        if (!ok) {
            throw new TlsProtocolException(TlsAlertException.HANDSHAKE_FAILURE,
                    "the server chose " + suite.name() + " with a "
                            + leaf.getPublicKey().getAlgorithm() + " certificate");
        }
    }

    /**
     * The TLS 1.2 Certificate message: a list of DER certificates, each with a
     * three-byte length, filling the message exactly - no request context and
     * no per-certificate extensions, unlike TLS 1.3's.
     */
    private static void readCertificates(MemorySegment message, long body, int length,
            List<X509Certificate> chain) throws IOException {
        if (length < 3) {
            throw StrictExtensions.decodeError("a Certificate message of " + length + " bytes");
        }
        int listLength = u24(message, body);
        if (listLength != length - 3) {
            throw StrictExtensions.decodeError("the certificate list says " + listLength
                    + " bytes and the message has " + (length - 3));
        }
        long at = body + 3;
        long end = body + length;
        while (at < end) {
            if (end - at < 3) {
                throw StrictExtensions.decodeError("a certificate entry cut short");
            }
            int size = u24(message, at);
            at += 3;
            if (size == 0 || at + size > end) {
                throw StrictExtensions.decodeError("a certificate of " + size + " bytes in a list "
                        + "with " + (end - at) + " left");
            }
            try {
                chain.add(Certificates.parse(message, at, size));
            } catch (CertificateException e) {
                throw new IOException("the server sent a certificate that cannot be read", e);
            }
            at += size;
        }
        if (chain.isEmpty()) {
            throw new TlsProtocolException(TlsAlertException.DECODE_ERROR,
                    "the server sent an empty certificate list");
        }
    }

    /**
     * ServerKeyExchange for ECDHE (RFC 4492 section 5.4, RFC 8422): a named
     * curve, which has to be P-256, the server's point, and a signature over
     * both randoms and those parameters - verified here against the
     * certificate's key, so that the point is the server's and not someone's
     * in between.
     */
    private static void readServerKeyExchange(MemorySegment message, long body, int length,
            MemorySegment clientRandom, MemorySegment serverRandom, X509Certificate leaf,
            MemorySegment serverPoint) throws IOException {
        if (length < 4 + 1 + 4) {
            throw StrictExtensions.decodeError("a ServerKeyExchange of " + length + " bytes");
        }
        int curveType = message.get(ValueLayout.JAVA_BYTE, body) & 0xff;
        int curve = Handshake.u16(message, body + 1);
        if (curveType != NAMED_CURVE || curve != ClientHello.SECP256R1) {
            throw new TlsProtocolException(TlsAlertException.HANDSHAKE_FAILURE,
                    "the server's ServerKeyExchange names "
                            + (curveType != NAMED_CURVE ? "explicit curve parameters"
                                    : "curve 0x" + Integer.toHexString(curve))
                            + "; this client's TLS 1.2 speaks P-256 only");
        }
        int pointLength = message.get(ValueLayout.JAVA_BYTE, body + 3) & 0xff;
        if (pointLength != NativeP256.PUBLIC_SIZE
                || message.get(ValueLayout.JAVA_BYTE, body + 4) != 4) {
            throw new TlsProtocolException(TlsAlertException.ILLEGAL_PARAMETER,
                    "the server's P-256 point is not an uncompressed point of 65 bytes");
        }
        int paramsLength = 4 + pointLength;
        long signatureAt = body + paramsLength;
        if (length < paramsLength + 4) {
            throw StrictExtensions.decodeError("a ServerKeyExchange without its signature");
        }
        int scheme = Handshake.u16(message, signatureAt);
        int signatureLength = Handshake.u16(message, signatureAt + 2);
        if (paramsLength + 4 + signatureLength != length) {
            throw StrictExtensions.decodeError("the ServerKeyExchange signature does not fill "
                    + "the message");
        }
        byte[] signed = new byte[32 + 32 + paramsLength];
        MemorySegment.copy(clientRandom, ValueLayout.JAVA_BYTE, 0, signed, 0, 32);
        MemorySegment.copy(serverRandom, ValueLayout.JAVA_BYTE, 0, signed, 32, 32);
        MemorySegment.copy(message, ValueLayout.JAVA_BYTE, body, signed, 64, paramsLength);
        byte[] signature = message.asSlice(signatureAt + 4, signatureLength)
                .toArray(ValueLayout.JAVA_BYTE);
        if (!HandshakeSignature.verifyTls12(leaf.getPublicKey(), scheme, signed, signature)) {
            throw new TlsProtocolException(TlsAlertException.DECRYPT_ERROR,
                    "the server's ServerKeyExchange does not verify against its own "
                            + "certificate (scheme 0x" + Integer.toHexString(scheme) + ")");
        }
        MemorySegment.copy(message, body + 4, serverPoint, 0, NativeP256.PUBLIC_SIZE);
    }

    /** A TLS 1.2 CertificateRequest (RFC 5246 section 7.4.4), read strictly. */
    private record CertificateRequest(List<Integer> schemes) {

        static CertificateRequest read(MemorySegment message, long body, int length)
                throws TlsProtocolException {
            if (length < 1) {
                throw StrictExtensions.decodeError("an empty CertificateRequest");
            }
            int types = message.get(ValueLayout.JAVA_BYTE, body) & 0xff;
            long at = body + 1 + types;
            long end = body + length;
            if (types == 0 || at + 2 > end) {
                throw StrictExtensions.decodeError("a CertificateRequest without certificate "
                        + "types or signature algorithms");
            }
            int schemesLength = Handshake.u16(message, at);
            at += 2;
            if (schemesLength == 0 || schemesLength % 2 != 0 || at + schemesLength + 2 > end) {
                throw StrictExtensions.decodeError("a malformed signature algorithm list in the "
                        + "CertificateRequest");
            }
            List<Integer> schemes = new ArrayList<>();
            for (int i = 0; i < schemesLength; i += 2) {
                schemes.add(Handshake.u16(message, at + i));
            }
            at += schemesLength;
            int authorities = Handshake.u16(message, at);
            if (at + 2 + authorities != end) {
                throw StrictExtensions.decodeError("the CertificateRequest's authorities do not "
                        + "fill the message");
            }
            return new CertificateRequest(List.copyOf(schemes));
        }

        boolean accepts(int scheme) {
            return schemes.contains(scheme);
        }
    }

    private static void sendCertificate(RecordStream records, TranscriptHash transcript,
            ByteArrayOutputStream log, ClientIdentity identity, Arena arena) throws IOException {
        List<byte[]> chain = identity == null ? List.of() : identity.chain();
        int listLength = 0;
        for (byte[] certificate : chain) {
            listLength += 3 + certificate.length;
        }
        int length = Handshake.HEADER + 3 + listLength;
        MemorySegment message = arena.allocate(length);
        header(message, Handshake.CERTIFICATE, 3 + listLength);
        putU24(message, Handshake.HEADER, listLength);
        long at = Handshake.HEADER + 3;
        for (byte[] certificate : chain) {
            putU24(message, at, certificate.length);
            MemorySegment.copy(certificate, 0, message, ValueLayout.JAVA_BYTE, at + 3,
                    certificate.length);
            at += 3 + certificate.length;
        }
        records.write((byte) 22, message, 0, length);
        transcript.update(message, 0, length);
        log(log, message, 0, length);
    }

    private static void sendClientKeyExchange(RecordStream records, TranscriptHash transcript,
            ByteArrayOutputStream log, NativeP256 keyExchange, Arena arena) throws IOException {
        int length = Handshake.HEADER + 1 + NativeP256.PUBLIC_SIZE;
        MemorySegment message = arena.allocate(length);
        header(message, CLIENT_KEY_EXCHANGE, 1 + NativeP256.PUBLIC_SIZE);
        message.set(ValueLayout.JAVA_BYTE, Handshake.HEADER, (byte) NativeP256.PUBLIC_SIZE);
        keyExchange.publicKey(message.asSlice(Handshake.HEADER + 1, NativeP256.PUBLIC_SIZE));
        records.write((byte) 22, message, 0, length);
        transcript.update(message, 0, length);
        log(log, message, 0, length);
    }

    /**
     * CertificateVerify in TLS 1.2 signs the handshake messages themselves -
     * everything sent and received so far - with the hash the scheme names.
     */
    private static void sendCertificateVerify(RecordStream records, TranscriptHash transcript,
            ByteArrayOutputStream log, ClientIdentity identity, Arena arena) throws IOException {
        byte[] signature;
        try {
            signature = identity.sign(log.toByteArray());
        } catch (RuntimeException e) {
            throw new IOException("signing the client CertificateVerify failed: "
                    + e.getMessage(), e);
        }
        MemorySegment message = arena.allocate(Handshake.HEADER + 4L + signature.length);
        int length = CertificateVerifyMessage.write(message, identity.signatureScheme(), signature);
        records.write((byte) 22, message, 0, length);
        transcript.update(message, 0, length);
        log(log, message, 0, length);
    }

    /**
     * A HelloRequest after the handshake - the server asking to renegotiate.
     * This client never does; RFC 5746 lets it say so with a warning and carry
     * on.
     */
    static boolean isHelloRequest(int type) {
        return type == HELLO_REQUEST;
    }

    private static void due(boolean inOrder, int type, Expect expected)
            throws TlsProtocolException {
        if (!inOrder) {
            throw new TlsProtocolException(TlsAlertException.UNEXPECTED_MESSAGE,
                    "the server sent " + messageName(type) + " where " + expected.wanted
                            + " was due");
        }
    }

    private static String messageName(int type) {
        return switch (type) {
            case Handshake.CERTIFICATE -> "Certificate";
            case SERVER_KEY_EXCHANGE -> "ServerKeyExchange";
            case Handshake.CERTIFICATE_REQUEST -> "CertificateRequest";
            case SERVER_HELLO_DONE -> "ServerHelloDone";
            case Handshake.NEW_SESSION_TICKET -> "NewSessionTicket";
            case Handshake.FINISHED -> "Finished";
            default -> "handshake message " + type;
        };
    }

    private static void log(ByteArrayOutputStream log, MemorySegment message, long start,
            int length) {
        if (log != null) {
            log.writeBytes(message.asSlice(start, length).toArray(ValueLayout.JAVA_BYTE));
        }
    }

    private static void header(MemorySegment message, int type, int length) {
        message.set(ValueLayout.JAVA_BYTE, 0, (byte) type);
        putU24(message, 1, length);
    }

    private static void putU24(MemorySegment out, long at, int value) {
        out.set(ValueLayout.JAVA_BYTE, at, (byte) (value >>> 16));
        out.set(ValueLayout.JAVA_BYTE, at + 1, (byte) (value >>> 8));
        out.set(ValueLayout.JAVA_BYTE, at + 2, (byte) value);
    }

    private static int u24(MemorySegment data, long at) {
        return ((data.get(ValueLayout.JAVA_BYTE, at) & 0xff) << 16)
                | ((data.get(ValueLayout.JAVA_BYTE, at + 1) & 0xff) << 8)
                | (data.get(ValueLayout.JAVA_BYTE, at + 2) & 0xff);
    }
}
