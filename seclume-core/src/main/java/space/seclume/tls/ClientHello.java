package space.seclume.tls;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

/**
 * The first flight of a TLS 1.3 client, written into the caller's native buffer.
 *
 * <p>This is an encoder, not a TLS connection. It offers AES-GCM with SHA-256
 * or SHA-384 and one X25519 or P-256 share, without PSK, early data or client certificates.
 * The caller owns generation and lifetime of the ephemeral private key; only
 * its public share belongs here. No JCA key generation or agreement is hidden
 * in this class. See the TLS design for the outstanding key-exchange work.
 *
 * <p>The result includes the handshake header, but no record header. Feed these
 * exact bytes to the transcript and frame them as a plaintext handshake record.
 * Random and session id must be fresh for each connection. A retry encoder and
 * the middlebox compatibility ChangeCipherSpec are not implemented here.
 */
public final class ClientHello {
    public static final int AES_128_GCM_SHA256 = 0x1301;
    public static final int AES_256_GCM_SHA384 = 0x1302;
    public static final int X25519 = 0x001d;
    public static final int SECP256R1 = 0x0017;
    public static final int SECP384R1 = 0x0018;
    /** RFC 8446: the cookie a HelloRetryRequest may carry, echoed in the second ClientHello. */
    public static final int EXTENSION_COOKIE = 44;
    private static final int TLS13 = 0x0304;
    private static final int TLS12 = 0x0303;
    private static final int SIGNATURE_ALGORITHMS_CERT = 50;

    /** TLS 1.2 suites: ECDHE and AES-GCM only - see {@link Offer#TLS13_AND_12}. */
    public static final int ECDHE_ECDSA_AES_256_GCM_SHA384 = 0xC02C;
    public static final int ECDHE_RSA_AES_256_GCM_SHA384 = 0xC030;
    public static final int ECDHE_ECDSA_AES_128_GCM_SHA256 = 0xC02B;
    public static final int ECDHE_RSA_AES_128_GCM_SHA256 = 0xC02F;
    /** RFC 4492: ec_point_formats, uncompressed only. */
    public static final int EXTENSION_EC_POINT_FORMATS = 11;
    /** RFC 7627: extended_master_secret. */
    public static final int EXTENSION_EXTENDED_MASTER_SECRET = 23;
    /** RFC 5746: renegotiation_info. */
    public static final int EXTENSION_RENEGOTIATION_INFO = 0xff01;

    /**
     * Which versions a ClientHello offers.
     *
     * <p>TLS 1.2 is offered as a deliberately small profile: ECDHE on P-256,
     * AES-GCM, the extended master secret, and nothing else - no static RSA
     * key exchange, no CBC, no renegotiation, no resumption. Those are the
     * parts of TLS 1.2 whose history is padding oracles and Lucky13; leaving
     * them out leaves a protocol whose record layer is the same AEAD as TLS
     * 1.3's and whose key exchange is the same group.
     */
    public enum Offer {
        /** TLS 1.3 alone. */
        TLS13,
        /** TLS 1.3 first, the TLS 1.2 profile for a server without it. */
        TLS13_AND_12,
        /**
         * The TLS 1.2 profile alone - for TDS 7.4, whose handshake inside the
         * pre-login packets cannot carry TLS 1.3 at all.
         */
        TLS12
    }

    private ClientHello() {
    }

    /**
     * Encodes a ClientHello, returning the number of bytes written.
     *
     * @param random exactly 32 public random bytes
     * @param sessionId 0 to 32 public bytes; 32 enables middlebox compatibility
     * @param publicShare exactly 32 bytes, X25519's little-endian public u-coordinate
     * @param serverName an ASCII DNS name for SNI, or null to omit SNI (e.g. an IP address)
     * @throws IllegalArgumentException for wrong input sizes or a non-DNS SNI name
     * @throws IndexOutOfBoundsException if the destination is too short
     */
    public static int write(MemorySegment out, long offset, MemorySegment random,
            MemorySegment sessionId, MemorySegment publicShare, String serverName) {
        return write(out, offset, random, sessionId, X25519, publicShare, serverName);
    }

    /**
     * As above, with an explicit group. P-256 needs a 65-byte uncompressed point
     * (0x04, then two 32-byte big-endian coordinates). Only this group is offered;
     * choosing a group the server does not support will fail negotiation.
     * Public-point validation belongs to the key-exchange implementation.
     */
    public static int write(MemorySegment out, long offset, MemorySegment random,
            MemorySegment sessionId, int group, MemorySegment publicShare, String serverName) {
        return write(out, offset, random, sessionId, group, publicShare, serverName, null);
    }

    /**
     * As above, offering one application protocol.
     *
     * <p>ALPN, and it is here for one reason: <b>TDS 8.0 requires it.</b> SQL
     * Server's strict encryption puts TLS around the whole connection from
     * the first byte, and the way it tells that apart from anything else
     * arriving on port 1433 is the protocol name {@code tds/8.0} in this
     * extension. Without it the server has no way to know what it is talking
     * to, and says so by hanging up.
     *
     * <p>One name, not a list. A list is what a browser needs, and every
     * entry on it is a branch afterwards; here the caller knows exactly which
     * protocol it intends to speak and a second-choice answer would be no use
     * to it.
     *
     * @param alpn the protocol name, ASCII, or null to omit the extension
     */
    public static int write(MemorySegment out, long offset, MemorySegment random,
            MemorySegment sessionId, int group, MemorySegment publicShare, String serverName,
            String alpn) {
        return write(out, offset, random, sessionId, new int[] {group},
                new MemorySegment[] {publicShare}, serverName, alpn);
    }

    /** The hybrid post-quantum group, X25519MLKEM768 - see HybridMlKem. */
    public static final int X25519MLKEM768 = 0x11EC;

    /**
     * As above, offering a share for each of several groups, in order of
     * preference - the post-quantum hybrid first and P-256 beside it, so that
     * a server without the hybrid picks P-256 at once rather than asking for a
     * retry this client does not do.
     */
    public static int write(MemorySegment out, long offset, MemorySegment random,
            MemorySegment sessionId, int[] groups, MemorySegment[] publicShares,
            String serverName, String alpn) {
        return write(out, offset, random, sessionId, groups, publicShares, serverName, alpn,
                Offer.TLS13);
    }

    /**
     * As above, saying which versions are offered. With TLS 1.2 in the offer
     * the groups are still the key shares' groups, and a TLS 1.2 server picks
     * one of them for its ServerKeyExchange - in practice P-256, the only one
     * TLS 1.2 can use.
     */
    public static int write(MemorySegment out, long offset, MemorySegment random,
            MemorySegment sessionId, int[] groups, MemorySegment[] publicShares,
            String serverName, String alpn, Offer offer) {
        return write(out, offset, random, sessionId, groups, groups, publicShares, serverName,
                alpn, offer, null);
    }

    /**
     * The general form: the groups offered in {@code supported_groups}, in order
     * of preference, apart from the ones a key share goes with - so that a group
     * can be offered without the cost of a share, and asked for by a
     * HelloRetryRequest - and the cookie such a request may have sent.
     *
     * @param supportedGroups every group offered, in order of preference
     * @param shareGroups     the groups a key share is sent for, a subset of them;
     *                        ignored when TLS 1.3 is not offered
     * @param cookie          the HelloRetryRequest's cookie, or null
     */
    public static int write(MemorySegment out, long offset, MemorySegment random,
            MemorySegment sessionId, int[] supportedGroups, int[] shareGroups,
            MemorySegment[] publicShares, String serverName, String alpn, Offer offer,
            MemorySegment cookie) {
        boolean offers13 = offer != Offer.TLS12;
        boolean offers12 = offer != Offer.TLS13;
        int[] groups = shareGroups;
        if (supportedGroups.length == 0 || groups.length != publicShares.length
                || offers13 && groups.length == 0) {
            throw new IllegalArgumentException("one public share per group, and a group offered");
        }
        int sharesLength = 0;
        for (int i = 0; i < groups.length; i++) {
            int expected = switch (groups[i]) {
                case X25519 -> 32;
                case SECP256R1 -> 65;
                case SECP384R1 -> 97;
                case X25519MLKEM768 -> space.seclume.crypto.HybridMlKem.CLIENT_SHARE;
                default -> throw new IllegalArgumentException("unsupported key share group: "
                        + groups[i]);
            };
            if (publicShares[i].byteSize() != expected) {
                throw new IllegalArgumentException("wrong public share length for group "
                        + groups[i]);
            }
            if ((groups[i] == SECP256R1 || groups[i] == SECP384R1)
                    && publicShares[i].get(java.lang.foreign.ValueLayout.JAVA_BYTE, 0) != 4) {
                throw new IllegalArgumentException("a NIST curve needs an uncompressed point");
            }
            sharesLength += 4 + expected;
        }
        if (random.byteSize() != 32 || sessionId.byteSize() > 32) {
            throw new IllegalArgumentException("wrong random or session id length");
        }
        String name = dnsName(serverName); // public routing metadata, never a secret
        int sessionLength = (int) sessionId.byteSize();
        // supported_versions (7), groups (6 + 2 per group), signatures (6 + 2
        // per scheme), certificate signatures (6 + 2 per scheme + 6),
        // key_share (6 + the shares), optional server_name (9 + name).
        int alpnLength = alpn == null ? 0 : 4 + 2 + 1 + alpn.length();
        // supported_versions with one or two versions, and the key shares, only
        // where TLS 1.3 is offered; ec_point_formats (6), extended_master_secret
        // (4), an empty renegotiation_info (5) and three more signature schemes
        // (6) only where TLS 1.2 is.
        int versionsLength = offers13 ? (offers12 ? 9 : 7) : 0;
        int signaturesLength = 6 + 2 * SIGNATURE_SCHEMES.length + (offers12 ? 6 : 0);
        int certificateSignaturesLength = 6 + 2 * SIGNATURE_SCHEMES.length + 6;
        int cookieLength = cookie == null ? 0 : 4 + 2 + (int) cookie.byteSize();
        int extensions = versionsLength + 6 + 2 * supportedGroups.length + signaturesLength
                + certificateSignaturesLength
                + (offers13 ? 6 + sharesLength : 0)
                + (offers12 ? 6 + 4 + 5 : 0)
                + (name == null ? 0 : 9 + name.length()) + alpnLength + cookieLength;
        int suites = (offers13 ? 4 : 0) + (offers12 ? 8 : 0);
        int body = 2 + 32 + 1 + sessionLength + 2 + suites + 1 + 1 + 2 + extensions;
        int length = Handshake.HEADER + body;
        // Validate the entire output range before writing anything.
        ByteBuffer buffer = out.asSlice(offset, length).asByteBuffer();
        buffer.put((byte) Handshake.CLIENT_HELLO);
        buffer.put((byte) (body >>> 16)).putShort((short) body);
        buffer.putShort((short) Handshake.LEGACY_VERSION);
        buffer.put(random.asByteBuffer());
        buffer.put((byte) sessionLength).put(sessionId.asByteBuffer());
        buffer.putShort((short) suites);
        if (offers13) {
            buffer.putShort((short) AES_256_GCM_SHA384).putShort((short) AES_128_GCM_SHA256);
        }
        if (offers12) {
            buffer.putShort((short) ECDHE_ECDSA_AES_256_GCM_SHA384)
                    .putShort((short) ECDHE_RSA_AES_256_GCM_SHA384)
                    .putShort((short) ECDHE_ECDSA_AES_128_GCM_SHA256)
                    .putShort((short) ECDHE_RSA_AES_128_GCM_SHA256);
        }
        buffer.put((byte) 1).put((byte) 0); // only null legacy compression
        buffer.putShort((short) extensions);

        if (name != null) {
            extension(buffer, Handshake.EXTENSION_SERVER_NAME, 5 + name.length());
            buffer.putShort((short) (3 + name.length()));
            buffer.put((byte) 0).putShort((short) name.length());
            for (int i = 0; i < name.length(); i++) {
                buffer.put((byte) name.charAt(i));
            }
        }
        if (offers13) {
            extension(buffer, Handshake.EXTENSION_SUPPORTED_VERSIONS, offers12 ? 5 : 3);
            buffer.put((byte) (offers12 ? 4 : 2)).putShort((short) TLS13);
            if (offers12) {
                buffer.putShort((short) TLS12);
            }
        }
        extension(buffer, Handshake.EXTENSION_SUPPORTED_GROUPS, 2 + 2 * supportedGroups.length);
        buffer.putShort((short) (2 * supportedGroups.length));
        for (int group : supportedGroups) {
            buffer.putShort((short) group);
        }

        // CertificateVerify: RSA-PSS with rsaEncryption keys, or ECDSA. With
        // TLS 1.2 on offer, RSA PKCS#1 v1.5 as well - for its ServerKeyExchange
        // only: RFC 8446 section 4.2.3 forbids a TLS 1.3 server to use it, and
        // the TLS 1.3 path does not accept it.
        extension(buffer, Handshake.EXTENSION_SIGNATURE_ALGORITHMS, signaturesLength - 4);
        buffer.putShort((short) (signaturesLength - 6));
        signatures(buffer);
        if (offers12) {
            buffer.putShort((short) 0x0401).putShort((short) 0x0501).putShort((short) 0x0601);
        }
        // Certificates may additionally be signed with RSA PKCS#1 v1.5.
        // Those schemes are deliberately absent from CertificateVerify's list.
        extension(buffer, SIGNATURE_ALGORITHMS_CERT, certificateSignaturesLength - 4);
        buffer.putShort((short) (certificateSignaturesLength - 6));
        signatures(buffer);
        buffer.putShort((short) 0x0401).putShort((short) 0x0501).putShort((short) 0x0601);

        if (offers13) {
            extension(buffer, Handshake.EXTENSION_KEY_SHARE, 2 + sharesLength);
            buffer.putShort((short) sharesLength);
            for (int i = 0; i < groups.length; i++) {
                buffer.putShort((short) groups[i]).putShort((short) publicShares[i].byteSize());
                buffer.put(publicShares[i].asByteBuffer());
            }
        }
        if (offers12) {
            extension(buffer, EXTENSION_EC_POINT_FORMATS, 2);
            buffer.put((byte) 1).put((byte) 0);              // uncompressed
            extension(buffer, EXTENSION_EXTENDED_MASTER_SECRET, 0);
            // RFC 5746, as the extension rather than the signalling suite: an
            // initial handshake, so renegotiated_connection is empty. Some
            // servers answer only the extension; every one answers it.
            extension(buffer, EXTENSION_RENEGOTIATION_INFO, 1);
            buffer.put((byte) 0);
        }
        if (cookie != null) {
            extension(buffer, EXTENSION_COOKIE, 2 + (int) cookie.byteSize());
            buffer.putShort((short) cookie.byteSize());
            buffer.put(cookie.asByteBuffer());
        }

        if (alpn != null) {
            extension(buffer, EXTENSION_ALPN, 2 + 1 + alpn.length());
            buffer.putShort((short) (1 + alpn.length()));
            buffer.put((byte) alpn.length());
            for (int i = 0; i < alpn.length(); i++) {
                buffer.put((byte) alpn.charAt(i));
            }
        }
        return length;
    }

    /** RFC 7301, application_layer_protocol_negotiation. */
    public static final int EXTENSION_ALPN = 16;

    /**
     * What a server may sign with, in order of preference: RSA-PSS for an
     * ordinary RSA key, ECDSA, EdDSA, and RSA-PSS for a key that is itself
     * RSASSA-PSS ({@code rsa_pss_pss_*}). Every one is verified by the JDK -
     * see {@link HandshakeSignature}, which has to understand exactly these.
     */
    static final int[] SIGNATURE_SCHEMES = {
        HandshakeSignature.RSA_PSS_RSAE_SHA256, HandshakeSignature.RSA_PSS_RSAE_SHA384,
        HandshakeSignature.RSA_PSS_RSAE_SHA512,
        HandshakeSignature.ECDSA_SECP256R1_SHA256, HandshakeSignature.ECDSA_SECP384R1_SHA384,
        HandshakeSignature.ECDSA_SECP521R1_SHA512,
        HandshakeSignature.ED25519, HandshakeSignature.ED448,
        HandshakeSignature.RSA_PSS_PSS_SHA256, HandshakeSignature.RSA_PSS_PSS_SHA384,
        HandshakeSignature.RSA_PSS_PSS_SHA512,
    };

    private static void signatures(ByteBuffer buffer) {
        for (int scheme : SIGNATURE_SCHEMES) {
            buffer.putShort((short) scheme);
        }
    }

    private static void extension(ByteBuffer buffer, int type, int length) {
        buffer.putShort((short) type).putShort((short) length);
    }

    private static String dnsName(String name) {
        if (name == null) {
            return null;
        }
        if (name.isEmpty() || name.length() > 253 || name.matches("[0-9.]+")) {
            throw new IllegalArgumentException("SNI must be an ASCII DNS name, not an IP address");
        }
        for (String label : name.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || label.charAt(0) == '-'
                    || label.charAt(label.length() - 1) == '-') {
                throw new IllegalArgumentException("invalid SNI DNS label");
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
                        || c >= '0' && c <= '9' || c == '-')) {
                    throw new IllegalArgumentException("SNI requires an ASCII DNS name");
                }
            }
        }
        return name;
    }
}
