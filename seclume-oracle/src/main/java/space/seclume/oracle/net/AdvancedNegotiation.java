package space.seclume.oracle.net;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Locale;

import space.seclume.crypto.DiffieHellman;
import space.seclume.internal.WireBuffer;
import space.seclume.secret.SecretScope;

/**
 * Oracle Net's advanced negotiation (ANO): right after the listener's ACCEPT
 * and before TTC, client and server agree on the services the connection
 * runs under - here: Native Network Encryption and its checksums - and on
 * a Diffie-Hellman secret to key them with.
 *
 * <p>The messages travel in ordinary DATA packets. Each starts with
 * {@code DEADBEEF}, its length, a version and the number of services; each
 * service with its type, the number of fields and an error code; each field
 * with its length and type. The client offers supervisor, authentication
 * (none, or a login by the operating system - Kerberos or NTS), encryption
 * (AES-256/192/128) and data integrity (SHA-256/384/512);
 * the server picks one of each and, when a key is needed, sends a
 * Diffie-Hellman group, its public value and an IV, and the client answers
 * with its own public value.
 *
 * <p>The format follows go-ora (MIT licence - see NOTICE), and was checked
 * against Oracle Free 23 with {@code SQLNET.ENCRYPTION_SERVER} and
 * {@code SQLNET.CRYPTO_CHECKSUM_SERVER} set to REQUIRED.
 */
public final class AdvancedNegotiation {

    /** What the client asks for. */
    public enum Mode {
        /** Never: a server that requires it is refused, with the reason. */
        OFF,
        /**
         * The default, as with Oracle's own client: not offered in the CONNECT,
         * but negotiated when the server's ACCEPT asks for it - a listener
         * with SQLNET.ENCRYPTION_SERVER=REQUIRED works without a setting, and
         * any other costs nothing.
         */
        ACCEPTED,
        /** Offered in the CONNECT; used when the server agrees, plain when it does not. */
        REQUESTED,
        /** Offered, and the connection refused without it. */
        REQUIRED;

        /** From the URL option {@code nativeEncryption}. */
        public static Mode of(String value) {
            if (value == null || value.isBlank()) {
                return ACCEPTED;
            }
            return switch (value.trim().toLowerCase(Locale.ROOT)) {
                case "off", "false", "rejected" -> OFF;
                case "accepted" -> ACCEPTED;
                case "requested", "on", "true" -> REQUESTED;
                case "required" -> REQUIRED;
                default -> throw new IllegalArgumentException("nativeEncryption is off, "
                        + "accepted, requested or required, not '" + value + "'");
            };
        }

        /** Whether the CONNECT offers the negotiation. */
        public boolean offered() {
            return this == REQUESTED || this == REQUIRED;
        }
    }

    private static final int MAGIC = 0xDEADBEEF;
    private static final int VERSION = 0x0B200200;
    private static final int SUPERVISOR = 4;
    private static final int AUTHENTICATION = 1;
    private static final int ENCRYPTION = 2;
    private static final int INTEGRITY = 3;
    private static final int FIELD_STRING = 0;
    private static final int FIELD_BYTES = 1;
    private static final int FIELD_UB1 = 2;
    private static final int FIELD_UB2 = 3;
    private static final int FIELD_UB4 = 4;
    private static final int FIELD_VERSION = 5;
    private static final int FIELD_STATUS = 6;
    private static final byte[] CLIENT_ID = {0, 0, 16, 28, 102, 236 - 256, 40, 234 - 256};
    private static final int[] SERVICES = {SUPERVISOR, AUTHENTICATION, ENCRYPTION, INTEGRITY};
    private static final String KERBEROS5 = "KERBEROS5";
    private static final String NTS = "NTS";

    private AdvancedNegotiation() {
    }

    /**
     * Whether the server's ACCEPT asks for the negotiation - it does when the
     * CONNECT offered it and the server has not switched it off.
     */
    static boolean wanted(int acceptFlags0, int acceptFlags1) {
        return (acceptFlags0 & 1) != 0 && (acceptFlags0 & 4) == 0 && (acceptFlags1 & 8) == 0;
    }

    /**
     * Runs the negotiation on a channel that has just read the ACCEPT.
     *
     * @param authService the login by the operating system the authentication
     *                    service offers - {@code KERBEROS5} (see
     *                    {@link #kerberos}) or {@code NTS} (see {@link #nts})
     *                    - or null for a password login after the negotiation
     * @return the encryption to switch on once the negotiation is over, or
     *         null when the server settled on none
     */
    static NativeEncryption negotiate(NsChannel channel, Mode mode, String authService)
            throws IOException {
        if (authService != null && !KERBEROS5.equals(authService) && !NTS.equals(authService)) {
            throw new IllegalArgumentException("no login by " + authService);
        }
        boolean osLogin = authService != null;
        boolean insist = mode == Mode.REQUIRED;
        boolean none = mode == Mode.OFF;                    // only for a Kerberos login
        byte[] encryption = none ? new byte[] {0} : insist
                ? new byte[] {NativeEncryption.AES256, NativeEncryption.AES192,
                        NativeEncryption.AES128}
                : new byte[] {NativeEncryption.AES256, NativeEncryption.AES192,
                        NativeEncryption.AES128, 0};
        byte[] integrity = none ? new byte[] {0} : insist
                ? new byte[] {NativeEncryption.SHA256, NativeEncryption.SHA384,
                        NativeEncryption.SHA512}
                : new byte[] {NativeEncryption.SHA256, NativeEncryption.SHA384,
                        NativeEncryption.SHA512, 0};

        WireBuffer out = channel.beginData();
        int supervisor = 8 + (4 + 4) + (4 + CLIENT_ID.length) + (4 + 10 + 2 * SERVICES.length);
        int authentication = 8 + (4 + 4) + (4 + 2) + (4 + 2)
                + (osLogin ? (4 + 1) + (4 + authService.length()) : 0);
        int encrypt = 8 + (4 + 4) + (4 + encryption.length) + (4 + 1);
        int check = 8 + (4 + 4) + (4 + integrity.length);
        header(out, 13 + supervisor + authentication + encrypt + check, SERVICES.length);
        serviceHeader(out, SUPERVISOR, 3);
        version(out);
        bytes(out, CLIENT_ID);
        field(out, 10 + 2 * SERVICES.length, FIELD_BYTES);
        out.putInt(MAGIC).putShort((short) 3).putInt(SERVICES.length);
        for (int service : SERVICES) {
            out.putShort((short) service);
        }
        serviceHeader(out, AUTHENTICATION, osLogin ? 5 : 3);
        version(out);
        field(out, 2, FIELD_UB2);
        out.putShort((short) 0xE0E1);
        field(out, 2, FIELD_STATUS);
        out.putShort((short) 0xFCFF);
        if (osLogin) {
            field(out, 1, FIELD_UB1);
            out.putByte((byte) 1);                          // the adapter's number
            field(out, authService.length(), FIELD_STRING);
            byte[] name = authService.getBytes(java.nio.charset.StandardCharsets.US_ASCII); // seclume-allow: a service name
            out.putBytes(MemorySegment.ofArray(name), 0, name.length);
        }
        serviceHeader(out, ENCRYPTION, 3);
        version(out);
        bytes(out, encryption);
        field(out, 1, FIELD_UB1);
        out.putByte((byte) 1);
        serviceHeader(out, INTEGRITY, 2);
        version(out);
        bytes(out, integrity);
        channel.sendData();

        WireBuffer in = answer(channel);
        int services = readHeader(in);
        int chosenEncryption = 0;
        int chosenIntegrity = 0;
        boolean loginChosen = false;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment generator = null;
            MemorySegment prime = null;
            MemorySegment serverPublic = null;
            MemorySegment iv = null;
            for (int s = 0; s < services; s++) {
                int service = in.getShort() & 0xffff;
                int fields = in.getShort() & 0xffff;
                checkError(in.getInt());
                switch (service) {
                    case SUPERVISOR -> {
                        readVersion(in);
                        int status = readStatus(in);
                        if (status != 31) {
                            throw new IOException("the supervisor service answered " + status);
                        }
                        in.skip(expect(in, FIELD_BYTES));
                    }
                    case AUTHENTICATION -> {
                        readVersion(in);
                        int status = readStatus(in);
                        if (status == 0xFAFF && fields > 2) {
                            in.skip(expect(in, FIELD_UB1));
                            String name = in.readString(expect(in, FIELD_STRING));
                            if (fields > 4) {
                                readVersion(in);
                                in.skip(expect(in, FIELD_UB4));
                                in.skip(expect(in, FIELD_UB4));
                            }
                            if (!name.equals(authService)) {
                                throw new IOException("the server wants authentication by "
                                        + name + " in the negotiation, which this connection "
                                        + "does not offer");
                            }
                            loginChosen = true;
                        } else if (status != 0xFBFF) {
                            throw new IOException("the authentication service answered 0x"
                                    + Integer.toHexString(status));
                        }
                    }
                    case ENCRYPTION -> {
                        readVersion(in);
                        expect(in, FIELD_UB1);
                        chosenEncryption = in.getByte() & 0xff;
                    }
                    case INTEGRITY -> {
                        readVersion(in);
                        expect(in, FIELD_UB1);
                        chosenIntegrity = in.getByte() & 0xff;
                        if (fields == 8) {
                            expect(in, FIELD_UB2);
                            in.getShort();                  // generator length, in bits
                            expect(in, FIELD_UB2);
                            in.getShort();                  // prime length, in bits
                            generator = copy(in, arena, expect(in, FIELD_BYTES));
                            prime = copy(in, arena, expect(in, FIELD_BYTES));
                            serverPublic = copy(in, arena, expect(in, FIELD_BYTES));
                            iv = copy(in, arena, expect(in, FIELD_BYTES));
                        }
                    }
                    default -> throw new IOException("the negotiation answered for service "
                            + service);
                }
            }
            if (osLogin && !loginChosen) {
                throw new IOException("the server did not take up " + authService + " - is "
                        + "SQLNET.AUTHENTICATION_SERVICES set to " + authService + " on it?");
            }
            boolean kerberosChosen = loginChosen && KERBEROS5.equals(authService);
            boolean ntsChosen = loginChosen && NTS.equals(authService);
            boolean encrypted = chosenEncryption != 0 || chosenIntegrity != 0;
            if (insist && chosenEncryption == 0) {
                throw new IOException(chosenIntegrity == 0
                        ? "the server agreed to no native encryption, and nativeEncryption=required"
                        : "the server agreed to checksums but not to encryption, and "
                                + "nativeEncryption=required");
            }
            if (encrypted && (prime == null || generator == null || serverPublic == null)) {
                throw new IOException("the server chose encryption but sent no Diffie-Hellman "
                        + "group to key it with");
            }

            // One message for what the client still owes: its public value, and
            // the opening of the Kerberos or NTS exchange.
            DiffieHellman dh = null;
            space.seclume.internal.Gssapi.Context ntlm = null;
            try {
                int length = encrypted ? (int) prime.byteSize() : 0;
                if (encrypted && serverPublic.byteSize() != length) {
                    throw new IOException("the server's public value has "
                            + serverPublic.byteSize() + " bytes for a group of " + length);
                }
                byte[] negotiateMessage = null;
                if (ntsChosen) {
                    ntlm = ntlm();
                    negotiateMessage = step(ntlm, null, 0);
                }
                if (encrypted || loginChosen) {
                    WireBuffer answer = channel.beginData();
                    int size = 13 + (encrypted ? 8 + 4 + length : 0) + (kerberosChosen ? 37 : 0)
                            + (ntsChosen ? 8 + 7 * 4 + 4 + 4 + 4 + 20 + 4 + 4
                                    + negotiateMessage.length : 0);
                    header(answer, size, (encrypted ? 1 : 0) + (loginChosen ? 1 : 0));
                    if (encrypted) {
                        dh = DiffieHellman.generate(prime, 0, length, generator, 0,
                                (int) generator.byteSize(), length);
                        MemorySegment own = arena.allocate(length);
                        dh.publicValue(own, 0);
                        serviceHeader(answer, INTEGRITY, 1);
                        field(answer, length, FIELD_BYTES);
                        answer.putBytes(own, 0, length);
                    }
                    if (kerberosChosen) {
                        serviceHeader(answer, AUTHENTICATION, 4);
                        version(answer);
                        field(answer, 4, FIELD_UB4);
                        answer.putInt(9);
                        field(answer, 4, FIELD_UB4);
                        answer.putInt(2);
                        field(answer, 1, FIELD_UB1);
                        answer.putByte((byte) 1);
                    }
                    if (ntsChosen) {
                        ntsNegotiate(answer, negotiateMessage);
                    }
                    channel.sendData();
                }
                if (kerberosChosen) {
                    kerberos(channel);
                }
                if (ntsChosen) {
                    nts(channel, ntlm);
                }
                if (!encrypted) {
                    return null;
                }
                try (SecretScope shared = dh.sharedSecret(serverPublic, 0, length)) {
                    return new NativeEncryption(chosenEncryption, chosenIntegrity, shared, iv);
                } catch (IllegalArgumentException e) {
                    throw new IOException("native encryption: " + e.getMessage(), e);
                }
            } finally {
                if (dh != null) {
                    dh.close();
                }
                if (ntlm != null) {
                    ntlm.close();
                }
            }
        }
    }

    /**
     * The Kerberos exchange inside the negotiation: the server names its
     * service and host, the client answers with an AP-REQ for
     * {@code service/host} - from the system's GSSAPI or SSPI, which hold the
     * ticket - and the server's AP-REP comes back and is checked, so the
     * login counts only once the server has proved it holds the service's
     * key. Oracle takes the bare Kerberos messages, without the GSS-API
     * framing the libraries put around them.
     */
    private static void kerberos(NsChannel channel) throws IOException {
        WireBuffer in = answer(channel);
        int services = readHeader(in);
        for (int s = 0; s < services; s++) {
            in.getShort();
            in.getShort();
            checkError(in.getInt());
        }
        String service = in.readString(expect(in, FIELD_STRING));
        String host = in.readString(expect(in, FIELD_STRING));
        if (service.isEmpty() || host.isEmpty()) {
            throw new IOException("the server named no Kerberos service or host");
        }
        if (!space.seclume.internal.Gssapi.available()) {
            throw new IOException("Kerberos needs the system's GSSAPI library on Linux or "
                    + "SSPI on Windows, and neither is there");
        }
        try (space.seclume.internal.Gssapi.Context gss =
                     space.seclume.internal.Gssapi.initiate(service, host);
             Arena arena = Arena.ofConfined()) {
            byte[] framed = gss.step(null, 0, 0);
            int at = Krb5Token.innerOffset(framed, 0x01);
            int length = framed.length - at;
            byte[] address = localAddress(channel);
            WireBuffer out = channel.beginData();
            header(out, length + 43 + address.length, 1);
            serviceHeader(out, AUTHENTICATION, 4);
            field(out, 2, FIELD_UB2);
            out.putShort((short) (address.length == 4 ? 2 : 24));
            field(out, 4, FIELD_UB4);
            out.putInt(address.length);
            bytes(out, address);
            field(out, length, FIELD_BYTES);
            out.putBytes(MemorySegment.ofArray(framed), at, length);
            channel.sendData();

            WireBuffer reply = answer(channel);
            int count = readHeader(reply);
            for (int s = 0; s < count; s++) {
                reply.getShort();
                reply.getShort();
                checkError(reply.getInt());
            }
            reply.skip(expect(reply, FIELD_UB1));
            int apRepLength = expect(reply, FIELD_BYTES);
            MemorySegment apRep = copy(reply, arena, apRepLength);
            byte[] wrapped = Krb5Token.frame(apRep, 0x02);
            MemorySegment token = arena.allocate(wrapped.length);
            MemorySegment.copy(wrapped, 0, token, java.lang.foreign.ValueLayout.JAVA_BYTE, 0,
                    wrapped.length);
            gss.step(token, 0, wrapped.length);
            if (!gss.complete()) {
                throw new IOException("the server's Kerberos answer did not prove it holds the "
                        + "key of " + service + "/" + host + " - refused, as it could be anybody");
            }

            WireBuffer done = channel.beginData();
            header(done, 25, 1);
            serviceHeader(done, AUTHENTICATION, 1);
            field(done, 0, FIELD_BYTES);
            channel.sendData();
        } catch (IllegalStateException refused) {
            throw new IOException("Kerberos login with " + service + "/" + host + " failed: "
                    + refused.getMessage(), refused);
        }
    }

    /**
     * Oracle's Windows native authentication (NTS) inside the negotiation:
     * NTLM's three messages - negotiate, challenge, authenticate - each in
     * the authentication service, from SSPI with the logon session's
     * credentials. NTLM proves nothing about the server; there is no answer
     * to check after the last message.
     */
    private static space.seclume.internal.Gssapi.Context ntlm() throws IOException {
        if (!space.seclume.internal.Platform.isWindows()) {
            throw new IOException("Oracle's NTS login is Windows' own: it needs SSPI, and this "
                    + "is not Windows");
        }
        try {
            return space.seclume.internal.Gssapi.initiateNtlm(localHostName());
        } catch (IllegalStateException refused) {
            throw new IOException(refused.getMessage(), refused);
        }
    }

    /** The first NTS message: seven fields, the last the NTLM negotiate message. */
    private static void ntsNegotiate(WireBuffer out, byte[] negotiate) {
        serviceHeader(out, AUTHENTICATION, 7);
        field(out, 4, FIELD_VERSION);
        out.putInt(0x02000000);
        field(out, 4, FIELD_UB4);
        out.putInt(9);
        field(out, 4, FIELD_UB4);
        out.putInt(2);
        bytes(out, new byte[] {2, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        bytes(out, new byte[4]);
        ntsToken(out, negotiate);
    }

    /** The server's NTLM challenge, and the client's authenticate message to it. */
    private static void nts(NsChannel channel, space.seclume.internal.Gssapi.Context ntlm)
            throws IOException {
        WireBuffer in = answer(channel);
        int services = readHeader(in);
        for (int s = 0; s < services; s++) {
            in.getShort();
            in.getShort();
            checkError(in.getInt());
        }
        in.skip(expect(in, FIELD_BYTES));                  // the length again, little-endian
        int length = expect(in, FIELD_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment challenge = copy(in, arena, length);
            byte[] authenticate = step(ntlm, challenge, length);
            WireBuffer out = channel.beginData();
            // This one message carries version 0 in its header.
            out.putInt(MAGIC).putShort((short) (13 + 8 + 8 + 4 + authenticate.length))
                    .putInt(0).putShort((short) 1).putByte((byte) 0);
            serviceHeader(out, AUTHENTICATION, 2);
            ntsToken(out, authenticate);
            channel.sendData();
        }
    }

    /** An NTLM message: its length little-endian in a field of its own, then the message. */
    private static void ntsToken(WireBuffer out, byte[] message) {
        field(out, 4, FIELD_BYTES);
        out.putByte((byte) message.length).putByte((byte) (message.length >>> 8))
                .putByte((byte) (message.length >>> 16)).putByte((byte) (message.length >>> 24));
        bytes(out, message);
    }

    private static byte[] step(space.seclume.internal.Gssapi.Context context,
            MemorySegment token, int length) throws IOException {
        try {
            return context.step(token, 0, length);
        } catch (IllegalStateException refused) {
            throw new IOException("NTS login: " + refused.getMessage(), refused);
        }
    }

    private static String localHostName() {
        try {
            return java.net.InetAddress.getLocalHost().getHostName();
        } catch (java.net.UnknownHostException e) {
            return "localhost";
        }
    }

    /** The client's own address as the server sees the socket - IPv4 or IPv6. */
    private static byte[] localAddress(NsChannel channel) throws IOException {
        java.net.InetAddress local = channel.localAddress();
        if (local == null) {
            local = java.net.InetAddress.getLocalHost();
        }
        return local.getAddress();
    }

    private static WireBuffer answer(NsChannel channel) throws IOException {
        int type = channel.nextPacket();
        if (type != NsPacket.TYPE_DATA) {
            throw new IOException("the server answered the negotiation with "
                    + NsPacket.typeName(type));
        }
        return channel.packet();
    }

    /** The message header; the number of services that follow. */
    private static int readHeader(WireBuffer in) throws IOException {
        if (in.getInt() != MAGIC) {
            throw new IOException("the server's answer to the negotiation does not start with "
                    + "DEADBEEF");
        }
        in.getShort();                                      // length
        in.getInt();                                        // version
        int services = in.getShort() & 0xffff;
        in.getByte();                                       // error flags
        return services;
    }

    private static void checkError(int error) throws IOException {
        if (error != 0) {
            throw new IOException("the server refused the negotiation: ORA-" + error
                    + explain(error));
        }
    }

    /** What an ORA code in the negotiation usually means - the common ones. */
    private static String explain(int error) {
        return switch (error) {
            case 12650 -> " (no encryption or checksum algorithm in common)";
            case 12660 -> " (the server requires encryption or checksums)";
            case 12631 -> " (the Kerberos ticket could not be had or was refused)";
            case 12638 -> " (the server could not verify the credentials)";
            default -> "";
        };
    }

    private static void header(WireBuffer out, int length, int services) {
        out.putInt(MAGIC).putShort((short) length).putInt(VERSION).putShort((short) services)
                .putByte((byte) 0);
    }

    private static void serviceHeader(WireBuffer out, int service, int fields) {
        out.putShort((short) service).putShort((short) fields).putInt(0);
    }

    private static void field(WireBuffer out, int length, int type) {
        out.putShort((short) length).putShort((short) type);
    }

    private static void version(WireBuffer out) {
        field(out, 4, FIELD_VERSION);
        out.putInt(VERSION);
    }

    private static void bytes(WireBuffer out, byte[] value) {
        field(out, value.length, FIELD_BYTES);
        out.putBytes(MemorySegment.ofArray(value), 0, value.length);
    }

    /** A field's header; its length, after checking its type. */
    private static int expect(WireBuffer in, int type) throws IOException {
        int length = in.getShort() & 0xffff;
        int actual = in.getShort() & 0xffff;
        if (actual != type) {
            throw new IOException("the negotiation sent a field of type " + actual + " where "
                    + type + " belongs");
        }
        return length;
    }

    private static void readVersion(WireBuffer in) throws IOException {
        expect(in, FIELD_VERSION);
        in.getInt();
    }

    private static int readStatus(WireBuffer in) throws IOException {
        expect(in, FIELD_STATUS);
        return in.getShort() & 0xffff;
    }

    private static MemorySegment copy(WireBuffer in, Arena arena, int length) {
        MemorySegment target = arena.allocate(Math.max(1, length)).asSlice(0, length);
        MemorySegment.copy(in.segment(), in.position(), target, 0, length);
        in.skip(length);
        return target;
    }
}
