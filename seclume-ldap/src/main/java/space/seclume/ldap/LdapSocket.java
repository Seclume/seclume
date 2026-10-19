package space.seclume.ldap;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Arrays;

import space.seclume.internal.Gssapi;
import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.SecretScope;

/**
 * The socket JNDI gets: encrypted with seclume's TLS when JNDI connects (either
 * directly for {@code ldaps://} or after an RFC 4511 StartTLS
 * {@code ExtendedRequest} for {@code ldap://}), and a pipe for LDAP messages -
 * each of which is looked at once, on its way out.
 *
 * <p>An LDAP message is BER: {@code SEQUENCE { messageID, protocolOp,
 * controls? }}. When the operation is a {@code BindRequest} ({@code
 * [APPLICATION 0]}) with a simple password ({@code [0]}) that is a seclume
 * placeholder, the socket either writes the message again with the real
 * password - from the secret provider, in native memory - and with the lengths
 * of the three enclosing elements, or (when {@code authentication=kerberos} is
 * configured) drives the RFC 4752 {@code GSSAPI} SASL bind over the TLS channel
 * and hands the final {@code BindResponse} back to JNDI. Any other message, and
 * a bind with any other password, goes out as JNDI wrote it.
 */
final class LdapSocket extends Socket {

    private static final int SEQUENCE = 0x30;
    private static final int OCTET_STRING = 0x04;
    private static final int ENUMERATED = 0x0a;
    private static final int BIND_REQUEST = 0x60;
    private static final int BIND_RESPONSE = 0x61;
    private static final int EXTENDED_REQUEST = 0x77;
    private static final int EXTENDED_RESPONSE = 0x78;
    private static final int SIMPLE = 0x80;
    private static final int SERVER_SASL_CREDS = 0x87;
    private static final int SASL = 0xa3;
    private static final int SASL_BIND_IN_PROGRESS = 14;
    private static final int SASL_QOP_NO_PROTECTION = 0x01;
    private static final byte[] START_TLS_OID =
            "1.3.6.1.4.1.1466.20037".getBytes(StandardCharsets.US_ASCII); // seclume-allow: RFC 4511 StartTLS OID - no secret
    private static final byte[] GSSAPI_MECHANISM =
            "GSSAPI".getBytes(StandardCharsets.US_ASCII); // seclume-allow: SASL mechanism name - no secret
    private static final byte[] PREFIX =
            SeclumeLdap.PLACEHOLDER_PREFIX.getBytes(StandardCharsets.US_ASCII); // seclume-allow: the placeholder's prefix - no secret

    private final Object writing = new Object();
    private final Object handshakeLock = new Object();
    private final ByteArrayOutputStream pending = new ByteArrayOutputStream();
    private boolean firstMessagePending = true;
    private byte[] preRead;
    private int preReadOffset;
    private volatile LdapSettings settings;
    private volatile SocketTransport transport;
    private volatile TlsLayer tls;
    private volatile boolean closed;
    private int timeout;

    @Override
    public void connect(SocketAddress address, int connectTimeout) throws IOException {
        if (transport != null) {
            throw new SocketException("already connected");
        }
        if (!(address instanceof InetSocketAddress inet)) {
            throw new SocketException("an LDAP server is a host and a port");
        }
        String authority = (inet.getHostString().indexOf(':') >= 0
                ? "[" + inet.getHostString() + "]" : inet.getHostString()) + ":" + inet.getPort();
        LdapSettings found = SeclumeLdap.BY_AUTHORITY.get(authority);
        if (found == null) {
            throw new SocketException(authority + " was not set up with SeclumeLdap.of(...) - "
                    + "its URL names the host and port JNDI connects to");
        }
        SocketTransport opened = SocketTransport.connect(found.host, found.port,
                connectTimeout > 0 ? connectTimeout : found.connectTimeout);
        try {
            opened.networkTimeout(timeout > 0 ? timeout : found.timeout);
            if (found.startTls) {
                startTls(opened, found);
            }
            tls = TrustChoice.using(found.trust, () -> {
                try {
                    return TlsLayers.start(TlsStack.SECLUME, opened, found.host, found.port, true);
                } catch (IOException e) {
                    throw new SQLException(e.getMessage(), "08001", e);
                }
            });
            if (timeout == 0) {
                opened.networkTimeout(0);
            }
            settings = found;
            transport = opened;
        } catch (SQLException e) {
            opened.close();
            throw e.getCause() instanceof IOException io ? io : new IOException(e.getMessage(), e);
        } catch (IOException | RuntimeException e) {
            opened.close();
            throw e;
        }
    }

    /**
     * Sends RFC 4511 StartTLS {@code ExtendedRequest} ({@code 1.3.6.1.4.1.1466.20037})
     * and checks the {@code ExtendedResponse} before the TLS handshake starts.
     * Refuses if the server sends any trailing plaintext bytes after the response.
     */
    private static void startTls(SocketTransport opened, LdapSettings found) throws IOException {
        int extContent = 2 + START_TLS_OID.length;
        int msgContent = 3 + 2 + extContent;
        byte[] req = new byte[2 + msgContent];
        req[0] = (byte) SEQUENCE;
        req[1] = (byte) msgContent;
        req[2] = 0x02;
        req[3] = 0x01;
        req[4] = 0x01;
        req[5] = (byte) EXTENDED_REQUEST;
        req[6] = (byte) extContent;
        req[7] = (byte) SIMPLE;
        req[8] = (byte) START_TLS_OID.length;
        System.arraycopy(START_TLS_OID, 0, req, 9, START_TLS_OID.length);
        opened.write(ByteBuffer.wrap(req));

        byte[] buf = new byte[512];
        int readTotal = 0;
        int expected = -1;
        while (expected < 0 || readTotal < expected) {
            if (readTotal == buf.length) {
                if (buf.length >= 65536) {
                    throw new IOException("StartTLS response from " + found.authority()
                            + " exceeds 64 KiB");
                }
                buf = Arrays.copyOf(buf, buf.length * 2);
            }
            int n = opened.read(ByteBuffer.wrap(buf, readTotal, buf.length - readTotal));
            if (n < 0) {
                throw new EOFException("the LDAP server at " + found.authority()
                        + " closed the connection during StartTLS");
            }
            readTotal += n;
            expected = messageLength(buf, readTotal, 65536);
        }
        if (readTotal > expected) {
            throw new IOException("the LDAP server at " + found.authority()
                    + " sent bytes after the StartTLS response before the TLS handshake");
        }
        ParsedResult res = response(buf, expected, EXTENDED_RESPONSE);
        if (res.resultCode != 0) {
            throw new IOException("StartTLS on " + found.authority()
                    + " was refused by the server (LDAP result " + res.resultCode
                    + (res.diagnostic.isEmpty() ? ")" : ": " + res.diagnostic + ")"));
        }
    }

    @Override
    public void connect(SocketAddress address) throws IOException {
        connect(address, 0);
    }

    private final InputStream in = new InputStream() {
        private final byte[] one = new byte[1];

        @Override
        public int read() throws IOException {
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] target, int offset, int length) throws IOException {
            if (length == 0) {
                return 0;
            }
            synchronized (handshakeLock) {
                while (firstMessagePending && !closed) {
                    try {
                        handshakeLock.wait();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new InterruptedIOException("interrupted waiting for LDAP bind");
                    }
                }
                if (preRead != null && preReadOffset < preRead.length) {
                    int copy = Math.min(length, preRead.length - preReadOffset);
                    System.arraycopy(preRead, preReadOffset, target, offset, copy);
                    preReadOffset += copy;
                    if (preReadOffset >= preRead.length) {
                        preRead = null;
                        preReadOffset = 0;
                    }
                    return copy;
                }
            }
            return open().read(ByteBuffer.wrap(target, offset, length));
        }

        @Override
        public void close() {
            LdapSocket.this.close();
        }
    };

    private final OutputStream out = new OutputStream() {
        @Override
        public void write(int value) throws IOException {
            write(new byte[] {(byte) value}, 0, 1);
        }

        @Override
        public void write(byte[] source, int offset, int length) throws IOException {
            synchronized (writing) {
                pending.write(source, offset, length);
                sendComplete();
            }
        }

        @Override
        public void close() {
            LdapSocket.this.close();
        }
    };

    /** Sends every whole message collected so far; a partial one waits for the rest. */
    private void sendComplete() throws IOException {
        byte[] bytes = pending.toByteArray();
        int at = 0;
        while (true) {
            long[] header = header(bytes, at, bytes.length);
            if (header == null || at + header[0] + header[1] > bytes.length) {
                break;
            }
            int end = (int) (at + header[0] + header[1]);
            send(Arrays.copyOfRange(bytes, at, end));
            at = end;
        }
        pending.reset();
        pending.write(bytes, at, bytes.length - at);
    }

    /**
     * The tag and length at {@code at}: {@code {header size, content length}},
     * or {@code null} while the header is not complete.
     */
    private static long[] header(byte[] b, int at, int limit) throws IOException {
        if (limit - at < 2) {
            return null;
        }
        int first = b[at + 1] & 0xff;
        if (first < 0x80) {
            return new long[] {2, first};
        }
        int count = first & 0x7f;
        if (count == 0 || count > 4) {
            throw new IOException("an LDAP message with a BER length JNDI does not write");
        }
        long length = 0;
        for (int i = 0; i < count; i++) {
            int index = at + 2 + i;
            if (index >= limit) {
                return null;                           // the length is not all here yet
            }
            length = (length << 8) | (b[index] & 0xff);
        }
        return new long[] {2 + count, length};
    }

    private void send(byte[] message) throws IOException {
        try {
            if ((message[0] & 0xff) == SEQUENCE) {
                long[] outer = header(message, 0, message.length);
                int id = (int) outer[0];
                long[] idHeader = header(message, id, message.length);
                int op = (int) (id + idHeader[0] + idHeader[1]);
                if (op < message.length && (message[op] & 0xff) == BIND_REQUEST) {
                    long[] bind = header(message, op, message.length);
                    int version = (int) (op + bind[0]);
                    long[] versionHeader = header(message, version, message.length);
                    int name = (int) (version + versionHeader[0] + versionHeader[1]);
                    long[] nameHeader = header(message, name, message.length);
                    int auth = (int) (name + nameHeader[0] + nameHeader[1]);
                    if (auth < message.length && (message[auth] & 0xff) == SIMPLE) {
                        long[] authHeader = header(message, auth, message.length);
                        int value = (int) (auth + authHeader[0]);
                        byte[] password = Arrays.copyOfRange(message, value,
                                (int) (value + authHeader[1]));
                        if (startsWith(password, PREFIX)) {
                            LdapSettings registered = SeclumeLdap.BY_PLACEHOLDER.get(
                                    new String(password, StandardCharsets.US_ASCII)); // seclume-allow: the placeholder - no secret
                            if (registered == null) {
                                throw new IOException("a seclume placeholder no SeclumeLdap.of(...) "
                                        + "made - is the password from another instance's SeclumeLdap?");
                            }
                            if (registered.kerberos) {
                                bindKerberos(message, id, op, registered);
                            } else {
                                rewriteBind(message, op, bind, auth, authHeader, registered);
                            }
                            return;
                        }
                    }
                }
            }
            open().write(ByteBuffer.wrap(message));
        } finally {
            synchronized (handshakeLock) {
                if (firstMessagePending) {
                    firstMessagePending = false;
                    handshakeLock.notifyAll();
                }
            }
        }
    }

    private void rewriteBind(byte[] message, int op, long[] bind, int auth, long[] authHeader,
                             LdapSettings registered) throws IOException {
        int authEnd = (int) (auth + authHeader[0] + authHeader[1]);
        int opEnd = (int) (op + bind[0] + bind[1]);
        int bindBefore = auth - (int) (op + bind[0]);            // version and name
        int bindAfter = opEnd - authEnd;                          // nothing, usually
        int opStart = (int) header(message, 0, message.length)[0]; // the message id starts here
        int messageAfter = message.length - opEnd;                // controls
        LdapSettings target = settings;
        space.seclume.jfr.Observed.secretUse("ldap", target == null ? ""
                : target.host + ":" + target.port, "simple-bind");
        try (SecretScope password = SecretScope.fromProvider(registered.secret)) {
            int secret = password.length();
            int authContent = secret;
            int bindContent = bindBefore + 1 + lengthSize(authContent) + authContent + bindAfter;
            int messageContent = (op - opStart) + 1 + lengthSize(bindContent) + bindContent
                    + messageAfter;
            int total = 1 + lengthSize(messageContent) + messageContent;
            try (SecretScope rewritten = SecretScope.allocate(total)) {
                MemorySegment w = rewritten.segment();
                int p = 0;
                w.set(ValueLayout.JAVA_BYTE, p++, (byte) SEQUENCE);
                p = putLength(w, p, messageContent);
                MemorySegment.copy(message, opStart, w, ValueLayout.JAVA_BYTE, p, op - opStart);
                p += op - opStart;
                w.set(ValueLayout.JAVA_BYTE, p++, (byte) BIND_REQUEST);
                p = putLength(w, p, bindContent);
                MemorySegment.copy(message, (int) (op + bind[0]), w, ValueLayout.JAVA_BYTE, p,
                        bindBefore);
                p += bindBefore;
                w.set(ValueLayout.JAVA_BYTE, p++, (byte) SIMPLE);
                p = putLength(w, p, authContent);
                MemorySegment.copy(password.segment(), 0, w, p, secret);
                p += secret;
                MemorySegment.copy(message, authEnd, w, ValueLayout.JAVA_BYTE, p, bindAfter);
                p += bindAfter;
                MemorySegment.copy(message, opEnd, w, ValueLayout.JAVA_BYTE, p, messageAfter);
                p += messageAfter;
                open().write(w.asSlice(0, p).asByteBuffer());
            }
        }
    }

    /**
     * Drives the RFC 4752 SASL {@code GSSAPI} bind over TLS when JNDI sends its
     * initial placeholder {@code BindRequest}, negotiating mutual authentication
     * and {@code NO_PROTECTION} ({@code 0x01}) before queueing the final
     * {@code BindResponse} for JNDI's reader thread.
     */
    private void bindKerberos(byte[] message, int opStart, int op, LdapSettings registered)
            throws IOException {
        byte[] msgIdBytes = Arrays.copyOfRange(message, opStart, op);
        LdapSettings target = settings;
        space.seclume.jfr.Observed.secretUse("ldap", target == null ? ""
                : target.host + ":" + target.port, "kerberos-bind");
        TlsLayer channel = open();
        ParsedResult lastResult;
        try (Gssapi.Context gss = registered.gssSupplier.get()) {
            byte[] clientStep = gss.step(null, 0, 0);
            writeSaslBindRequest(channel, msgIdBytes, clientStep);
            lastResult = readBindResponse(channel, registered);
            while (!gss.complete()) {
                if (lastResult.resultCode != SASL_BIND_IN_PROGRESS && lastResult.resultCode != 0) {
                    throw new IOException("Kerberos SASL bind on " + registered.authority()
                            + " was refused (LDAP result " + lastResult.resultCode
                            + (lastResult.diagnostic.isEmpty() ? ")" : ": " + lastResult.diagnostic + ")"));
                }
                if (lastResult.serverSaslCreds == null || lastResult.serverSaslCreds.length == 0) {
                    throw new IOException("the LDAP server at " + registered.authority()
                            + " did not return a Kerberos challenge for mutual authentication");
                }
                byte[] serverBytes = lastResult.serverSaslCreds;
                try (Arena stepArena = Arena.ofConfined()) {
                    MemorySegment inSeg = stepArena.allocate(serverBytes.length);
                    MemorySegment.copy(serverBytes, 0, inSeg, ValueLayout.JAVA_BYTE, 0,
                            serverBytes.length);
                    clientStep = gss.step(inSeg, 0, serverBytes.length);
                }
                if (!gss.complete() || clientStep.length > 0) {
                    writeSaslBindRequest(channel, msgIdBytes, clientStep);
                    lastResult = readBindResponse(channel, registered);
                }
            }
            if (clientStep.length == 0 && lastResult.resultCode == SASL_BIND_IN_PROGRESS) {
                writeSaslBindRequest(channel, msgIdBytes, new byte[0]);
                lastResult = readBindResponse(channel, registered);
            }
            if (lastResult.resultCode != SASL_BIND_IN_PROGRESS) {
                throw new IOException("Kerberos SASL security-layer negotiation on "
                        + registered.authority() + " failed (LDAP result " + lastResult.resultCode
                        + (lastResult.diagnostic.isEmpty() ? ")" : ": " + lastResult.diagnostic + ")"));
            }
            if (lastResult.serverSaslCreds == null || lastResult.serverSaslCreds.length == 0) {
                throw new IOException("the LDAP server at " + registered.authority()
                        + " did not send the RFC 4752 SASL security-layer challenge");
            }
            byte[] unwrapped = gss.unwrap(lastResult.serverSaslCreds);
            if (unwrapped.length < 4 || (unwrapped[0] & SASL_QOP_NO_PROTECTION) == 0) {
                String offered = unwrapped.length > 0
                        ? "0x" + Integer.toHexString(unwrapped[0] & 0xff) : "empty";
                throw new IOException("the LDAP server at " + registered.authority()
                        + " does not allow SASL GSSAPI NO_PROTECTION over TLS (offered QOP "
                        + offered + ")");
            }
            byte[] authzBytes = registered.authorizationId.getBytes(StandardCharsets.UTF_8); // seclume-allow: SASL authorization identity, not a secret
            byte[] securityReply = new byte[4 + authzBytes.length];
            securityReply[0] = (byte) SASL_QOP_NO_PROTECTION;
            System.arraycopy(authzBytes, 0, securityReply, 4, authzBytes.length);
            byte[] wrappedReply = gss.wrap(securityReply);
            writeSaslBindRequest(channel, msgIdBytes, wrappedReply);
            lastResult = readBindResponse(channel, registered);
        } catch (RuntimeException e) {
            throw new IOException("Kerberos SASL bind on " + registered.authority()
                    + " failed: " + e.getMessage(), e);
        }
        byte[] finalResponse = encodeBindResponse(msgIdBytes, lastResult);
        synchronized (handshakeLock) {
            preRead = finalResponse;
            preReadOffset = 0;
        }
    }

    private static void writeSaslBindRequest(TlsLayer channel, byte[] msgIdBytes, byte[] saslBytes)
            throws IOException {
        int mechLen = 2 + GSSAPI_MECHANISM.length;
        int credsLen = saslBytes == null ? 0 : 1 + lengthSize(saslBytes.length) + saslBytes.length;
        int saslContent = mechLen + credsLen;
        int saslTotal = 1 + lengthSize(saslContent) + saslContent;
        int bindContent = 3 + 2 + saslTotal;
        int bindTotal = 1 + lengthSize(bindContent) + bindContent;
        int msgContent = msgIdBytes.length + bindTotal;
        int total = 1 + lengthSize(msgContent) + msgContent;
        byte[] out = new byte[total];
        int p = 0;
        out[p++] = (byte) SEQUENCE;
        p = putLengthArray(out, p, msgContent);
        System.arraycopy(msgIdBytes, 0, out, p, msgIdBytes.length);
        p += msgIdBytes.length;
        out[p++] = (byte) BIND_REQUEST;
        p = putLengthArray(out, p, bindContent);
        out[p++] = 0x02;
        out[p++] = 0x01;
        out[p++] = 0x03;
        out[p++] = (byte) OCTET_STRING;
        out[p++] = 0x00;
        out[p++] = (byte) SASL;
        p = putLengthArray(out, p, saslContent);
        out[p++] = (byte) OCTET_STRING;
        out[p++] = (byte) GSSAPI_MECHANISM.length;
        System.arraycopy(GSSAPI_MECHANISM, 0, out, p, GSSAPI_MECHANISM.length);
        p += GSSAPI_MECHANISM.length;
        if (saslBytes != null) {
            out[p++] = (byte) OCTET_STRING;
            p = putLengthArray(out, p, saslBytes.length);
            System.arraycopy(saslBytes, 0, out, p, saslBytes.length);
        }
        channel.write(ByteBuffer.wrap(out));
    }

    private static ParsedResult readBindResponse(TlsLayer channel, LdapSettings registered)
            throws IOException {
        byte[] buf = new byte[1024];
        int readTotal = 0;
        int expected = -1;
        while (expected < 0 || readTotal < expected) {
            if (readTotal == buf.length) {
                if (buf.length >= 1048576) {
                    throw new IOException("LDAP BindResponse from " + registered.authority()
                            + " exceeds 1 MiB");
                }
                buf = Arrays.copyOf(buf, buf.length * 2);
            }
            int n = channel.read(ByteBuffer.wrap(buf, readTotal, buf.length - readTotal));
            if (n < 0) {
                throw new EOFException("the LDAP server at " + registered.authority()
                        + " closed the connection during the Kerberos SASL bind");
            }
            readTotal += n;
            expected = messageLength(buf, readTotal, 1048576);
        }
        return response(buf, expected, BIND_RESPONSE);
    }

    /**
     * How long the message starting at {@code buf[0]} is, header included;
     * -1 while its header is not all here. A length beyond {@code cap} is
     * refused before it is believed - a four-byte BER length is up to 4 GiB.
     */
    static int messageLength(byte[] buf, int readTotal, int cap) throws IOException {
        long[] outer = header(buf, 0, readTotal);
        if (outer == null) {
            return -1;
        }
        long total = outer[0] + outer[1];
        if (total > cap) {
            throw new IOException("an LDAP response of " + total + " bytes; at most " + cap
                    + " are read");
        }
        return (int) total;
    }

    /**
     * A whole LDAP message of {@code length} bytes as the result of the
     * operation {@code tag} - a BindResponse or the StartTLS ExtendedResponse.
     * Every length is checked against what contains it: whatever a server
     * sends, this answers or throws an {@link IOException}, never reads past
     * the message. Package-private for {@code LdapResponseFuzzTest}.
     */
    static ParsedResult response(byte[] buf, int length, int tag) throws IOException {
        if (length < 2 || length > buf.length || (buf[0] & 0xff) != SEQUENCE) {
            throw new IOException("an LDAP response that is not a message");
        }
        int[] message = element(buf, 0, length);
        int[] id = element(buf, message[0], message[1]);
        int op = id[1];
        if (op >= message[1] || (buf[op] & 0xff) != tag) {
            throw new IOException("expected an LDAP response of tag 0x"
                    + Integer.toHexString(tag) + ", got "
                    + (op < message[1] ? "0x" + Integer.toHexString(buf[op] & 0xff) : "nothing"));
        }
        return parseLdapResult(buf, op, message[1]);
    }

    /**
     * The element at {@code at}, which has to end within {@code limit}:
     * {@code {content start, content end}}.
     */
    private static int[] element(byte[] buf, int at, int limit) throws IOException {
        long[] header = header(buf, at, limit);
        if (header == null || at + header[0] + header[1] > limit) {
            throw new IOException("a malformed LDAP response: an element runs past its end");
        }
        return new int[] {(int) (at + header[0]), (int) (at + header[0] + header[1])};
    }

    private static ParsedResult parseLdapResult(byte[] buf, int op, int limit) throws IOException {
        int[] operation = element(buf, op, limit);
        int opEnd = operation[1];
        int[] rc = element(buf, operation[0], opEnd);
        if (rc[1] - rc[0] < 1 || rc[1] - rc[0] > 4) {
            throw new IOException("a malformed LDAP response: a result code of "
                    + (rc[1] - rc[0]) + " bytes");
        }
        int resultCode = readInt(buf, rc[0], rc[1] - rc[0]);
        int[] mdn = element(buf, rc[1], opEnd);
        byte[] matchedDn = Arrays.copyOfRange(buf, mdn[0], mdn[1]);
        int[] diag = element(buf, mdn[1], opEnd);
        byte[] diagBytes = Arrays.copyOfRange(buf, diag[0], diag[1]);
        String diagnostic = new String(diagBytes, StandardCharsets.UTF_8); // seclume-allow: LDAP diagnostic text, not a secret
        int pos = diag[1];
        byte[] serverSaslCreds = null;
        while (pos < opEnd) {
            int[] value = element(buf, pos, opEnd);
            if ((buf[pos] & 0xff) == SERVER_SASL_CREDS) {
                serverSaslCreds = Arrays.copyOfRange(buf, value[0], value[1]);
            }
            pos = value[1];
        }
        return new ParsedResult(resultCode, matchedDn, diagBytes, diagnostic, serverSaslCreds);
    }

    private static byte[] encodeBindResponse(byte[] msgIdBytes, ParsedResult res) {
        int rcLen = 3;
        int mdnLen = 1 + lengthSize(res.matchedDn.length) + res.matchedDn.length;
        int diagLen = 1 + lengthSize(res.diagBytes.length) + res.diagBytes.length;
        int bindContent = rcLen + mdnLen + diagLen;
        int bindTotal = 1 + lengthSize(bindContent) + bindContent;
        int msgContent = msgIdBytes.length + bindTotal;
        int total = 1 + lengthSize(msgContent) + msgContent;
        byte[] out = new byte[total];
        int p = 0;
        out[p++] = (byte) SEQUENCE;
        p = putLengthArray(out, p, msgContent);
        System.arraycopy(msgIdBytes, 0, out, p, msgIdBytes.length);
        p += msgIdBytes.length;
        out[p++] = (byte) BIND_RESPONSE;
        p = putLengthArray(out, p, bindContent);
        out[p++] = (byte) ENUMERATED;
        out[p++] = 0x01;
        out[p++] = (byte) res.resultCode;
        out[p++] = (byte) OCTET_STRING;
        p = putLengthArray(out, p, res.matchedDn.length);
        System.arraycopy(res.matchedDn, 0, out, p, res.matchedDn.length);
        p += res.matchedDn.length;
        out[p++] = (byte) OCTET_STRING;
        p = putLengthArray(out, p, res.diagBytes.length);
        System.arraycopy(res.diagBytes, 0, out, p, res.diagBytes.length);
        return out;
    }

    private static int readInt(byte[] b, int at, int len) {
        int val = 0;
        for (int i = 0; i < len; i++) {
            val = (val << 8) | (b[at + i] & 0xff);
        }
        return val;
    }

    private static int putLengthArray(byte[] out, int at, int length) {
        int size = lengthSize(length);
        if (size == 1) {
            out[at] = (byte) length;
            return at + 1;
        }
        out[at] = (byte) (0x80 | (size - 1));
        for (int i = size - 1; i >= 1; i--) {
            out[at + i] = (byte) length;
            length >>>= 8;
        }
        return at + size;
    }

    record ParsedResult(int resultCode, byte[] matchedDn, byte[] diagBytes,
                                String diagnostic, byte[] serverSaslCreds) {
    }

    private static int lengthSize(int length) {
        return length < 0x80 ? 1 : length < 0x100 ? 2 : length < 0x10000 ? 3
                : length < 0x1000000 ? 4 : 5;
    }

    /** A BER length, byte by byte into native memory - it follows from the password's. */
    private static int putLength(MemorySegment w, int at, int length) {
        int size = lengthSize(length);
        if (size == 1) {
            w.set(ValueLayout.JAVA_BYTE, at, (byte) length);
            return at + 1;
        }
        w.set(ValueLayout.JAVA_BYTE, at, (byte) (0x80 | (size - 1)));
        for (int i = size - 1; i >= 1; i--) {
            w.set(ValueLayout.JAVA_BYTE, at + i, (byte) length);
            length >>>= 8;
        }
        return at + size;
    }

    private static boolean startsWith(byte[] value, byte[] prefix) {
        return value.length > prefix.length
                && Arrays.equals(value, 0, prefix.length, prefix, 0, prefix.length);
    }

    private TlsLayer open() throws IOException {
        TlsLayer current = tls;
        if (current == null || closed) {
            throw new SocketException(closed ? "closed" : "not connected");
        }
        return current;
    }

    // ---- what JNDI asks of a socket ----------------------------------------------

    @Override
    public InputStream getInputStream() throws IOException {
        open();
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        open();
        return out;
    }

    @Override
    public void setSoTimeout(int millis) throws SocketException {
        timeout = millis;
        SocketTransport current = transport;
        if (current != null) {
            try {
                current.networkTimeout(millis);
            } catch (IOException e) {
                throw new SocketException(e.getMessage());
            }
        }
    }

    @Override
    public int getSoTimeout() {
        return timeout;
    }

    @Override
    public void setTcpNoDelay(boolean on) {
        // seclume's transport sets it itself
    }

    @Override
    public void setKeepAlive(boolean on) {
        // seclume's transport decides
    }

    @Override
    public void setSoLinger(boolean on, int linger) {
        // the TLS close is seclume's
    }

    @Override
    public boolean isConnected() {
        return tls != null;
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public boolean isBound() {
        return tls != null;
    }

    @Override
    public boolean isInputShutdown() {
        return closed;
    }

    @Override
    public boolean isOutputShutdown() {
        return closed;
    }

    @Override
    public int getPort() {
        LdapSettings current = settings;
        return current == null ? 0 : current.port;
    }

    @Override
    public InetAddress getInetAddress() {
        LdapSettings current = settings;
        if (current == null) {
            return null;
        }
        try {
            return InetAddress.getByName(current.host);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    @Override
    public void close() {
        closed = true;
        synchronized (handshakeLock) {
            firstMessagePending = false;
            handshakeLock.notifyAll();
        }
        TlsLayer current = tls;
        if (current != null) {
            try {
                current.close();
            } catch (Exception ignored) {
                // closing anyway
            }
        }
        SocketTransport raw = transport;
        if (raw != null) {
            raw.close();
        }
    }

    @Override
    public String toString() {
        LdapSettings current = settings;
        return "seclume LDAP socket" + (current == null ? "" : " to " + current.authority());
    }
}
