package space.seclume.postgresql.auth;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.crypto.ConstantTime;
import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;
import space.seclume.crypto.Pbkdf2;
import space.seclume.internal.Base64Off;
import space.seclume.internal.Entropy;

/**
 * SCRAM-SHA-256 (RFC 5802/7677) as a client, entirely off-heap.
 *
 * <p>This is the place where an ordinary driver puts the password on the heap:
 * the usual implementation assembles the auth message as a {@code String} and
 * calls {@code Mac.getInstance("HmacSHA256")} with a {@code SecretKeySpec}.
 * Neither is an option here. The whole procedure - auth message, salted
 * password, client key, proof - lives in an {@link Arena} that is zeroed on
 * close.
 *
 * <p>Not included: SCRAM-SHA-256-PLUS. Channel binding needs the connection's
 * TLS certificate; it arrives with the TLS part, and until then this client
 * does not offer it rather than pretend.
 *
 * <p>Also not included: SASLprep. PostgreSQL applies it server-side to the
 * stored password; a password made of printable ASCII is unaffected by it. For
 * passwords with special characters from the Unicode range this is recorded in
 * {@code docs/protocol/postgresql.md} as a known gap - nothing is guessed
 * here.
 */
public final class ScramSha256 implements AutoCloseable {

    /** Every value that falls out of SHA-256 is this long. */
    private static final int KEY_LENGTH = 32;

    private final Arena arena = Arena.ofConfined();
    /** The client's random characters, base64 encoded and thus printable. */
    private final MemorySegment clientNonce;
    private final int clientNonceLength;
    /** client-first-bare + "," + server-first + "," + client-final-without-proof */
    private final GrowingText authMessage;

    private MemorySegment salt;
    private int saltLength;
    private int iterations;
    private MemorySegment serverNonce;
    private int serverNonceLength;
    private MemorySegment expectedServerSignature;
    private boolean closed;

    public ScramSha256() {
        this(24);
    }

    /** @param nonceBytes the raw bytes of the client nonce before base64 encoding */
    public ScramSha256(int nonceBytes) {
        MemorySegment random = arena.allocate(nonceBytes);
        try {
            Entropy.fill(random);
            this.clientNonce = arena.allocate(Base64Off.encodedLength(nonceBytes));
            this.clientNonceLength =
                    Base64Off.encode(random, 0, nonceBytes, clientNonce, 0);
        } finally {
            random.fill((byte) 0);
        }
        this.authMessage = new GrowingText(arena, 512);
    }

    /** Only for tests with fixed vectors: the nonce is supplied. */
    ScramSha256(MemorySegment fixedNonce, int length) {
        this.clientNonce = arena.allocate(length);
        MemorySegment.copy(fixedNonce, 0, clientNonce, 0, length);
        this.clientNonceLength = length;
        this.authMessage = new GrowingText(arena, 512);
    }

    /**
     * Writes {@code n,,n=,r=<nonce>} and remembers the part without the GS2
     * header - that one goes into the auth message later.
     *
     * @return the length of the message written
     */
    public int clientFirst(MemorySegment target) {
        // With PostgreSQL the user name is already in the startup message;
        // SCRAM therefore leaves n= empty, and the server expects it that way.
        return clientFirst(target, "");
    }

    /**
     * Like {@link #clientFirst(MemorySegment)}, but with the user name in the
     * {@code n=} field. PostgreSQL does not need it; RFC 7677 provides for it,
     * and the published test vectors rest on it.
     */
    public int clientFirst(MemorySegment target, String username) {
        int position = 0;
        position = put(target, position, "n,,");
        int bareStart = position;
        position = put(target, position, "n=");
        position = putEscaped(target, position, username);
        position = put(target, position, ",r=");
        MemorySegment.copy(clientNonce, 0, target, position, clientNonceLength);
        position += clientNonceLength;

        authMessage.append(target, bareStart, position - bareStart);
        return position;
    }

    /** RFC 5802: comma and equals sign in the name get replaced. */
    private static int putEscaped(MemorySegment target, int position, String username) {
        int out = position;
        for (int i = 0; i < username.length(); i++) {
            char c = username.charAt(i);
            if (c == ',') {
                out = put(target, out, "=2C");
            } else if (c == '=') {
                out = put(target, out, "=3D");
            } else {
                target.set(ValueLayout.JAVA_BYTE, out++, (byte) c);
            }
        }
        return out;
    }

    /**
     * Takes in {@code r=<nonce>,s=<salt>,i=<iterations>}.
     *
     * @throws IllegalStateException if the server nonce does not start with our
     *         own - then somebody else is talking to us
     */
    public void serverFirst(MemorySegment data, int offset, int length) {
        authMessage.appendByte((byte) ',');
        authMessage.append(data, offset, length);

        int nonceLength = attributeLength(data, offset, length, 'r');
        int noncePosition = attributePosition(data, offset, length, 'r');
        if (nonceLength < clientNonceLength
                || !ConstantTime.equals(data, noncePosition, clientNonce, 0, clientNonceLength)) {
            throw new IllegalStateException(
                    "the server nonce does not start with ours - refusing to continue");
        }
        serverNonce = arena.allocate(nonceLength);
        MemorySegment.copy(data, noncePosition, serverNonce, 0, nonceLength);
        serverNonceLength = nonceLength;

        int saltPosition = attributePosition(data, offset, length, 's');
        int saltEncodedLength = attributeLength(data, offset, length, 's');
        salt = arena.allocate(Base64Off.decodedUpperBound(saltEncodedLength) + 1);
        saltLength = Base64Off.decode(data, saltPosition, saltEncodedLength, salt, 0);

        iterations = readNumber(data, attributePosition(data, offset, length, 'i'),
                attributeLength(data, offset, length, 'i'));
        if (iterations < 1 || iterations > 10_000_000) {
            throw new IllegalStateException("implausible iteration count " + iterations);
        }
    }

    /**
     * Builds {@code c=biws,r=<nonce>,p=<proof>} and computes everything that
     * touches the password along the way.
     *
     * @param password the password, off-heap
     * @return the length of the message written
     */
    public int clientFinal(MemorySegment target, MemorySegment password) {
        MemorySegment saltedPassword = arena.allocate(KEY_LENGTH);
        MemorySegment clientKey = arena.allocate(KEY_LENGTH);
        MemorySegment storedKey = arena.allocate(KEY_LENGTH);
        MemorySegment signature = arena.allocate(KEY_LENGTH);
        try {
            // c=biws is base64("n,,") - the GS2 header, sent back unchanged.
            int position = put(target, 0, "c=biws,r=");
            MemorySegment.copy(serverNonce, 0, target, position, serverNonceLength);
            position += serverNonceLength;

            authMessage.appendByte((byte) ',');
            authMessage.append(target, 0, position);

            MemorySegment saltSlice = salt.asSlice(0, saltLength);
            Pbkdf2.derive(HashAlgorithm.SHA_256, password, saltSlice, iterations, saltedPassword);

            mac(saltedPassword, "Client Key", clientKey);
            HashAlgorithm.SHA_256.hash(clientKey, 0, KEY_LENGTH, storedKey, 0);

            try (Hmac hmac = new Hmac(HashAlgorithm.SHA_256, storedKey)) {
                hmac.update(authMessage.segment(), 0, authMessage.length());
                hmac.doFinal(signature, 0);
            }
            // ClientProof = ClientKey XOR ClientSignature, in place.
            for (int i = 0; i < KEY_LENGTH; i++) {
                byte value = (byte) (clientKey.get(ValueLayout.JAVA_BYTE, i)
                        ^ signature.get(ValueLayout.JAVA_BYTE, i));
                clientKey.set(ValueLayout.JAVA_BYTE, i, value);
            }

            position = put(target, position, ",p=");
            position += Base64Off.encode(clientKey, 0, KEY_LENGTH, target, position);

            // The server's answer is checked against this later.
            expectedServerSignature = arena.allocate(KEY_LENGTH);
            MemorySegment serverKey = arena.allocate(KEY_LENGTH);
            try {
                mac(saltedPassword, "Server Key", serverKey);
                try (Hmac hmac = new Hmac(HashAlgorithm.SHA_256, serverKey)) {
                    hmac.update(authMessage.segment(), 0, authMessage.length());
                    hmac.doFinal(expectedServerSignature, 0);
                }
            } finally {
                serverKey.fill((byte) 0);
            }
            return position;
        } finally {
            saltedPassword.fill((byte) 0);
            clientKey.fill((byte) 0);
            storedKey.fill((byte) 0);
            signature.fill((byte) 0);
        }
    }

    /**
     * Checks {@code v=<signature>} from the server's final message.
     *
     * <p>This is not a formality: without that check a server sitting in
     * between could confirm the login without knowing the password. The
     * comparison runs in constant time.
     */
    public void verifyServerFinal(MemorySegment data, int offset, int length) {
        int position = attributePosition(data, offset, length, 'v');
        int encodedLength = attributeLength(data, offset, length, 'v');
        MemorySegment decoded = arena.allocate(Base64Off.decodedUpperBound(encodedLength) + 1);
        try {
            int decodedLength = Base64Off.decode(data, position, encodedLength, decoded, 0);
            if (decodedLength != KEY_LENGTH
                    || !ConstantTime.equals(decoded, 0, expectedServerSignature, 0, KEY_LENGTH)) {
                throw new IllegalStateException(
                        "the server could not prove that it knows the password");
            }
        } finally {
            decoded.fill((byte) 0);
        }
    }

    public int iterations() {
        return iterations;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        arena.close();
    }

    // ---- odds and ends ---------------------------------------------------

    private void mac(MemorySegment key, String message, MemorySegment out) {
        try (Arena scratch = Arena.ofConfined();
             Hmac hmac = new Hmac(HashAlgorithm.SHA_256, key)) {
            MemorySegment text = scratch.allocate(message.length());
            put(text, 0, message);
            hmac.update(text, 0, message.length());
            hmac.doFinal(out, 0);
        }
    }

    /** Writes ASCII protocol text; secrets never pass through here. */
    private static int put(MemorySegment target, int position, String text) {
        for (int i = 0; i < text.length(); i++) {
            target.set(ValueLayout.JAVA_BYTE, position + i, (byte) text.charAt(i));
        }
        return position + text.length();
    }

    /** Position of the value of {@code name=} in a comma-separated list. */
    private static int attributePosition(MemorySegment data, int offset, int length, char name) {
        int position = offset;
        int end = offset + length;
        while (position < end) {
            if (data.get(ValueLayout.JAVA_BYTE, position) == (byte) name
                    && position + 1 < end
                    && data.get(ValueLayout.JAVA_BYTE, position + 1) == '='
                    && (position == offset
                        || data.get(ValueLayout.JAVA_BYTE, position - 1) == ',')) {
                return position + 2;
            }
            position++;
        }
        throw new IllegalStateException("the server message has no attribute " + name);
    }

    private static int attributeLength(MemorySegment data, int offset, int length, char name) {
        int start = attributePosition(data, offset, length, name);
        int end = start;
        int limit = offset + length;
        while (end < limit && data.get(ValueLayout.JAVA_BYTE, end) != ',') {
            end++;
        }
        return end - start;
    }

    private static int readNumber(MemorySegment data, int offset, int length) {
        int value = 0;
        for (int i = 0; i < length; i++) {
            int digit = (data.get(ValueLayout.JAVA_BYTE, offset + i) & 0xff) - '0';
            if (digit < 0 || digit > 9) {
                throw new IllegalStateException("the iteration count is not a number");
            }
            value = value * 10 + digit;
        }
        return value;
    }

    /**
     * A growing text buffer in the same arena - the auth message is the only
     * thing here that outlives a single step.
     */
    private static final class GrowingText {

        private final Arena arena;
        private MemorySegment segment;
        private int length;

        GrowingText(Arena arena, int capacity) {
            this.arena = arena;
            this.segment = arena.allocate(capacity);
        }

        void append(MemorySegment source, long offset, int count) {
            ensure(length + count);
            MemorySegment.copy(source, offset, segment, length, count);
            length += count;
        }

        void appendByte(byte value) {
            ensure(length + 1);
            segment.set(ValueLayout.JAVA_BYTE, length++, value);
        }

        MemorySegment segment() {
            return segment;
        }

        int length() {
            return length;
        }

        private void ensure(int needed) {
            if (needed <= segment.byteSize()) {
                return;
            }
            MemorySegment bigger = arena.allocate(Math.max(needed, segment.byteSize() * 2));
            MemorySegment.copy(segment, 0, bigger, 0, length);
            segment.fill((byte) 0);
            segment = bigger;
        }
    }
}
