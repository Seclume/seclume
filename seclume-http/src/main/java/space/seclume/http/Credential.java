package space.seclume.http;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import space.seclume.internal.Base64Off;
import space.seclume.secret.SecretScope;

/**
 * The credential header - {@code Authorization: Bearer ...},
 * {@code Authorization: Basic ...} or a header of the API's own - built and
 * written from native memory, once per request.
 *
 * <p>The secret is read from the provider into a {@link SecretScope}; the
 * header line is assembled in a second one - for Basic, the base64 of
 * {@code user:password} included, by {@link Base64Off}, which works on native
 * memory - and written from there to seclume's TLS. Both scopes are wiped on
 * the way out. The header name and prefix are configuration, not secret.
 *
 * <p>Read per request rather than kept: a rotated key takes effect with the
 * next request, and between requests there is no copy of it anywhere in this
 * process. Providers that fetch over the network (Vault, the cloud secret
 * managers, a managed identity's token) keep their own native cache.
 */
final class Credential {

    private Credential() {
    }

    /** The header line, CRLF included, for the request being written on {@code wire}. */
    static void write(HttpWire wire, HttpSettings settings) throws IOException {
        String headText = settings.headerName + ": " + settings.prefix;
        byte[] head = headText.getBytes(StandardCharsets.ISO_8859_1); // seclume-allow: the header name and its fixed prefix, e.g. 'Authorization: Bearer ' - the secret follows off the heap
        try (SecretScope secret = SecretScope.fromProvider(settings.secret)) {
            requireOneLine(secret);
            if (settings.auth == HttpSettings.Auth.BASIC) {
                basic(wire, settings, head, secret);
                return;
            }
            int length = head.length + secret.length() + 2;
            try (SecretScope line = SecretScope.allocate(length)) {
                MemorySegment out = line.segment();
                MemorySegment.copy(head, 0, out, ValueLayout.JAVA_BYTE, 0, head.length);
                MemorySegment.copy(secret.segment(), 0, out, head.length, secret.length());
                crlf(out, head.length + secret.length());
                wire.write(out.asSlice(0, length).asByteBuffer());
            }
        }
    }

    /** {@code Authorization: Basic base64(user:password)} - RFC 7617. */
    private static void basic(HttpWire wire, HttpSettings settings, byte[] head,
                              SecretScope password) throws IOException {
        byte[] user = settings.user.getBytes(StandardCharsets.UTF_8); // seclume-allow: the user name, which is public
        int rawLength = user.length + 1 + password.length();
        try (SecretScope raw = SecretScope.allocate(rawLength)) {
            MemorySegment at = raw.segment();
            MemorySegment.copy(user, 0, at, ValueLayout.JAVA_BYTE, 0, user.length);
            at.set(ValueLayout.JAVA_BYTE, user.length, (byte) ':');
            MemorySegment.copy(password.segment(), 0, at, user.length + 1, password.length());
            int encoded = Base64Off.encodedLength(rawLength);
            try (SecretScope line = SecretScope.allocate(head.length + encoded + 2)) {
                MemorySegment out = line.segment();
                MemorySegment.copy(head, 0, out, ValueLayout.JAVA_BYTE, 0, head.length);
                int written = Base64Off.encode(at, 0, rawLength, out, head.length);
                crlf(out, head.length + written);
                wire.write(out.asSlice(0, head.length + written + 2).asByteBuffer());
            }
        }
    }

    private static void crlf(MemorySegment out, long at) {
        out.set(ValueLayout.JAVA_BYTE, at, (byte) '\r');
        out.set(ValueLayout.JAVA_BYTE, at + 1, (byte) '\n');
    }

    /**
     * A secret with a line break or NUL in it would end the header early and
     * put the rest of it into the request as a header - or a second request.
     * Refused rather than sent; a trailing newline from {@code echo > file} is
     * the usual cause, and the file provider already drops that one.
     */
    private static void requireOneLine(SecretScope secret) throws IOException {
        MemorySegment at = secret.segment();
        for (int i = 0; i < secret.length(); i++) {
            byte b = at.get(ValueLayout.JAVA_BYTE, i);
            if (b == '\r' || b == '\n' || b == 0) {
                throw new IOException("the secret holds a line break or NUL, which cannot go "
                        + "into an HTTP header - check the secret's source for a stray line");
            }
        }
    }
}
