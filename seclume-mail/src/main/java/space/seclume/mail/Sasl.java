package space.seclume.mail;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import space.seclume.internal.Base64Off;
import space.seclume.secret.SecretScope;

/**
 * The login arguments of all three protocols, built and written from native
 * memory: SASL PLAIN and XOAUTH2 in base64, and the bare password where a
 * protocol's own login wants it (POP3's PASS, IMAP's LOGIN, SMTP's LOGIN in
 * base64).
 *
 * <p>The credential is read from the provider into a {@link SecretScope}; the
 * argument is assembled in a second one - base64 included, by
 * {@link Base64Off}, which works on native memory - and written from there to
 * the connection, whose TLS is seclume's own. Both scopes are wiped on the way
 * out. What goes on the wire around it - a command, a tag, CRLF - is protocol
 * text and never touches the secret.
 */
final class Sasl {

    private Sasl() {
    }

    /**
     * RFC 4616: {@code \0user\0password}, base64 - after {@code prefix}, and
     * with CRLF. {@code prefix} is {@code "AUTH PLAIN "} on SMTP and POP3,
     * {@code "a1 AUTHENTICATE PLAIN "} on IMAP, or empty for a continuation.
     */
    static void plain(MailWire wire, String prefix) throws IOException {
        MailSettings settings = wire.settings();
        byte[] user = settings.user.getBytes(StandardCharsets.UTF_8); // seclume-allow: the user name, which is public
        try (SecretScope password = SecretScope.fromProvider(settings.secret)) {
            int length = 1 + user.length + 1 + password.length();
            try (SecretScope raw = SecretScope.allocate(length)) {
                MemorySegment at = raw.segment();
                at.set(ValueLayout.JAVA_BYTE, 0, (byte) 0);
                MemorySegment.copy(user, 0, at, ValueLayout.JAVA_BYTE, 1, user.length);
                at.set(ValueLayout.JAVA_BYTE, 1 + user.length, (byte) 0);
                MemorySegment.copy(password.segment(), 0, at, 2 + user.length, password.length());
                base64Line(wire, prefix, at, length);
            }
        }
    }

    /**
     * Google's and Microsoft's OAuth 2.0 login: {@code user=...^Aauth=Bearer
     * token^A^A}, base64, after {@code prefix} and with CRLF.
     */
    static void xoauth2(MailWire wire, String prefix) throws IOException {
        MailSettings settings = wire.settings();
        String prefixText = "user=" + settings.user + "\u0001auth=Bearer ";
        byte[] head = prefixText.getBytes(StandardCharsets.UTF_8); // seclume-allow: 'user=', the user name and 'auth=Bearer ' - no token in it
        try (SecretScope token = SecretScope.fromProvider(settings.secret)) {
            int length = head.length + token.length() + 2;
            try (SecretScope raw = SecretScope.allocate(length)) {
                MemorySegment at = raw.segment();
                MemorySegment.copy(head, 0, at, ValueLayout.JAVA_BYTE, 0, head.length);
                MemorySegment.copy(token.segment(), 0, at, head.length, token.length());
                at.set(ValueLayout.JAVA_BYTE, head.length + token.length(), (byte) 1);
                at.set(ValueLayout.JAVA_BYTE, head.length + token.length() + 1, (byte) 1);
                base64Line(wire, prefix, at, length);
            }
        }
    }

    /** The password alone, base64, with CRLF - the second step of SMTP's LOGIN. */
    static void passwordBase64(MailWire wire) throws IOException {
        try (SecretScope password = SecretScope.fromProvider(wire.settings().secret)) {
            base64Line(wire, "", password.segment(), password.length());
        }
    }

    /**
     * {@code prefix}, the password as it is, then CRLF - POP3's
     * {@code PASS password}. Refused when the password holds a line break,
     * which would end the command early and send the rest as another one.
     */
    static void passwordLine(MailWire wire, String prefix) throws IOException {
        try (SecretScope password = SecretScope.fromProvider(wire.settings().secret)) {
            requireOneLine(password);
            byte[] head = prefix.getBytes(StandardCharsets.US_ASCII); // seclume-allow: the command, e.g. 'PASS ' - the password follows off the heap
            int length = head.length + password.length() + 2;
            try (SecretScope line = SecretScope.allocate(length)) {
                MemorySegment out = line.segment();
                MemorySegment.copy(head, 0, out, ValueLayout.JAVA_BYTE, 0, head.length);
                MemorySegment.copy(password.segment(), 0, out, head.length, password.length());
                out.set(ValueLayout.JAVA_BYTE, head.length + password.length(), (byte) '\r');
                out.set(ValueLayout.JAVA_BYTE, head.length + password.length() + 1, (byte) '\n');
                wire.write(out.asSlice(0, length).asByteBuffer());
            }
        }
    }

    /**
     * IMAP's {@code LOGIN}: the user as a quoted string and the password as a
     * synchronizing literal - {@code {n}}, the server's go-ahead, then the
     * bytes - so no character of it needs quoting or escaping.
     *
     * @return the tagged reply, after the server's answer to the whole command
     */
    static String imapLogin(MailWire wire, String tag) throws IOException {
        MailSettings settings = wire.settings();
        try (SecretScope password = SecretScope.fromProvider(settings.secret)) {
            // The literal's length is a fact about the password, and a length is
            // what this library does not put on the heap either - so the command
            // line is built in native memory as well, digits and all.
            String commandText = tag + " LOGIN " + quoted(settings.user) + " {";
            byte[] head = commandText.getBytes(StandardCharsets.UTF_8); // seclume-allow: the tag, LOGIN and the quoted user name - public
            try (SecretScope command = SecretScope.allocate(head.length + 16)) {
                MemorySegment out = command.segment();
                MemorySegment.copy(head, 0, out, ValueLayout.JAVA_BYTE, 0, head.length);
                int at = head.length;
                int length = password.length();
                int digits = 1;
                for (int rest = length / 10; rest > 0; rest /= 10) {
                    digits++;
                }
                for (int i = digits - 1, rest = length; i >= 0; i--, rest /= 10) {
                    out.set(ValueLayout.JAVA_BYTE, at + i, (byte) ('0' + rest % 10));
                }
                at += digits;
                out.set(ValueLayout.JAVA_BYTE, at++, (byte) '}');
                out.set(ValueLayout.JAVA_BYTE, at++, (byte) '\r');
                out.set(ValueLayout.JAVA_BYTE, at++, (byte) '\n');
                wire.write(out.asSlice(0, at).asByteBuffer());
            }
            String goAhead = wire.readLine();
            if (!goAhead.startsWith("+")) {
                return goAhead;                  // the tagged refusal, instead of the go-ahead
            }
            try (SecretScope line = SecretScope.allocate(password.length() + 2)) {
                MemorySegment out = line.segment();
                MemorySegment.copy(password.segment(), 0, out, 0, password.length());
                out.set(ValueLayout.JAVA_BYTE, password.length(), (byte) '\r');
                out.set(ValueLayout.JAVA_BYTE, password.length() + 1, (byte) '\n');
                wire.write(out.asSlice(0, password.length() + 2).asByteBuffer());
            }
        }
        return null;
    }

    /** An IMAP quoted string: the user name, with backslash and quote escaped. */
    static String quoted(String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static void requireOneLine(SecretScope secret) throws MailException {
        MemorySegment at = secret.segment();
        for (int i = 0; i < secret.length(); i++) {
            byte b = at.get(ValueLayout.JAVA_BYTE, i);
            if (b == '\r' || b == '\n') {
                throw new MailException(-1, "the password holds a line break, which this "
                        + "protocol cannot carry in one command - use auth=plain");
            }
        }
    }

    /**
     * {@code prefix}, then {@code length} bytes of {@code secret} in base64,
     * then CRLF - built in native memory and written from there.
     */
    private static void base64Line(MailWire wire, String prefix, MemorySegment secret, int length)
            throws IOException {
        byte[] head = prefix.getBytes(StandardCharsets.US_ASCII); // seclume-allow: the command prefix, e.g. 'AUTH PLAIN ' - the secret goes in after it, off-heap
        int encoded = Base64Off.encodedLength(length);
        try (SecretScope line = SecretScope.allocate(head.length + encoded + 2)) {
            MemorySegment out = line.segment();
            MemorySegment.copy(head, 0, out, ValueLayout.JAVA_BYTE, 0, head.length);
            int written = Base64Off.encode(secret, 0, length, out, head.length);
            out.set(ValueLayout.JAVA_BYTE, head.length + written, (byte) '\r');
            out.set(ValueLayout.JAVA_BYTE, head.length + written + 1, (byte) '\n');
            wire.write(out.asSlice(0, head.length + written + 2).asByteBuffer());
        }
    }
}
