package space.seclume.mail;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64; // seclume-allow: the user name and the server's refusal are base64, neither is a secret
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import space.seclume.internal.Base64Off;
import space.seclume.internal.SocketTransport;
import space.seclume.internal.TlsLayer;
import space.seclume.internal.TlsLayers;
import space.seclume.internal.TrustChoice;
import space.seclume.internal.jdbc.TlsStack;
import space.seclume.secret.SecretScope;

/**
 * One SMTP session: connected, encrypted, logged in - and then as many
 * messages as the caller sends before closing it.
 *
 * <p><b>Where the credential goes.</b> It is read from the provider into a
 * {@link SecretScope}, the AUTH line is built next to it in another one -
 * base64 and all, by {@link Base64Off}, which works on native memory - and
 * written from there to seclume's own TLS 1.3, which encrypts it without a
 * heap copy. Both scopes are wiped on the way out. What Jakarta Mail would do
 * with the same login - a {@code String} password in its session, a
 * {@code String} of the base64 AUTH argument, JSSE's heap record buffers - does
 * not happen at any point.
 *
 * <p><b>STARTTLS.</b> Anything the server sent after its {@code 220} to
 * STARTTLS, before the handshake, is refused rather than read: those are
 * bytes a man in the middle could have injected into the plaintext, to be
 * taken as the first answers of the encrypted session (CVE-2011-0411 and its
 * many relatives). The EHLO before STARTTLS is forgotten; the one after it is
 * what counts.
 *
 * <p>Not thread-safe: one session, one sender at a time.
 */
public final class SmtpConnection implements AutoCloseable {

    private final MailSettings settings;
    private final MailWire wire;
    private Map<String, String> extensions = Map.of();
    private boolean open = true;

    private SmtpConnection(MailWire wire) {
        this.settings = wire.settings();
        this.wire = wire;
    }

    /** Connects, says EHLO, encrypts and logs in as {@code settings} name it. */
    static SmtpConnection open(MailSettings settings) throws IOException {
        SmtpConnection connection = new SmtpConnection(MailWire.connect(settings));
        try {
            expect(connection.reply(), 220, "the greeting");
            connection.ehlo();
            if (settings.startTls) {
                if (!connection.extensions.containsKey("STARTTLS")) {
                    throw new MailException(-1, settings.host + " does not offer STARTTLS. "
                            + "Nothing is sent to it in the clear; tls=none says that is "
                            + "wanted, and then there is no login");
                }
                expect(connection.command("STARTTLS"), 220, "STARTTLS");
                connection.wire.startTls();
                connection.ehlo();
            }
            connection.login();
            return connection;
        } catch (IOException | RuntimeException e) {
            connection.abandon();
            throw e;
        }
    }

    /** What the server named in its last EHLO: keyword, upper case, to its parameters. */
    public Map<String, String> extensions() {
        return extensions;
    }

    /** Whether the session is encrypted - always, unless {@code tls=none} was asked for. */
    public boolean encrypted() {
        return wire.encrypted();
    }

    /**
     * Sends one message.
     *
     * @param from       the envelope sender - the address bounces go to
     * @param recipients the envelope recipients; the headers of the message
     *                   are not read for them
     * @param message    writes the message itself - headers, a blank line and
     *                   the body - with CRLF or LF line ends
     * @return which recipients the server took and which it refused, with its
     *         reason; when it took none, nothing is sent and
     *         {@link MailException} says why
     */
    public Sent send(String from, List<String> recipients, MessageWriter message)
            throws IOException {
        if (!open) {
            throw new IllegalStateException("this SMTP connection is closed");
        }
        if (recipients.isEmpty()) {
            throw new IllegalArgumentException("a message needs at least one envelope recipient");
        }
        boolean utf8 = !isAscii(from) || recipients.stream().anyMatch(r -> !isAscii(r));
        if (utf8 && !extensions.containsKey("SMTPUTF8")) {
            throw new MailException(-1, "an address is not ASCII, and " + settings.host
                    + " does not offer SMTPUTF8");
        }
        StringBuilder mail = new StringBuilder("MAIL FROM:<").append(from).append('>');
        if (extensions.containsKey("8BITMIME")) {
            mail.append(" BODY=8BITMIME");
        }
        if (utf8) {
            mail.append(" SMTPUTF8");
        }
        expect(command(mail.toString()), 250, "MAIL FROM");

        List<String> accepted = new ArrayList<>();
        Map<String, String> refused = new LinkedHashMap<>();
        for (String recipient : recipients) {
            Reply reply = command("RCPT TO:<" + recipient + ">");
            if (reply.code == 250 || reply.code == 251) {
                accepted.add(recipient);
            } else {
                refused.put(recipient, reply.text());
            }
        }
        if (accepted.isEmpty()) {
            command("RSET");
            throw new MailException(-1, "the server took none of the recipients: " + refused);
        }
        expect(command("DATA"), 354, "DATA");
        try (DotStuffing body = new DotStuffing()) {
            message.writeTo(body);
            body.finish();
        } catch (IOException | RuntimeException e) {
            // Half a message is on the wire and there is no way to take it
            // back but to hang up: the server discards a DATA that never ended.
            abandon();
            throw e;
        }
        Reply queued = reply();
        expect(queued, 250, "the end of the message");
        return new Sent(List.copyOf(accepted), Map.copyOf(refused), queued.text());
    }

    /** QUIT, then the connection closed - also when the server does not answer. */
    @Override
    public void close() {
        if (!open) {
            return;
        }
        try {
            command("QUIT");
        } catch (IOException | RuntimeException ignored) {
            // leaving anyway
        }
        abandon();
    }

    // ---- the steps ----------------------------------------------------------

    private void ehlo() throws IOException {
        Reply reply = command("EHLO " + settings.ehloName);
        expect(reply, 250, "EHLO");
        Map<String, String> offered = new LinkedHashMap<>();
        for (int i = 1; i < reply.lines.size(); i++) {
            String line = reply.lines.get(i).trim();
            int space = line.indexOf(' ');
            String keyword = (space < 0 ? line : line.substring(0, space)).toUpperCase(Locale.ROOT);
            offered.put(keyword, space < 0 ? "" : line.substring(space + 1).trim());
        }
        extensions = Map.copyOf(offered);
    }

    private void login() throws IOException {
        MailSettings.Auth auth = settings.auth;
        if (auth == MailSettings.Auth.NONE) {
            return;
        }
        List<String> offered = List.of(extensions.getOrDefault("AUTH", "")
                .toUpperCase(Locale.ROOT).split("\\s+"));
        if (auth == MailSettings.Auth.BEST) {
            if (offered.contains("PLAIN")) {
                auth = MailSettings.Auth.PLAIN;
            } else if (offered.contains("LOGIN")) {
                auth = MailSettings.Auth.LOGIN;
            } else {
                throw new MailException(-1, settings.host + " offers no password login this "
                        + "client speaks (AUTH " + extensions.getOrDefault("AUTH", "-")
                        + "); auth=xoauth2 logs in with a token");
            }
        } else if (!offered.contains(auth.name())) {
            throw new MailException(-1, settings.host + " does not offer AUTH " + auth.name()
                    + " (it offers: " + extensions.getOrDefault("AUTH", "nothing") + ")");
        }
        switch (auth) {
            case PLAIN -> plain();
            case LOGIN -> loginMechanism();
            case XOAUTH2 -> xoauth2();
            default -> throw new IllegalStateException(auth.name());
        }
    }

    /** RFC 4616: {@code \0user\0password}, base64, in one line - see {@link Sasl}. */
    private void plain() throws IOException {
        Sasl.plain(wire, "AUTH PLAIN ");
        expectLogin(reply(), "AUTH PLAIN");
    }

    /** The old two-step LOGIN: the user name, then the password, each in base64. */
    private void loginMechanism() throws IOException {
        expect(command("AUTH LOGIN"), 334, "AUTH LOGIN");
        // seclume-allow: the user name in LOGIN's first step, public
        byte[] name = settings.user.getBytes(StandardCharsets.UTF_8);
        // seclume-allow: the same user name, base64 as LOGIN wants it
        expect(command(Base64.getEncoder().encodeToString(name)), 334, "the user name");
        Sasl.passwordBase64(wire);
        expectLogin(reply(), "AUTH LOGIN");
    }

    /**
     * Google's and Microsoft's OAuth 2.0 login. A refusal comes as a 334 with
     * a base64 JSON reason, which is answered with an empty line.
     */
    private void xoauth2() throws IOException {
        Sasl.xoauth2(wire, "AUTH XOAUTH2 ");
        Reply reply = reply();
        if (reply.code == 334) {
            String reason = MailReplies.oauthReason(reply.text());
            reply = command("");
            throw new MailException(reply.code, "the server refused the token of "
                    + settings.user + ": " + reason);
        }
        expectLogin(reply, "AUTH XOAUTH2");
    }

    private void expectLogin(Reply reply, String step) throws MailException {
        if (reply.code != 235) {
            throw new MailException(reply.code, "the server refused the login of "
                    + settings.user + " (" + step + "): " + reply.text());
        }
    }

    // ---- the wire -----------------------------------------------------------

    /** A reply: its code and its lines, the code stripped from each. */
    record Reply(int code, List<String> lines) {
        String text() {
            return String.join(" / ", lines);
        }
    }

    private Reply command(String line) throws IOException {
        wire.writeLine(line);
        return reply();
    }

    private static void expect(Reply reply, int code, String step) throws MailException {
        if (reply.code != code) {
            throw new MailException(reply.code, step + " was answered with " + reply.code + " "
                    + reply.text());
        }
    }

    /** Reads one reply, however many lines it has ({@code 250-...} up to {@code 250 ...}). */
    private Reply reply() throws IOException {
        List<String> lines = new ArrayList<>();
        while (true) {
            String line = wire.readLine();
            if (line.length() < 3 || !isDigit(line.charAt(0)) || !isDigit(line.charAt(1))
                    || !isDigit(line.charAt(2))
                    || (line.length() > 3 && line.charAt(3) != ' ' && line.charAt(3) != '-')) {
                throw new MailException(-1, "not an SMTP reply: " + line);
            }
            int code = (line.charAt(0) - '0') * 100 + (line.charAt(1) - '0') * 10
                    + (line.charAt(2) - '0');
            lines.add(line.length() > 4 ? line.substring(4) : "");
            if (line.length() == 3 || line.charAt(3) == ' ') {
                return new Reply(code, List.copyOf(lines));
            }
        }
    }

    private void abandon() {
        open = false;
        wire.close();
    }

    /** An ASCII digit - not Character.isDigit, which takes every script's digits. */
    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean isAscii(String text) {
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) > 0x7f) {
                return false;
            }
        }
        return true;
    }

    /**
     * The message on its way into DATA: every line ending made CRLF, a dot at
     * the start of a line doubled (RFC 5321 section 4.5.2), and the closing
     * {@code CRLF . CRLF} added by {@link #finish()}.
     */
    private final class DotStuffing extends OutputStream {

        private final byte[] buffer = new byte[16 * 1024];
        private int used;
        private boolean lineStart = true;
        private boolean afterCr;

        @Override
        public void write(int value) throws IOException {
            byte b = (byte) value;
            if (b == '\n') {
                if (!afterCr) {
                    put('\r');
                }
                put('\n');
                lineStart = true;
                afterCr = false;
                return;
            }
            if (afterCr) {
                // a CR on its own ends a line as well
                put('\n');
                lineStart = true;
            }
            afterCr = b == '\r';
            if (lineStart && b == '.') {
                put('.');
            }
            put(b);
            lineStart = false;
        }

        @Override
        public void write(byte[] source, int offset, int length) throws IOException {
            for (int i = 0; i < length; i++) {
                write(source[offset + i]);
            }
        }

        void finish() throws IOException {
            if (afterCr) {
                put('\n');
                lineStart = true;
                afterCr = false;
            }
            if (!lineStart) {
                put('\r');
                put('\n');
            }
            put('.');
            put('\r');
            put('\n');
            flush();
        }

        private void put(int b) throws IOException {
            if (used == buffer.length) {
                flush();
            }
            buffer[used++] = (byte) b;
        }

        @Override
        public void flush() throws IOException {
            if (used > 0) {
                wire.write(ByteBuffer.wrap(buffer, 0, used));
                used = 0;
            }
        }

        @Override
        public void close() {
            used = 0;
        }
    }

    /** Writes a message - headers, blank line, body - into the stream it is given. */
    @FunctionalInterface
    public interface MessageWriter {
        void writeTo(OutputStream out) throws IOException;
    }

    /**
     * What happened to one message.
     *
     * @param accepted the recipients the server took
     * @param refused  those it did not, each with its reply
     * @param queued   the server's answer to the message - usually a queue id
     */
    public record Sent(List<String> accepted, Map<String, String> refused, String queued) {
    }
}
