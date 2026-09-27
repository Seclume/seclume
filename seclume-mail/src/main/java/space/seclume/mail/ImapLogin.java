package space.seclume.mail;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * An IMAP connection up to "logged in" - and no further: from there on it is
 * Jakarta Mail's, which is told so with a {@code PREAUTH} greeting (see
 * {@link MailSocket}).
 *
 * <p>The greeting, CAPABILITY, STARTTLS where the URL asks for it, and one of:
 *
 * <ul>
 *   <li>{@code AUTHENTICATE PLAIN} (RFC 4616), the default wherever the server
 *       offers {@code AUTH=PLAIN};
 *   <li>{@code AUTHENTICATE XOAUTH2} for Microsoft 365 and Google, by name;
 *   <li>{@code LOGIN} with the password as a literal, where PLAIN is not
 *       offered - or by name - and the server has not disabled it.
 * </ul>
 *
 * <p>The initial response goes with the command where the server offers
 * {@code SASL-IR} (RFC 4959), and after its {@code +} otherwise. Either way
 * the argument is built and written by {@link Sasl}, off the heap.
 */
final class ImapLogin {

    private final MailWire wire;
    private final MailSettings settings;
    private int tags;

    private ImapLogin(MailWire wire) {
        this.wire = wire;
        this.settings = wire.settings();
    }

    /** Connected, encrypted and logged in - or closed and refused. */
    static MailWire open(MailSettings settings) throws IOException {
        MailWire wire = MailWire.connect(settings);
        try {
            new ImapLogin(wire).login();
            return wire;
        } catch (IOException | RuntimeException e) {
            wire.close();
            throw e;
        }
    }

    private void login() throws IOException {
        String greeting = wire.readLine();
        String upper = greeting.toUpperCase(Locale.ROOT);
        if (upper.startsWith("* PREAUTH")) {
            throw new MailException(-1, settings.host + " logged this connection in before "
                    + "anyone asked (PREAUTH) - there is no login to give it");
        }
        if (!upper.startsWith("* OK")) {
            throw new MailException(-1, settings.host + " did not greet as an IMAP server: "
                    + greeting);
        }
        Set<String> capabilities = fromGreeting(greeting);
        if (capabilities == null) {
            capabilities = capability();
        }
        if (settings.startTls) {
            if (!capabilities.contains("STARTTLS")) {
                throw new MailException(-1, settings.host + " does not offer STARTTLS. "
                        + "Nothing is sent to it in the clear");
            }
            String tag = tag();
            wire.writeLine(tag + " STARTTLS");
            expectOk(tag, "STARTTLS");
            wire.startTls();
            capabilities = capability();
        }

        MailSettings.Auth auth = settings.auth;
        if (auth == MailSettings.Auth.BEST) {
            auth = capabilities.contains("AUTH=PLAIN") ? MailSettings.Auth.PLAIN
                    : MailSettings.Auth.LOGIN;
        }
        switch (auth) {
            case PLAIN -> authenticate("PLAIN", capabilities);
            case XOAUTH2 -> authenticate("XOAUTH2", capabilities);
            case LOGIN -> {
                if (capabilities.contains("LOGINDISABLED")) {
                    throw new MailException(-1, settings.host + " has disabled LOGIN and "
                            + "offers " + capabilities.stream()
                            .filter(c -> c.startsWith("AUTH=")).toList()
                            + "; auth=plain or auth=xoauth2 may be what it takes");
                }
                String tag = tag();
                String refused = Sasl.imapLogin(wire, tag);
                if (refused != null) {
                    throw refusal("LOGIN", refused);
                }
                expectOk(tag, "LOGIN");
            }
            default -> throw new IllegalStateException("no IMAP login for " + auth);
        }
    }

    private void authenticate(String mechanism, Set<String> capabilities) throws IOException {
        if (!capabilities.contains("AUTH=" + mechanism)) {
            throw new MailException(-1, settings.host + " does not offer AUTHENTICATE "
                    + mechanism + " (it offers: " + capabilities.stream()
                    .filter(c -> c.startsWith("AUTH=")).toList() + ")");
        }
        String tag = tag();
        String command = tag + " AUTHENTICATE " + mechanism;
        if (capabilities.contains("SASL-IR")) {
            send(mechanism, command + " ");
        } else {
            wire.writeLine(command);
            String goAhead = wire.readLine();
            if (!goAhead.startsWith("+")) {
                throw refusal(mechanism, goAhead);
            }
            send(mechanism, "");
        }
        String reply = untilTagged(tag);
        if (reply.startsWith("+")) {
            // XOAUTH2's refusal: a base64 JSON reason, answered with an empty line
            String reason = MailReplies.oauthReason(reply.substring(1));
            wire.writeLine("");
            untilTagged(tag);
            throw new MailException(-1, "the server refused the token of " + settings.user
                    + ": " + reason);
        }
        requireOk(tag, reply, "AUTHENTICATE " + mechanism);
    }

    private void send(String mechanism, String prefix) throws IOException {
        if (mechanism.equals("XOAUTH2")) {
            Sasl.xoauth2(wire, prefix);
        } else {
            Sasl.plain(wire, prefix);
        }
    }

    private Set<String> capability() throws IOException {
        String tag = tag();
        wire.writeLine(tag + " CAPABILITY");
        Set<String> capabilities = new TreeSet<>();
        while (true) {
            String line = wire.readLine();
            String upper = line.toUpperCase(Locale.ROOT);
            if (upper.startsWith("* CAPABILITY ")) {
                capabilities.addAll(words(upper.substring(13)));
            } else if (upper.startsWith(tag.toUpperCase(Locale.ROOT) + " ")) {
                requireOk(tag, line, "CAPABILITY");
                return capabilities;
            }
        }
    }

    /** {@code * OK [CAPABILITY IMAP4rev1 ...] ...}, or null when the greeting names none. */
    private static Set<String> fromGreeting(String greeting) {
        String upper = greeting.toUpperCase(Locale.ROOT);
        int start = upper.indexOf("[CAPABILITY ");
        int end = upper.indexOf(']', start + 1);
        if (start < 0 || end < 0) {
            return null;
        }
        return new TreeSet<>(words(upper.substring(start + 12, end)));
    }

    private static List<String> words(String text) {
        List<String> words = new ArrayList<>();
        for (String word : text.trim().split("\\s+")) {
            if (!word.isEmpty()) {
                words.add(word);
            }
        }
        return words;
    }

    /** Reads up to the tagged line, or a continuation; untagged lines are passed over. */
    private String untilTagged(String tag) throws IOException {
        while (true) {
            String line = wire.readLine();
            if (line.startsWith("+") || line.startsWith(tag + " ")) {
                return line;
            }
        }
    }

    private void expectOk(String tag, String step) throws IOException {
        requireOk(tag, untilTagged(tag), step);
    }

    private void requireOk(String tag, String line, String step) throws MailException {
        String status = line.length() > tag.length() + 1 ? line.substring(tag.length() + 1) : "";
        if (!status.toUpperCase(Locale.ROOT).startsWith("OK")) {
            throw refusal(step, line);
        }
    }

    private MailException refusal(String step, String line) {
        boolean login = step.startsWith("AUTHENTICATE") || step.equals("LOGIN")
                || step.equals("PLAIN") || step.equals("XOAUTH2");
        return new MailException(-1, login
                ? "the server refused the login of " + settings.user + " (" + step + "): " + line
                : step + " was answered with: " + line);
    }

    private String tag() {
        return "s" + (++tags);
    }
}
