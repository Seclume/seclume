package space.seclume.mail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;

/**
 * A small IMAP server for the tests: STARTTLS or implicit TLS, AUTHENTICATE
 * PLAIN and XOAUTH2 (with and without SASL-IR) and LOGIN with a literal,
 * checked against what it was given - then one read-only INBOX, enough of
 * FETCH for Jakarta Mail to list and read it.
 *
 * <p>Strict where it matters to the tests: a login in the clear, or any
 * mailbox command before one, is refused - so a client cannot get in by
 * accident, and a {@code LOGIN} that Jakarta Mail sends on its own would be
 * seen in {@link #commands}.
 */
final class FakeImapServer extends FakeLineServer {

    // what it offers and expects
    String user = "reports";
    byte[] password = "correct horse".getBytes(StandardCharsets.UTF_8);
    byte[] token = "ya29.test-token".getBytes(StandardCharsets.UTF_8);
    List<String> mechanisms = List.of("PLAIN", "XOAUTH2");
    boolean saslIr = true;
    boolean loginDisabled;
    boolean capabilityInGreeting = true;
    boolean offerStartTls = true;
    boolean injectAfterStartTls;
    boolean preauth;
    final List<String> messages = new CopyOnWriteArrayList<>();

    // what it saw
    final List<String> logins = new CopyOnWriteArrayList<>();
    final List<String> commands = new CopyOnWriteArrayList<>();

    FakeImapServer(SSLContext tls, boolean implicitTls) throws IOException {
        super(tls, implicitTls, "fake-imap");
    }

    private String capabilities(boolean encrypted) {
        StringBuilder all = new StringBuilder("IMAP4rev1");
        if (!encrypted && offerStartTls) {
            all.append(" STARTTLS");
        }
        if (encrypted) {
            for (String mechanism : mechanisms) {
                all.append(" AUTH=").append(mechanism);
            }
            if (saslIr) {
                all.append(" SASL-IR");
            }
        }
        if (!encrypted || loginDisabled) {
            all.append(" LOGINDISABLED");
        }
        return all.toString();
    }

    @Override
    void serve(Connection c) throws IOException {
        if (preauth) {
            c.line("* PREAUTH welcome, whoever you are");
        } else {
            c.line("* OK " + (capabilityInGreeting ? "[CAPABILITY " + capabilities(c.encrypted)
                    + "] " : "") + "fake IMAP ready");
        }
        boolean authenticated = preauth;
        boolean selected = false;
        while (true) {
            String line = c.readLine();
            if (line == null) {
                return;
            }
            String[] words = line.split(" ", 3);
            if (words.length < 2) {
                c.line("* BAD no tag");
                continue;
            }
            String tag = words[0];
            String verb = words[1].toUpperCase(Locale.ROOT);
            String rest = words.length > 2 ? words[2] : "";
            commands.add(verb.equals("UID") ? "UID " + rest.split(" ")[0].toUpperCase(Locale.ROOT)
                    : verb);
            switch (verb) {
                case "CAPABILITY" -> {
                    c.line("* CAPABILITY " + capabilities(c.encrypted));
                    c.line(tag + " OK CAPABILITY completed");
                }
                case "STARTTLS" -> {
                    if (c.encrypted) {
                        c.line(tag + " BAD already encrypted");
                        continue;
                    }
                    if (injectAfterStartTls) {
                        c.send(tag + " OK begin TLS\r\n* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] "
                                + "injected\r\n");
                    } else {
                        c.line(tag + " OK begin TLS");
                    }
                    c.startTls();
                }
                case "LOGIN" -> {
                    if (!c.encrypted || loginDisabled) {
                        c.line(tag + " NO LOGIN is disabled here");
                        continue;
                    }
                    authenticated = login(c, tag, rest);
                }
                case "AUTHENTICATE" -> {
                    if (!c.encrypted) {
                        c.line(tag + " NO encrypt first");
                        continue;
                    }
                    authenticated = authenticate(c, tag, rest);
                }
                case "NOOP" -> c.line(tag + " OK NOOP completed");
                case "LOGOUT" -> {
                    c.line("* BYE logging out");
                    c.line(tag + " OK LOGOUT completed");
                    return;
                }
                default -> {
                    if (!authenticated) {
                        c.line(tag + " NO log in first");
                        continue;
                    }
                    switch (verb) {
                        case "LIST" -> {
                            c.line("* LIST (\\HasNoChildren) \"/\" INBOX");
                            c.line(tag + " OK LIST completed");
                        }
                        case "SELECT", "EXAMINE" -> {
                            if (!rest.replace("\"", "").equalsIgnoreCase("INBOX")) {
                                c.line(tag + " NO no such mailbox");
                                continue;
                            }
                            selected = true;
                            c.line("* FLAGS (\\Seen \\Deleted)");
                            c.line("* " + messages.size() + " EXISTS");
                            c.line("* 0 RECENT");
                            c.line("* OK [UIDVALIDITY 7] UIDs valid");
                            c.line("* OK [UIDNEXT " + (messages.size() + 1) + "] next");
                            c.line(tag + " OK [READ-ONLY] " + verb + " completed");
                        }
                        case "FETCH" -> {
                            if (!selected) {
                                c.line(tag + " NO select first");
                                continue;
                            }
                            fetch(c, rest);
                            c.line(tag + " OK FETCH completed");
                        }
                        case "CLOSE", "UNSELECT" -> {
                            selected = false;
                            c.line(tag + " OK " + verb + " completed");
                        }
                        default -> c.line(tag + " BAD unknown command " + verb);
                    }
                }
            }
        }
    }

    /** {@code LOGIN "user" {n}}, the go-ahead, n bytes and the rest of the line. */
    private boolean login(Connection c, String tag, String rest) throws IOException {
        Matcher m = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\" \\{(\\d+)}").matcher(rest);
        if (!m.matches()) {
            c.line(tag + " BAD this server takes the password as a literal");
            return false;
        }
        String name = m.group(1).replace("\\\"", "\"").replace("\\\\", "\\");
        c.line("+ go ahead");
        byte[] given = c.readBytes(Integer.parseInt(m.group(2)));
        c.readLine();
        return verdict(c, tag, "LOGIN", name.equals(user) && Arrays.equals(given, password));
    }

    private boolean authenticate(Connection c, String tag, String rest) throws IOException {
        String[] parts = rest.split(" ");
        String mechanism = parts[0].toUpperCase(Locale.ROOT);
        if (!mechanisms.contains(mechanism)) {
            c.line(tag + " NO unsupported mechanism");
            return false;
        }
        String response;
        if (parts.length > 1) {
            if (!saslIr) {
                c.line(tag + " BAD no SASL-IR here");
                return false;
            }
            response = parts[1];
        } else {
            c.line("+ ");
            response = c.readLine();
        }
        byte[] raw = Base64.getDecoder().decode(response);
        if (mechanism.equals("PLAIN")) {
            return verdict(c, tag, mechanism, Arrays.equals(raw, concat(new byte[] {0},
                    user.getBytes(StandardCharsets.UTF_8), new byte[] {0}, password)));
        }
        byte[] expected = concat(("user=" + user + "\u0001auth=Bearer ")
                .getBytes(StandardCharsets.UTF_8), token, new byte[] {1, 1});
        if (Arrays.equals(raw, expected)) {
            return verdict(c, tag, mechanism, true);
        }
        c.line("+ " + Base64.getEncoder().encodeToString(
                "{\"status\":\"401\",\"schemes\":\"bearer\"}".getBytes(StandardCharsets.UTF_8)));
        c.readLine();
        return verdict(c, tag, mechanism, false);
    }

    private boolean verdict(Connection c, String tag, String mechanism, boolean ok)
            throws IOException {
        if (ok) {
            logins.add(mechanism);
            c.line(tag + " OK logged in");
        } else {
            c.line(tag + " NO [AUTHENTICATIONFAILED] invalid credentials");
        }
        return ok;
    }

    /** FETCH set items - the items Jakarta Mail asks for to list and read a mailbox. */
    private void fetch(Connection c, String rest) throws IOException {
        int space = rest.indexOf(' ');
        List<Integer> numbers = sequence(rest.substring(0, space));
        String items = rest.substring(space + 1).toUpperCase(Locale.ROOT);
        Matcher body = Pattern.compile("BODY(?:\\.PEEK)?\\[\\](?:<(\\d+)\\.(\\d+)>)?")
                .matcher(items);
        for (int number : numbers) {
            byte[] message = messages.get(number - 1).getBytes(StandardCharsets.UTF_8);
            List<String> parts = new ArrayList<>();
            if (items.contains("UID")) {
                parts.add("UID " + number);
            }
            if (items.contains("FLAGS")) {
                parts.add("FLAGS (\\Seen)");
            }
            if (items.contains("INTERNALDATE")) {
                parts.add("INTERNALDATE \"27-Sep-2026 10:00:00 +0000\"");
            }
            if (items.contains("RFC822.SIZE")) {
                parts.add("RFC822.SIZE " + message.length);
            }
            if (items.contains("ENVELOPE")) {
                parts.add("ENVELOPE (NIL \"" + header(messages.get(number - 1), "Subject")
                        + "\" ((NIL NIL \"sender\" \"example.com\")) NIL NIL "
                        + "((NIL NIL \"reports\" \"example.com\")) NIL NIL NIL NIL)");
            }
            StringBuilder line = new StringBuilder("* " + number + " FETCH (" + String.join(" ", parts));
            if (body.find(0)) {
                int start = body.group(1) == null ? 0 : Math.min(Integer.parseInt(body.group(1)),
                        message.length);
                int end = body.group(2) == null ? message.length
                        : Math.min(message.length, start + Integer.parseInt(body.group(2)));
                line.append(parts.isEmpty() ? "" : " ").append("BODY[]")
                        .append(body.group(1) == null ? "" : "<" + start + ">")
                        .append(" {").append(end - start).append("}\r\n");
                c.send(line.toString());
                c.send(new String(message, start, end - start, StandardCharsets.UTF_8));
                c.line(")");
            } else {
                c.line(line.append(")").toString());
            }
        }
    }

    private List<Integer> sequence(String set) {
        List<Integer> numbers = new ArrayList<>();
        for (String range : set.split(",")) {
            String[] ends = range.split(":");
            int from = ends[0].equals("*") ? messages.size() : Integer.parseInt(ends[0]);
            int to = ends.length == 1 ? from
                    : ends[1].equals("*") ? messages.size() : Integer.parseInt(ends[1]);
            for (int n = Math.min(from, to); n <= Math.max(from, to) && n <= messages.size(); n++) {
                numbers.add(n);
            }
        }
        return numbers;
    }

    private static String header(String message, String name) {
        for (String line : message.split("\r\n")) {
            if (line.isEmpty()) {
                break;
            }
            if (line.regionMatches(true, 0, name + ":", 0, name.length() + 1)) {
                return line.substring(name.length() + 1).trim();
            }
        }
        return "";
    }
}
