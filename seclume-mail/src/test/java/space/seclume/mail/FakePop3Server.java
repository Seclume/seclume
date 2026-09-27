package space.seclume.mail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.net.ssl.SSLContext;

/**
 * A small POP3 server for the tests: CAPA, STLS or implicit TLS, AUTH PLAIN
 * and XOAUTH2 and USER/PASS, checked against what it was given - then a
 * maildrop Jakarta Mail can count, list and read (STAT, LIST, UIDL, TOP,
 * RETR).
 *
 * <p>Strict where it matters to the tests: a login in the clear, or any
 * maildrop command before one, is refused, and every command is recorded -
 * so the placeholder password Jakarta Mail is given would be seen here if it
 * were ever sent.
 */
final class FakePop3Server extends FakeLineServer {

    // what it offers and expects
    String user = "reports";
    byte[] password = "correct horse".getBytes(StandardCharsets.UTF_8);
    byte[] token = "ya29.test-token".getBytes(StandardCharsets.UTF_8);
    List<String> mechanisms = List.of("PLAIN", "XOAUTH2");
    boolean offerStartTls = true;
    boolean injectAfterStartTls;
    final List<String> messages = new CopyOnWriteArrayList<>();

    // what it saw
    final List<String> logins = new CopyOnWriteArrayList<>();
    final List<String> commands = new CopyOnWriteArrayList<>();
    final List<String> passwordsSeen = new CopyOnWriteArrayList<>();

    FakePop3Server(SSLContext tls, boolean implicitTls) throws IOException {
        super(tls, implicitTls, "fake-pop3");
    }

    @Override
    void serve(Connection c) throws IOException {
        c.line("+OK fake POP3 ready");
        boolean authenticated = false;
        String userGiven = null;
        while (true) {
            String line = c.readLine();
            if (line == null) {
                return;
            }
            String[] words = line.split(" ");
            String verb = words[0].toUpperCase(Locale.ROOT);
            commands.add(verb);
            switch (verb) {
                case "CAPA" -> {
                    c.line("+OK capabilities");
                    c.line("USER");
                    c.line("UIDL");
                    c.line("TOP");
                    if (!c.encrypted && offerStartTls) {
                        c.line("STLS");
                    }
                    if (c.encrypted) {
                        c.line("SASL " + String.join(" ", mechanisms));
                    }
                    c.line(".");
                }
                case "STLS" -> {
                    if (c.encrypted) {
                        c.line("-ERR already encrypted");
                        continue;
                    }
                    c.send(injectAfterStartTls ? "+OK begin TLS\r\n+OK injected\r\n"
                            : "+OK begin TLS\r\n");
                    c.startTls();
                }
                case "USER" -> {
                    if (!c.encrypted) {
                        c.line("-ERR encrypt first");
                        continue;
                    }
                    userGiven = words.length > 1 ? words[1] : "";
                    c.line("+OK send PASS");
                }
                case "PASS" -> {
                    byte[] given = line.substring(Math.min(line.length(), 5))
                            .getBytes(StandardCharsets.UTF_8);
                    passwordsSeen.add(new String(given, StandardCharsets.UTF_8));
                    boolean ok = c.encrypted && user.equals(userGiven)
                            && Arrays.equals(given, password);
                    authenticated = verdict(c, "USER", ok);
                }
                case "AUTH" -> {
                    if (!c.encrypted) {
                        c.line("-ERR encrypt first");
                        continue;
                    }
                    authenticated = auth(c, words);
                }
                case "NOOP" -> c.line("+OK");
                case "QUIT" -> {
                    c.line("+OK bye");
                    return;
                }
                default -> {
                    if (!authenticated) {
                        c.line("-ERR log in first");
                        continue;
                    }
                    maildrop(c, verb, words);
                }
            }
        }
    }

    private boolean auth(Connection c, String[] words) throws IOException {
        String mechanism = words.length > 1 ? words[1].toUpperCase(Locale.ROOT) : "";
        if (!mechanisms.contains(mechanism)) {
            c.line("-ERR unsupported mechanism");
            return false;
        }
        String response;
        if (words.length > 2) {
            response = words[2];
        } else {
            c.line("+ ");
            response = c.readLine();
        }
        byte[] raw = Base64.getDecoder().decode(response);
        if (mechanism.equals("PLAIN")) {
            return verdict(c, mechanism, Arrays.equals(raw, concat(new byte[] {0},
                    user.getBytes(StandardCharsets.UTF_8), new byte[] {0}, password)));
        }
        byte[] expected = concat(("user=" + user + "\u0001auth=Bearer ")
                .getBytes(StandardCharsets.UTF_8), token, new byte[] {1, 1});
        if (Arrays.equals(raw, expected)) {
            return verdict(c, mechanism, true);
        }
        c.line("+ " + Base64.getEncoder().encodeToString(
                "{\"status\":\"401\",\"schemes\":\"bearer\"}".getBytes(StandardCharsets.UTF_8)));
        c.readLine();
        return verdict(c, mechanism, false);
    }

    private boolean verdict(Connection c, String mechanism, boolean ok) throws IOException {
        if (ok) {
            logins.add(mechanism);
            c.line("+OK logged in");
        } else {
            c.line("-ERR [AUTH] invalid credentials");
        }
        return ok;
    }

    private void maildrop(Connection c, String verb, String[] words) throws IOException {
        switch (verb) {
            case "STAT" -> {
                int size = 0;
                for (String message : messages) {
                    size += bytes(message).length;
                }
                c.line("+OK " + messages.size() + " " + size);
            }
            case "LIST", "UIDL" -> {
                if (words.length > 1) {
                    int n = Integer.parseInt(words[1]);
                    c.line("+OK " + n + " " + (verb.equals("LIST")
                            ? bytes(messages.get(n - 1)).length : "uid-" + n));
                    return;
                }
                c.line("+OK");
                for (int n = 1; n <= messages.size(); n++) {
                    c.line(n + " " + (verb.equals("LIST")
                            ? bytes(messages.get(n - 1)).length : "uid-" + n));
                }
                c.line(".");
            }
            case "RETR", "TOP" -> {
                int n = Integer.parseInt(words[1]);
                String message = messages.get(n - 1);
                if (verb.equals("TOP")) {
                    message = message.substring(0, message.indexOf("\r\n\r\n") + 4);
                }
                c.line("+OK " + bytes(message).length + " octets");
                if (message.endsWith("\r\n")) {
                    message = message.substring(0, message.length() - 2);
                }
                for (String line : message.split("\r\n", -1)) {
                    c.line(line.startsWith(".") ? "." + line : line);
                }
                c.line(".");
            }
            case "DELE", "RSET" -> c.line("+OK");
            default -> c.line("-ERR unknown command " + verb);
        }
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
