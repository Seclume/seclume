package space.seclume.mail;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * A POP3 connection up to "logged in" (the TRANSACTION state) - from there on
 * it is Jakarta Mail's; see {@link MailSocket} for how it is told.
 *
 * <p>The greeting, CAPA (RFC 2449), STLS (RFC 2595) where the URL asks for
 * STARTTLS, and one of:
 *
 * <ul>
 *   <li>{@code AUTH PLAIN} with its initial response (RFC 5034), the default
 *       wherever CAPA names PLAIN among its SASL mechanisms;
 *   <li>{@code AUTH XOAUTH2} for Microsoft 365 and Google, by name;
 *   <li>{@code USER} and {@code PASS}, the protocol's own login, where PLAIN is
 *       not offered - or by name.
 * </ul>
 */
final class Pop3Login {

    private final MailWire wire;
    private final MailSettings settings;

    private Pop3Login(MailWire wire) {
        this.wire = wire;
        this.settings = wire.settings();
    }

    /** Connected, encrypted and logged in - or closed and refused. */
    static MailWire open(MailSettings settings) throws IOException {
        MailWire wire = MailWire.connect(settings);
        try {
            Pop3Login login = new Pop3Login(wire);
            MailEvents.login("pop3", settings, login::login);
            return wire;
        } catch (IOException | RuntimeException e) {
            wire.close();
            throw e;
        }
    }

    private void login() throws IOException {
        String greeting = wire.readLine();
        if (!greeting.startsWith("+OK")) {
            throw new MailException(-1, settings.host + " did not greet as a POP3 server: "
                    + greeting);
        }
        Map<String, String> capabilities = capa();
        if (settings.startTls) {
            if (!capabilities.containsKey("STLS")) {
                throw new MailException(-1, settings.host + " does not offer STLS (STARTTLS "
                        + "for POP3). Nothing is sent to it in the clear");
            }
            wire.writeLine("STLS");
            expectOk("STLS");
            wire.startTls();
            capabilities = capa();
        }

        List<String> sasl = List.of(capabilities.getOrDefault("SASL", "")
                .toUpperCase(Locale.ROOT).split("\\s+"));
        MailSettings.Auth auth = settings.auth;
        if (auth == MailSettings.Auth.BEST) {
            auth = sasl.contains("PLAIN") ? MailSettings.Auth.PLAIN : MailSettings.Auth.LOGIN;
        }
        switch (auth) {
            case PLAIN, XOAUTH2 -> {
                String mechanism = auth.name();
                if (!sasl.contains(mechanism)) {
                    throw new MailException(-1, settings.host + " does not offer AUTH "
                            + mechanism + " (its SASL mechanisms: "
                            + capabilities.getOrDefault("SASL", "none") + ")");
                }
                if (auth == MailSettings.Auth.PLAIN) {
                    Sasl.plain(wire, "AUTH PLAIN ");
                } else {
                    Sasl.xoauth2(wire, "AUTH XOAUTH2 ");
                }
                String reply = wire.readLine();
                if (reply.startsWith("+ ") || reply.equals("+")) {
                    String reason = MailReplies.oauthReason(reply.substring(1));
                    wire.writeLine("");
                    wire.readLine();
                    throw new MailException(-1, "the server refused the token of "
                            + settings.user + ": " + reason);
                }
                requireOk(reply, "AUTH " + mechanism);
            }
            case LOGIN -> {
                wire.writeLine("USER " + settings.user);
                expectOk("USER");
                Sasl.passwordLine(wire, "PASS ");
                expectOk("PASS");
            }
            default -> throw new IllegalStateException("no POP3 login for " + auth);
        }
    }

    /** CAPA's answer, keyword to parameters; empty when the server does not know CAPA. */
    private Map<String, String> capa() throws IOException {
        wire.writeLine("CAPA");
        Map<String, String> capabilities = new TreeMap<>();
        if (!wire.readLine().startsWith("+OK")) {
            return capabilities;
        }
        while (true) {
            String line = wire.readLine();
            if (line.equals(".")) {
                return capabilities;
            }
            int space = line.indexOf(' ');
            capabilities.put((space < 0 ? line : line.substring(0, space)).toUpperCase(Locale.ROOT),
                    space < 0 ? "" : line.substring(space + 1).trim());
        }
    }

    private void expectOk(String step) throws IOException {
        requireOk(wire.readLine(), step);
    }

    private void requireOk(String reply, String step) throws MailException {
        if (!reply.startsWith("+OK")) {
            boolean login = step.startsWith("AUTH") || step.equals("PASS") || step.equals("USER");
            throw new MailException(-1, login
                    ? "the server refused the login of " + settings.user + " (" + step + "): "
                            + reply
                    : step + " was answered with: " + reply);
        }
    }
}
