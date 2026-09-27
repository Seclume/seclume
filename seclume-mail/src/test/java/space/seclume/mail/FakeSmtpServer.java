package space.seclume.mail;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * A small SMTP server for the tests: STARTTLS or implicit TLS (the JDK's,
 * TLS 1.3), AUTH PLAIN, LOGIN and XOAUTH2 checked against what it was given,
 * and every message kept - envelope and the DATA with its dots unstuffed.
 *
 * <p>Deliberately strict where a real server is lenient: a command before
 * STARTTLS that needs encryption, a login in the clear or a bare LF in DATA
 * is answered with an error, so the client cannot pass by accident.
 */
final class FakeSmtpServer implements AutoCloseable {

    /** One message as the server took it. */
    record Received(String from, List<String> recipients, String data, String mailCommand) {
    }

    // what it offers and expects
    String user = "reports";
    byte[] password = "correct horse".getBytes(StandardCharsets.UTF_8);
    byte[] token = "ya29.test-token".getBytes(StandardCharsets.UTF_8);
    List<String> mechanisms = List.of("PLAIN", "LOGIN", "XOAUTH2");
    boolean offerStartTls = true;
    boolean eightBit = true;
    boolean smtpUtf8 = false;
    boolean injectAfterStartTls;
    boolean requireAuth = true;

    // what it saw
    final List<Received> received = new CopyOnWriteArrayList<>();
    final List<String> logins = new CopyOnWriteArrayList<>();
    final List<String> commands = new CopyOnWriteArrayList<>();

    private final SSLContext tls;
    private final boolean implicitTls;
    private final ServerSocket listener;
    private final Thread acceptor;

    FakeSmtpServer(SSLContext tls, boolean implicitTls) throws IOException {
        this.tls = tls;
        this.implicitTls = implicitTls;
        if (implicitTls) {
            SSLServerSocket secure = (SSLServerSocket) tls.getServerSocketFactory()
                    .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
            secure.setEnabledProtocols(new String[] {"TLSv1.3"});
            this.listener = secure;
        } else {
            this.listener = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        }
        this.acceptor = new Thread(this::accept, "fake-smtp");
        this.acceptor.setDaemon(true);
        this.acceptor.start();
    }

    int port() {
        return listener.getLocalPort();
    }

    private void accept() {
        while (!listener.isClosed()) {
            try {
                Socket socket = listener.accept();
                Thread session = new Thread(() -> serve(socket), "fake-smtp-session");
                session.setDaemon(true);
                session.start();
            } catch (IOException closed) {
                return;
            }
        }
    }

    private void serve(Socket socket) {
        try (Socket plain = socket) {
            new Session(plain).run();
        } catch (IOException | RuntimeException ignored) {
            // the client went away; the test asserts on what was recorded
        }
    }

    @Override
    public void close() throws IOException {
        listener.close();
    }

    /** One connection's worth of the protocol. */
    private final class Session {

        private Socket socket;
        private InputStream in;
        private OutputStream out;
        private boolean encrypted;
        private boolean authenticated;
        private String from;
        private final List<String> recipients = new ArrayList<>();
        private String mailCommand;

        Session(Socket socket) throws IOException {
            this.socket = socket;
            this.in = new BufferedInputStream(socket.getInputStream());
            this.out = socket.getOutputStream();
            this.encrypted = implicitTls;
        }

        void run() throws IOException {
            reply("220 localhost ESMTP fake");
            while (true) {
                String line = readLine();
                if (line == null) {
                    return;
                }
                commands.add(line.startsWith("AUTH ") ? line.substring(0, line.indexOf(' ', 5) < 0
                        ? line.length() : line.indexOf(' ', 5)) : line);
                String verb = (line.contains(" ") ? line.substring(0, line.indexOf(' ')) : line)
                        .toUpperCase();
                switch (verb) {
                    case "EHLO" -> ehlo();
                    case "STARTTLS" -> startTls();
                    case "AUTH" -> auth(line);
                    case "MAIL" -> mail(line);
                    case "RCPT" -> rcpt(line);
                    case "DATA" -> data();
                    case "RSET" -> {
                        reset();
                        reply("250 OK");
                    }
                    case "QUIT" -> {
                        reply("221 bye");
                        return;
                    }
                    default -> reply("502 unknown command");
                }
            }
        }

        private void ehlo() throws IOException {
            List<String> lines = new ArrayList<>();
            lines.add("localhost greets you");
            if (!encrypted && offerStartTls) {
                lines.add("STARTTLS");
            }
            if (encrypted) {
                lines.add("AUTH " + String.join(" ", mechanisms));
            }
            if (eightBit) {
                lines.add("8BITMIME");
            }
            if (smtpUtf8) {
                lines.add("SMTPUTF8");
            }
            lines.add("SIZE 10485760");
            for (int i = 0; i < lines.size(); i++) {
                reply("250" + (i == lines.size() - 1 ? " " : "-") + lines.get(i));
            }
        }

        private void startTls() throws IOException {
            if (encrypted) {
                reply("503 already encrypted");
                return;
            }
            if (injectAfterStartTls) {
                // what a man in the middle would do: a reply smuggled in the plaintext
                out.write("220 ready\r\n250 injected\r\n".getBytes(StandardCharsets.US_ASCII));
                out.flush();
            } else {
                reply("220 ready");
            }
            SSLSocket secure = (SSLSocket) tls.getSocketFactory().createSocket(socket, null, true);
            secure.setUseClientMode(false);
            secure.setEnabledProtocols(new String[] {"TLSv1.3"});
            // The server side, which checks no peer certificate at all - but set
            // like a client's, so no reading of this file takes it for a socket
            // that trusts whatever it is shown.
            javax.net.ssl.SSLParameters parameters = secure.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            secure.setSSLParameters(parameters);
            secure.startHandshake();
            socket = secure;
            in = new BufferedInputStream(secure.getInputStream());
            out = secure.getOutputStream();
            encrypted = true;
            authenticated = false;
        }

        private void auth(String line) throws IOException {
            if (!encrypted) {
                reply("538 encryption required for AUTH");
                return;
            }
            String[] parts = line.split(" ");
            String mechanism = parts[1].toUpperCase();
            if (!mechanisms.contains(mechanism)) {
                reply("504 unrecognized mechanism");
                return;
            }
            boolean ok = switch (mechanism) {
                case "PLAIN" -> {
                    byte[] raw = Base64.getDecoder().decode(parts[2]);
                    byte[] expected = concat(new byte[] {0}, user.getBytes(StandardCharsets.UTF_8),
                            new byte[] {0}, password);
                    yield Arrays.equals(raw, expected);
                }
                case "LOGIN" -> {
                    reply("334 VXNlcm5hbWU6");
                    String name = new String(Base64.getDecoder().decode(readLine()),
                            StandardCharsets.UTF_8);
                    reply("334 UGFzc3dvcmQ6");
                    byte[] given = Base64.getDecoder().decode(readLine());
                    yield name.equals(user) && Arrays.equals(given, password);
                }
                case "XOAUTH2" -> {
                    byte[] raw = Base64.getDecoder().decode(parts[2]);
                    byte[] expected = concat(("user=" + user + "\u0001auth=Bearer ")
                            .getBytes(StandardCharsets.UTF_8), token, new byte[] {1, 1});
                    if (Arrays.equals(raw, expected)) {
                        yield true;
                    }
                    reply("334 " + Base64.getEncoder().encodeToString(
                            "{\"status\":\"401\",\"schemes\":\"bearer\"}"
                                    .getBytes(StandardCharsets.UTF_8)));
                    readLine();
                    yield false;
                }
                default -> false;
            };
            if (ok) {
                authenticated = true;
                logins.add(mechanism);
                reply("235 2.7.0 Authentication successful");
            } else {
                reply("535 5.7.8 Authentication credentials invalid");
            }
        }

        private void mail(String line) throws IOException {
            if (requireAuth && !authenticated) {
                reply("530 5.7.0 Authentication required");
                return;
            }
            reset();
            mailCommand = line;
            from = between(line, '<', '>');
            reply("250 OK");
        }

        private void rcpt(String line) throws IOException {
            if (from == null) {
                reply("503 MAIL first");
                return;
            }
            String to = between(line, '<', '>');
            if (to.startsWith("nobody")) {
                reply("550 5.1.1 no such user");
                return;
            }
            recipients.add(to);
            reply("250 OK");
        }

        private void data() throws IOException {
            if (recipients.isEmpty()) {
                reply("503 RCPT first");
                return;
            }
            reply("354 go ahead");
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            while (true) {
                String line = readLineStrict();
                if (line.equals(".")) {
                    break;
                }
                body.writeBytes((line.startsWith(".") ? line.substring(1) : line)
                        .getBytes(StandardCharsets.UTF_8));
                body.writeBytes("\r\n".getBytes(StandardCharsets.US_ASCII));
            }
            received.add(new Received(from, List.copyOf(recipients),
                    body.toString(StandardCharsets.UTF_8), mailCommand));
            reset();
            reply("250 2.0.0 queued as FAKE" + received.size());
        }

        private void reset() {
            from = null;
            recipients.clear();
            mailCommand = null;
        }

        private void reply(String line) throws IOException {
            out.write((line + "\r\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
        }

        /** A line without its CRLF, or null at the end of the stream. */
        private String readLine() throws IOException {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            int b;
            while ((b = in.read()) >= 0) {
                if (b == '\n') {
                    byte[] bytes = line.toByteArray();
                    int length = bytes.length > 0 && bytes[bytes.length - 1] == '\r'
                            ? bytes.length - 1 : bytes.length;
                    return new String(bytes, 0, length, StandardCharsets.UTF_8);
                }
                line.write(b);
            }
            return null;
        }

        /** In DATA: every line must end in CRLF - a bare LF is a client bug. */
        private String readLineStrict() throws IOException {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            int b;
            int previous = -1;
            while ((b = in.read()) >= 0) {
                if (b == '\n') {
                    if (previous != '\r') {
                        throw new IOException("a bare LF in DATA");
                    }
                    byte[] bytes = line.toByteArray();
                    return new String(bytes, 0, bytes.length - 1, StandardCharsets.UTF_8);
                }
                if (previous == '\r') {
                    throw new IOException("a bare CR in DATA");
                }
                line.write(b);
                previous = b;
            }
            throw new IOException("the stream ended in DATA");
        }
    }

    private static String between(String line, char open, char close) {
        int start = line.indexOf(open);
        int end = line.indexOf(close, start + 1);
        return start < 0 || end < 0 ? "" : line.substring(start + 1, end);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            all.writeBytes(part);
        }
        return all.toByteArray();
    }
}
