package space.seclume.internal.jdbc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Where a Patroni cluster's leader and replicas are, asked of the cluster
 * itself instead of waiting for DNS or a load balancer to notice a switchover.
 *
 * <pre>
 *   jdbc:seclume:postgresql://db1,db2,db3/app?targetServerType=primary
 *       &amp;patroni=http://db1:8008,http://db2:8008,http://db3:8008
 * </pre>
 *
 * <p>Before a connection is opened, {@code GET /cluster} on the first REST
 * endpoint that answers lists the members and their roles. They replace the
 * URL's hosts for that attempt, ordered for what the connection wants: the
 * leader first for {@code primary}, replicas first for {@code secondary}. The
 * answer is kept for a second, so a burst of new connections asks once. When
 * no endpoint answers, the URL's own hosts are used as before - the topology
 * speeds up finding the right server, it is never the only way to find one.
 * The server's own answer to "what are you" is still checked after
 * connecting.
 */
public final class PatroniTopology implements ClusterTopology {

    private static final long KEEP_NANOS = 1_000_000_000L;
    private static final int TIMEOUT_MILLIS = 1500;
    private static final int MAX_ANSWER = 1 << 20;

    private final List<URI> endpoints;
    private volatile List<Member> cached;
    private volatile long cachedAt;

    /** One member as Patroni lists it. */
    public record Member(String host, int port, String role, String state) {

        boolean leader() {
            return role.equals("leader") || role.equals("standby_leader");
        }

        boolean usable() {
            return state.equals("running") || state.equals("streaming");
        }
    }

    private PatroniTopology(List<URI> endpoints) {
        this.endpoints = endpoints;
    }

    /** The {@code patroni=} option, or null when there is none. */
    public static PatroniTopology of(String option) {
        if (option == null || option.isBlank()) {
            return null;
        }
        List<URI> endpoints = new ArrayList<>();
        for (String one : option.split(",")) {
            String trimmed = one.trim();
            if (!trimmed.isEmpty()) {
                endpoints.add(URI.create(trimmed.contains("://") ? trimmed : "http://" + trimmed));
            }
        }
        return endpoints.isEmpty() ? null : new PatroniTopology(List.copyOf(endpoints));
    }

    /**
     * The members to try, in order, for {@code wanted}; empty when no endpoint
     * answered - the caller then keeps its own list.
     */
    @Override
    public List<HostList.Host> hosts(TargetServer wanted) {
        List<HostList.Host> leaders = new ArrayList<>();
        List<HostList.Host> replicas = new ArrayList<>();
        for (Member member : members()) {
            if (member.usable()) {
                (member.leader() ? leaders : replicas)
                        .add(new HostList.Host(member.host(), member.port()));
            }
        }
        List<HostList.Host> ordered = new ArrayList<>();
        if (wanted == TargetServer.SECONDARY) {
            ordered.addAll(replicas);
            ordered.addAll(leaders);
        } else {
            ordered.addAll(leaders);
            ordered.addAll(replicas);
        }
        return ordered;
    }

    /** The cluster as the first answering endpoint describes it; kept for a second. */
    List<Member> members() {
        List<Member> known = cached;
        if (known != null && System.nanoTime() - cachedAt < KEEP_NANOS) {
            return known;
        }
        for (URI endpoint : endpoints) {
            try {
                List<Member> fresh = parse(get(endpoint.resolve("/cluster")));
                cached = fresh;
                cachedAt = System.nanoTime();
                return fresh;
            } catch (IOException | RuntimeException unanswered) {
                // the next endpoint; a Patroni node that is down is the case this is for
            }
        }
        return List.of();
    }

    /** {@code GET} over HTTP/1.1, or HTTPS through the JDK's TLS; the answer's body. */
    private static String get(URI uri) throws IOException {
        boolean tls = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() > 0 ? uri.getPort() : (tls ? 443 : 80);
        try (Socket socket = tls ? javax.net.ssl.SSLSocketFactory.getDefault().createSocket()
                // Plain HTTP only when the configured Patroni URL says http; https is verified.
                : new Socket()) { // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
            socket.connect(new InetSocketAddress(uri.getHost(), port), TIMEOUT_MILLIS);
            socket.setSoTimeout(TIMEOUT_MILLIS);
            if (socket instanceof javax.net.ssl.SSLSocket secure) {
                javax.net.ssl.SSLParameters parameters = secure.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                secure.setSSLParameters(parameters);
            }
            OutputStream out = socket.getOutputStream();
            out.write(("GET " + uri.getRawPath() + " HTTP/1.1\r\nHost: " + uri.getHost()
                    + "\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII)); // seclume-allow: an HTTP request line, no secret in it
            out.flush();
            InputStream in = socket.getInputStream();
            ByteArrayOutputStream answer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192]; // seclume-allow: a cluster description, not a secret
            int read;
            while ((read = in.read(chunk)) > 0) {
                answer.write(chunk, 0, read);
                if (answer.size() > MAX_ANSWER) {
                    throw new IOException("the cluster description is larger than " + MAX_ANSWER);
                }
            }
            String text = answer.toString(StandardCharsets.UTF_8);
            if (text.length() < 12 || !text.startsWith("HTTP/1.")
                    || !text.substring(9, 12).equals("200")) {
                throw new IOException("Patroni answered " + text.lines().findFirst().orElse(""));
            }
            int body = text.indexOf("\r\n\r\n");
            return body < 0 ? "" : text.substring(body + 4);
        }
    }

    /** The members of a {@code /cluster} answer. */
    static List<Member> parse(String json) {
        Object root = new Json(json).value();
        List<Member> members = new ArrayList<>();
        if (root instanceof Map<?, ?> map && map.get("members") instanceof List<?> list) {
            for (Object entry : list) {
                if (entry instanceof Map<?, ?> member && member.get("host") instanceof String host) {
                    Object port = member.get("port");
                    members.add(new Member(host,
                            port instanceof Number number ? number.intValue() : 5432,
                            String.valueOf(member.get("role")).toLowerCase(Locale.ROOT),
                            String.valueOf(member.get("state")).toLowerCase(Locale.ROOT)));
                }
            }
        }
        return members;
    }

    /** Just enough JSON for a cluster description: objects, arrays, strings, numbers, literals. */
    private static final class Json {

        private final String text;
        private int at;

        Json(String text) {
            this.text = text;
        }

        Object value() {
            skip();
            if (at >= text.length()) {
                throw new IllegalArgumentException("the answer ends early");
            }
            char c = text.charAt(at);
            if (c == '{') {
                return object();
            }
            if (c == '[') {
                return array();
            }
            if (c == '"') {
                return string();
            }
            if (c == '-' || Character.isDigit(c)) {
                int start = at;
                while (at < text.length() && "-+.eE0123456789".indexOf(text.charAt(at)) >= 0) {
                    at++;
                }
                return Double.parseDouble(text.substring(start, at));
            }
            for (String literal : new String[] {"true", "false", "null"}) {
                if (text.startsWith(literal, at)) {
                    at += literal.length();
                    return literal.equals("null") ? null : Boolean.valueOf(literal);
                }
            }
            throw new IllegalArgumentException("not JSON at " + at);
        }

        private Map<String, Object> object() {
            Map<String, Object> map = new LinkedHashMap<>();
            at++;
            skip();
            if (peek() == '}') {
                at++;
                return map;
            }
            while (true) {
                skip();
                String key = string();
                skip();
                expect(':');
                map.put(key, value());
                skip();
                if (peek() == ',') {
                    at++;
                    continue;
                }
                expect('}');
                return map;
            }
        }

        private List<Object> array() {
            List<Object> list = new ArrayList<>();
            at++;
            skip();
            if (peek() == ']') {
                at++;
                return list;
            }
            while (true) {
                list.add(value());
                skip();
                if (peek() == ',') {
                    at++;
                    continue;
                }
                expect(']');
                return list;
            }
        }

        private String string() {
            expect('"');
            StringBuilder out = new StringBuilder(); // seclume-allow: a host name or a role, no secret
            while (peek() != '"') {
                char c = text.charAt(at++);
                if (c == '\\') {
                    char escaped = text.charAt(at++);
                    switch (escaped) {
                        case 'n' -> out.append('\n');
                        case 't' -> out.append('\t');
                        case 'u' -> {
                            out.append((char) Integer.parseInt(text.substring(at, at + 4), 16));
                            at += 4;
                        }
                        default -> out.append(escaped);
                    }
                } else {
                    out.append(c);
                }
            }
            at++;
            return out.toString();
        }

        private char peek() {
            if (at >= text.length()) {
                throw new IllegalArgumentException("the answer ends early");
            }
            return text.charAt(at);
        }

        private void expect(char c) {
            if (peek() != c) {
                throw new IllegalArgumentException("expected '" + c + "' at " + at);
            }
            at++;
        }

        private void skip() {
            while (at < text.length() && Character.isWhitespace(text.charAt(at))) {
                at++;
            }
        }
    }
}
