package space.seclume.elasticsearch;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64; // seclume-allow: user:placeholder - the secret is written in by seclume's TLS
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import space.seclume.http.SeclumeSslSocketFactory;

/**
 * seclume's URL for an Elasticsearch or OpenSearch cluster:
 *
 * <pre>
 * https://es1.example.com:9200,es2.example.com:9200/?auth=apikey&amp;provider=file&amp;path=/run/secrets/es-key
 * https://elastic@es.example.com:9200/?auth=basic&amp;provider=vault&amp;...&amp;tlsRootCert=/etc/es/ca.pem
 * </pre>
 *
 * <p>{@code auth} says what the secret is: {@code apikey} - the encoded API
 * key, {@code base64(id:key)}, as Elasticsearch hands it out - {@code bearer}
 * for a token, or {@code basic} for the password of the user named before
 * the {@code @}. The secret provider's options name where it comes from, as
 * everywhere in seclume; {@code tlsRootCert} and {@code tlsPin} whom to
 * trust. A password in the URL is refused, and so is {@code http://}: the
 * secret only ever travels inside seclume's TLS.
 */
record SearchUrl(List<Host> hosts, String pathPrefix, String authorization, String tls) {

    record Host(String name, int port) {
    }

    private static final Set<String> TLS_OPTIONS = Set.of("tlsRootCert", "tlsPin",
            "connectTimeout");

    static SearchUrl parse(String url) {
        if (url == null || !url.startsWith("https://")) {
            throw new IllegalArgumentException("an Elasticsearch or OpenSearch URL starts with "
                    + "https:// - the secret is only ever sent inside TLS");
        }
        String rest = url.substring("https://".length());
        int question = rest.indexOf('?');
        String options = question < 0 ? "" : rest.substring(question + 1);
        String location = question < 0 ? rest : rest.substring(0, question);
        int slash = location.indexOf('/');
        String authority = slash < 0 ? location : location.substring(0, slash);
        String path = slash < 0 ? "" : location.substring(slash);
        String user = null;
        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            user = URLDecoder.decode(authority.substring(0, at), StandardCharsets.UTF_8);
            if (user.contains(":")) {
                throw new IllegalArgumentException("a password in the URL is refused: name "
                        + "where it comes from instead (provider=...)");
            }
            authority = authority.substring(at + 1);
        }
        List<Host> hosts = new ArrayList<>();
        for (String one : authority.split(",")) {
            int colon = one.lastIndexOf(':');
            String name = colon < 0 ? one : one.substring(0, colon);
            int port;
            try {
                port = colon < 0 ? 9200 : Integer.parseInt(one.substring(colon + 1));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("not a port in '" + one + "'", e);
            }
            if (name.isEmpty() || port <= 0 || port > 65_535) {
                throw new IllegalArgumentException("not a host and port: '" + one + "'");
            }
            hosts.add(new Host(name, port));
        }

        Map<String, String> secret = new LinkedHashMap<>();
        StringBuilder tls = new StringBuilder();
        String auth = null;
        for (String pair : options.split("&")) {
            int equals = pair.indexOf('=');
            if (equals <= 0) {
                continue;
            }
            String key = URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8);
            if (key.equals("auth")) {
                auth = URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8)
                        .toLowerCase(Locale.ROOT);
            } else if (TLS_OPTIONS.contains(key)) {
                tls.append(tls.isEmpty() ? "" : "&").append(pair);
            } else {
                secret.put(key, URLDecoder.decode(pair.substring(equals + 1),
                        StandardCharsets.UTF_8));
            }
        }
        if (auth == null) {
            throw new IllegalArgumentException("auth=apikey, auth=bearer or auth=basic: what "
                    + "the secret is");
        }
        if (!secret.containsKey("provider")) {
            throw new IllegalArgumentException("no secret named: give the secret provider's "
                    + "options, e.g. provider=file&path=/run/secrets/es-key");
        }
        StringBuilder spec = new StringBuilder();
        secret.forEach((k, v) -> spec.append(spec.isEmpty() ? "" : "&").append(k).append('=')
                .append(java.net.URLEncoder.encode(v, StandardCharsets.UTF_8)));
        String placeholder = SeclumeSslSocketFactory.placeholder(spec.toString());
        String authorization = switch (auth) {
            case "apikey" -> "ApiKey " + placeholder;
            case "bearer" -> "Bearer " + placeholder;
            case "basic" -> {
                if (user == null || user.isEmpty()) {
                    throw new IllegalArgumentException("auth=basic needs the user before the @");
                }
                byte[] userAndPlaceholder = (user + ":" + placeholder) // seclume-allow: the user and a placeholder - no secret
                        .getBytes(StandardCharsets.UTF_8); // seclume-allow: the user and a placeholder - no secret
                yield "Basic " + Base64.getEncoder() // seclume-allow: the user and a placeholder - no secret
                        .encodeToString(userAndPlaceholder);
            }
            default -> throw new IllegalArgumentException("auth=" + auth + " is none of "
                    + "apikey, bearer and basic");
        };
        if (!auth.equals("basic") && user != null) {
            throw new IllegalArgumentException("a user before the @ goes with auth=basic only");
        }
        return new SearchUrl(List.copyOf(hosts), path.equals("/") ? "" : path, authorization,
                tls.toString());
    }
}
