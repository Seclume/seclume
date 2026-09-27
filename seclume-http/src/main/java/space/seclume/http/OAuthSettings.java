package space.seclume.http;

import java.net.URI;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import space.seclume.internal.TrustChoice;

/**
 * {@code auth=oauth2}: the OAuth 2.0 client credentials grant (RFC 6749 4.4)
 * against a token endpoint, whose access token then goes to the API as
 * {@code Authorization: Bearer}.
 *
 * <pre>
 * https://graph.microsoft.com/v1.0?auth=oauth2
 *     &amp;token-url=https://login.microsoftonline.com/&lt;tenant&gt;/oauth2/v2.0/token
 *     &amp;client-id=...&amp;scope=https://graph.microsoft.com/.default
 *     &amp;provider=vault&amp;...                        (the client secret)
 * </pre>
 *
 * <ul>
 *   <li>{@code token-url} - the token endpoint, {@code https://} only;
 *   <li>{@code client-id} - the application's id, which is public;
 *   <li>{@code scope}, {@code resource} (Entra ID v1, AD FS) and
 *       {@code audience} (Auth0) - sent when given;
 *   <li>{@code client-auth} - {@code basic} (the default, RFC 6749 2.3.1) or
 *       {@code post}, the secret in the form body;
 *   <li>{@code token-tlsRootCert} or {@code token-tlsPin} for a token endpoint
 *       whose CA the JVM does not know - the API's own {@code tlsPin} is for
 *       the API, which is usually another server.
 * </ul>
 *
 * <p>The secret provider's options name the client secret.
 */
final class OAuthSettings {

    enum ClientAuth { BASIC, POST }

    final HttpSettings.Endpoint endpoint;
    final String authority;
    final String path;
    final String clientId;
    final String scope;
    final String resource;
    final String audience;
    final ClientAuth clientAuth;

    private OAuthSettings(HttpSettings.Endpoint endpoint, String authority, String path,
                          String clientId, String scope, String resource, String audience,
                          ClientAuth clientAuth) {
        this.endpoint = endpoint;
        this.authority = authority;
        this.path = path;
        this.clientId = clientId;
        this.scope = scope;
        this.resource = resource;
        this.audience = audience;
        this.clientAuth = clientAuth;
    }

    /** Takes its options out of {@code options}, leaving the secret provider's. */
    static OAuthSettings take(Map<String, String> options, int connectTimeout, int timeout) {
        String tokenUrl = options.remove("token-url");
        String clientId = options.remove("client-id");
        String scope = options.remove("scope");
        String resource = options.remove("resource");
        String audience = options.remove("audience");
        String clientAuthName = options.remove("client-auth");
        String rootCert = options.remove("token-" + TrustChoice.ROOT_CERT);
        String pin = options.remove("token-" + TrustChoice.PIN);
        if (tokenUrl == null) {
            throw new IllegalArgumentException("auth=oauth2 needs token-url= - the identity "
                    + "provider's token endpoint, e.g. https://login.microsoftonline.com/"
                    + "<tenant>/oauth2/v2.0/token");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("auth=oauth2 needs client-id=");
        }
        for (String value : new String[] {clientId, scope, resource, audience}) {
            if (value != null && !HttpSettings.printable(value)) {
                throw new IllegalArgumentException("client-id, scope, resource and audience "
                        + "cannot hold control characters");
            }
        }
        URI uri = URI.create(tokenUrl);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            throw new IllegalArgumentException("token-url begins with https:// and names a "
                    + "host - the client secret is never sent in the clear, not to "
                    + uri.getScheme() + "://" + uri.getHost());
        }
        if (uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("token-url takes no user info and no fragment");
        }
        ClientAuth clientAuth = switch (clientAuthName == null ? "basic"
                : clientAuthName.toLowerCase(Locale.ROOT)) {
            case "basic" -> ClientAuth.BASIC;
            case "post" -> ClientAuth.POST;
            default -> throw new IllegalArgumentException("client-auth is basic or post, not '"
                    + clientAuthName + "'");
        };
        TrustChoice.Choice trust = null;
        if (rootCert != null || pin != null) {
            Properties named = new Properties();
            if (rootCert != null) {
                named.setProperty(TrustChoice.ROOT_CERT, rootCert);
            }
            if (pin != null) {
                named.setProperty(TrustChoice.PIN, pin);
            }
            try {
                trust = TrustChoice.of(null, named);
            } catch (SQLException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }
        int port = uri.getPort() >= 0 ? uri.getPort() : 443;
        String host = uri.getHost();
        String name = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/"
                : uri.getRawPath();
        if (uri.getRawQuery() != null) {
            path = path + "?" + uri.getRawQuery();
        }
        return new OAuthSettings(new HttpSettings.Endpoint(host, port, trust, connectTimeout,
                timeout), port == 443 ? name : name + ":" + port, path, clientId, scope,
                resource, audience, clientAuth);
    }
}
