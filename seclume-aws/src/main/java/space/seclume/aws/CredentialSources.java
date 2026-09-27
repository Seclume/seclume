package space.seclume.aws;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import space.seclume.internal.AwsSigV4;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;
import space.seclume.internal.TrustChoice;
import space.seclume.secret.AwsInstanceRole;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;
import space.seclume.secret.SecretUnavailableException;

/**
 * Where temporary credentials come from - the three ways AWS hands them to a
 * workload, none of which leaves a key in a file:
 *
 * <ul>
 *   <li>{@code instance} - an EC2 instance's role, from the instance metadata
 *       service (IMDSv2);
 *   <li>{@code container} - ECS tasks and EKS Pod Identity, from the container
 *       credentials endpoint ({@code AWS_CONTAINER_CREDENTIALS_FULL_URI} and the
 *       token in {@code AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE});
 *   <li>{@code web-identity} - EKS with IAM roles for service accounts (IRSA):
 *       the pod's token from {@code AWS_WEB_IDENTITY_TOKEN_FILE} traded with STS
 *       ({@code AssumeRoleWithWebIdentity}) for the role in {@code AWS_ROLE_ARN}.
 * </ul>
 *
 * <p>Every secret on the way - the metadata service's token, the container
 * token, the web identity token, and the credentials that come back - is
 * read into native memory and never becomes a Java object.
 */
final class CredentialSources {

    private static final int ROOM = 8 * 1024;

    private CredentialSources() {
    }

    static TemporaryCredentials of(String kind, Map<String, String> options,
                                   TrustChoice.Choice trust, String region) {
        return switch (kind) {
            case "instance" -> new Instance();
            case "container" -> new Container(option(options, "container-uri",
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI"), option(options, "container-token-file",
                    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"));
            case "web-identity" -> new WebIdentity(option(options, "role-arn", "AWS_ROLE_ARN"),
                    option(options, "web-identity-token-file", "AWS_WEB_IDENTITY_TOKEN_FILE"),
                    options.getOrDefault("role-session-name", "seclume"),
                    options.getOrDefault("sts-endpoint", region == null ? "sts.amazonaws.com"
                            : "sts." + region + ".amazonaws.com"), trust);
            default -> throw new IllegalArgumentException("credentials= is static, instance, "
                    + "container or web-identity, not '" + kind + "'");
        };
    }

    /** An option, or the environment variable AWS's own SDKs read - a name or a path, never a secret. */
    private static String option(Map<String, String> options, String name, String variable) {
        String value = options.get(name);
        if (value == null) {
            value = System.getenv(variable); // seclume-allow: a role name, a URI or a file path - the secrets are in the files
        }
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + "= is missing, and so is " + variable
                    + " in the environment");
        }
        return value;
    }

    /** EC2: the instance role, through the core's own IMDSv2 client. */
    static final class Instance extends TemporaryCredentials {

        @Override
        Fetched fetch() {
            AwsInstanceRole role = AwsInstanceRole.shared();
            return role.use((accessKeyId, secretKey, token) -> new Fetched(accessKeyId,
                    role.validUntil(), SecretScope.fromProvider(secretKey),
                    SecretScope.fromProvider(token)));
        }

        @Override
        String name() {
            return "instance";
        }
    }

    /** ECS and EKS Pod Identity: a link-local endpoint, asked with the container's token. */
    static final class Container extends TemporaryCredentials {

        private final URI uri;
        private final String tokenFile;

        Container(String uri, String tokenFile) {
            this.uri = URI.create(uri);
            this.tokenFile = tokenFile;
        }

        @Override
        Fetched fetch() {
            try (Arena arena = Arena.ofConfined();
                 SecretProvider file = SecretProviders.of(Map.of("provider", "file",
                         "path", tokenFile));
                 SecretScope token = SecretScope.fromProvider(file);
                 SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {
                SecretFetch.Response response = SecretFetch.sendLinkLocal(uri.getHost(),
                        uri.getPort() < 0 ? 80 : uri.getPort(), 5_000, "GET",
                        uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/"
                                : uri.getRawPath(), Map.of(),
                        List.of(new SecretFetch.SecretHeader("Authorization", token.segment(),
                                token.length())), answer.segment());
                if (response.status() != 200) {
                    throw new SecretUnavailableException("the container credentials endpoint "
                            + "answered " + response.status());
                }
                return json(answer.segment(), response.bodyLength(), "Token");
            } catch (IOException e) {
                throw new SecretUnavailableException("the container credentials endpoint "
                        + uri + " could not be reached", e);
            }
        }

        @Override
        String name() {
            return "container";
        }
    }

    /** EKS IRSA: the pod's token for the role's credentials, from STS. */
    static final class WebIdentity extends TemporaryCredentials {

        private final String roleArn;
        private final String tokenFile;
        private final String sessionName;
        private final String host;
        private final int port;
        private final TrustChoice.Choice trust;

        WebIdentity(String roleArn, String tokenFile, String sessionName, String endpoint,
                    TrustChoice.Choice trust) {
            this.roleArn = roleArn;
            this.tokenFile = tokenFile;
            this.sessionName = sessionName;
            int colon = endpoint.lastIndexOf(':');
            this.host = colon > 0 ? endpoint.substring(0, colon) : endpoint;
            this.port = colon > 0 ? port(endpoint.substring(colon + 1)) : 443;
            this.trust = trust;
        }

        @Override
        Fetched fetch() {
            String form = "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&DurationSeconds=3600"
                    + "&RoleArn=" + AwsSigV4.urlEncode(roleArn) + "&RoleSessionName="
                    + AwsSigV4.urlEncode(sessionName) + "&WebIdentityToken=";
            try (Arena arena = Arena.ofConfined();
                 SecretProvider file = SecretProviders.of(Map.of("provider", "file",
                         "path", tokenFile, "max-length", "16384"));
                 SecretScope token = SecretScope.fromProvider(file);
                 SecretScope body = SecretScope.in(arena, form.length() + 3 * token.length());
                 SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {
                int at = AwsSigV4.writeAscii(body.segment(), form);
                at += AwsSigV4.urlEncode(token.segment(), token.length(), body.segment(), at);
                Map<String, String> headers = new LinkedHashMap<>();
                headers.put("Content-Type", "application/x-www-form-urlencoded");
                headers.put("Accept", "application/xml");
                int bodyLength = at;
                SecretFetch.Response response = TrustChoice.using(trust, () -> {
                    try {
                        return SecretFetch.sendSecretBody(host, port, true, 10_000, "POST", "/",
                                headers, List.of(), new SecretFetch.SecretBody(body.segment(),
                                        bodyLength), answer.segment());
                    } catch (IOException e) {
                        throw new java.sql.SQLException(e.getMessage(), "08001", e);
                    }
                });
                if (response.status() != 200) {
                    throw new SecretUnavailableException("STS refused AssumeRoleWithWebIdentity "
                            + "for " + roleArn + " with " + response.status());
                }
                return xml(answer.segment(), response.bodyLength());
            } catch (java.sql.SQLException e) {
                throw new SecretUnavailableException("STS at " + host + " could not be reached",
                        e);
            }
        }

        @Override
        String name() {
            return "web-identity";
        }

        private static int port(String text) {
            try {
                return Integer.parseInt(text);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("sts-endpoint is host or host:port, and '"
                        + text + "' is not a port", e);
            }
        }
    }

    /** {@code AccessKeyId}, {@code SecretAccessKey}, the token, {@code Expiration} - JSON. */
    static TemporaryCredentials.Fetched json(MemorySegment json, int length, String tokenField) {
        SecretScope secretKey = SecretScope.allocate(ROOM);
        SecretScope token = SecretScope.allocate(ROOM);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = arena.allocate(256);
            String accessKeyId = ascii(text, JsonOff.string(json, length, text, "AccessKeyId"));
            String expiration = ascii(text, JsonOff.string(json, length, text, "Expiration"));
            secretKey.length(JsonOff.string(json, length, secretKey.segment(), "SecretAccessKey"));
            token.length(JsonOff.string(json, length, token.segment(), tokenField));
            return new TemporaryCredentials.Fetched(accessKeyId, Instant.parse(expiration),
                    secretKey, token);
        } catch (RuntimeException e) {
            secretKey.close();
            token.close();
            throw e;
        }
    }

    /** The same four from STS's XML answer. */
    static TemporaryCredentials.Fetched xml(MemorySegment xml, int length) {
        SecretScope secretKey = SecretScope.allocate(ROOM);
        SecretScope token = SecretScope.allocate(ROOM);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = arena.allocate(256);
            String accessKeyId = ascii(text, element(xml, length, "AccessKeyId", text));
            String expiration = ascii(text, element(xml, length, "Expiration", text));
            secretKey.length(element(xml, length, "SecretAccessKey", secretKey.segment()));
            token.length(element(xml, length, "SessionToken", token.segment()));
            return new TemporaryCredentials.Fetched(accessKeyId, Instant.parse(expiration),
                    secretKey, token);
        } catch (RuntimeException e) {
            secretKey.close();
            token.close();
            throw e;
        }
    }

    /** The text of {@code <name>...</name>}, copied byte by byte. */
    private static int element(MemorySegment xml, int length, String name, MemorySegment out) {
        int start = indexOf(xml, length, "<" + name + ">", 0);
        int end = start < 0 ? -1 : indexOf(xml, length, "</" + name + ">", start);
        if (start < 0 || end < 0) {
            throw new SecretUnavailableException("STS's answer has no " + name);
        }
        int from = start + name.length() + 2;
        int size = end - from;
        if (size > out.byteSize()) {
            throw new SecretUnavailableException(name + " is longer than expected");
        }
        MemorySegment.copy(xml, from, out, 0, size);
        return size;
    }

    private static int indexOf(MemorySegment data, int length, String text, int from) {
        outer:
        for (int i = from; i <= length - text.length(); i++) {
            for (int j = 0; j < text.length(); j++) {
                if (data.get(ValueLayout.JAVA_BYTE, i + j) != (byte) text.charAt(j)) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** A public value - a key id, a date. */
    private static String ascii(MemorySegment bytes, int length) {
        StringBuilder text = new StringBuilder(length); // seclume-allow: a key id or a date - public
        for (int i = 0; i < length; i++) {
            text.append((char) (bytes.get(ValueLayout.JAVA_BYTE, i) & 0xff));
        }
        return text.toString().trim();
    }
}
