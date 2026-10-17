package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import space.seclume.internal.AwsSigV4;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;
import space.seclume.internal.TrustChoice;

/**
 * The AWS credentials of the workload this runs on - instead of a key pair
 * written into a file:
 *
 * <ul>
 *   <li>{@code instance} - an EC2 instance's role, from the instance metadata
 *       service (IMDSv2);
 *   <li>{@code container} - ECS tasks and EKS Pod Identity, from the container
 *       credentials endpoint ({@code AWS_CONTAINER_CREDENTIALS_FULL_URI} or
 *       {@code AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}, and the token in
 *       {@code AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE});
 *   <li>{@code web-identity} - EKS with IAM roles for service accounts (IRSA):
 *       the pod's token from {@code AWS_WEB_IDENTITY_TOKEN_FILE} traded with
 *       STS ({@code AssumeRoleWithWebIdentity}) for the role in
 *       {@code AWS_ROLE_ARN}.
 * </ul>
 *
 * <pre>
 *   provider=rds-iam&amp;credentials=instance&amp;region=...
 *   provider=rds-iam&amp;credentials=container&amp;region=...
 *   provider=rds-iam&amp;credentials=web-identity&amp;region=...
 *   provider=aws-secrets-manager&amp;credentials=instance&amp;region=...&amp;secret-id=...
 * </pre>
 *
 * <p>That is how applications on AWS are meant to be given credentials: none
 * stored anywhere, short-lived ones handed out by the platform and renewed
 * behind the application's back. What the platform hands out is an access key
 * id (public), a secret access key and a session token. The last two are read
 * straight into native memory and never become Java objects - the session
 * token is the more dangerous of them, valid for hours and for every AWS API
 * the role may call. Every token on the way (IMDSv2, container authorization,
 * web identity JWT) travels the same way.
 *
 * <p>Kept until five minutes before they expire, then fetched again.
 */
public final class AwsInstanceRole {

    /** The metadata service's address; link-local, it answers only on this machine. */
    static final String HOST = "169.254.169.254";
    /** ECS container credentials endpoint when a relative URI is given. */
    static final String ECS_CONTAINER_HOST = "http://169.254.170.2";
    private static final long MARGIN_SECONDS = 300;
    private static final int KEY_ROOM = 256;
    private static final int TOKEN_ROOM = 8 * 1024;

    private static final AwsInstanceRole SHARED = new AwsInstanceRole(HOST, 80, 2000);

    private record Fetched(String accessKeyId, Instant expires, SecretScope secretKey,
                           SecretScope sessionToken) {
    }

    @FunctionalInterface
    private interface Source {
        Fetched fetch();
    }

    private final Source source;

    private String accessKeyId;
    private SecretScope secretKey;
    private SecretScope sessionToken;
    private Instant expires = Instant.EPOCH;

    AwsInstanceRole(String host, int port, int timeoutMillis) {
        this(() -> fetchImds(host, port, timeoutMillis));
    }

    private AwsInstanceRole(Source source) {
        this.source = source;
        // The role's keys are cached until they near their expiry; a
        // checkpoint image must not carry them.
        space.seclume.internal.Checkpoint.register(this, AwsInstanceRole::close);
    }

    /** The role of the EC2 instance this process runs on. */
    public static AwsInstanceRole shared() {
        return SHARED;
    }

    /**
     * Builds the workload credentials source named by {@code credentials} in
     * {@code settings}, or returns {@code null} when none (or {@code static})
     * is configured.
     */
    public static AwsInstanceRole of(Map<String, String> settings) {
        String kind = option(settings, "credentials");
        if (kind == null || kind.isBlank() || "static".equalsIgnoreCase(kind.trim())) {
            return null;
        }
        return switch (kind.trim().toLowerCase(Locale.ROOT)) {
            case "instance" -> SHARED;
            case "container" -> containerFrom(settings);
            case "web-identity", "webidentity" -> webIdentityFrom(settings);
            default -> throw new IllegalArgumentException(
                    "credentials is instance, container or web-identity, not '" + kind + "'");
        };
    }

    /** ECS tasks and EKS Pod Identity: a link-local endpoint, asked with the container's token. */
    public static AwsInstanceRole container(String uri, String tokenFile) {
        return container(uri, tokenFile, 5_000);
    }

    static AwsInstanceRole container(String uri, String tokenFile, int timeoutMillis) {
        if (uri == null || uri.isBlank()) {
            throw new IllegalArgumentException("container-uri is missing");
        }
        URI parsed = URI.create(uri.trim());
        if (parsed.getHost() == null || parsed.getHost().isBlank()) {
            throw new IllegalArgumentException("container-uri has no host: " + uri);
        }
        return new AwsInstanceRole(() -> fetchContainer(parsed, tokenFile, timeoutMillis));
    }

    /** EKS IRSA: the pod's web identity token traded with STS for temporary role credentials. */
    public static AwsInstanceRole webIdentity(String roleArn, String tokenFile, String sessionName,
                                              String stsEndpoint, boolean verify,
                                              TrustChoice.Choice trust) {
        if (roleArn == null || roleArn.isBlank()) {
            throw new IllegalArgumentException("role-arn is missing for web-identity");
        }
        if (tokenFile == null || tokenFile.isBlank()) {
            throw new IllegalArgumentException(
                    "web-identity-token-file is missing for web-identity");
        }
        String session = sessionName == null || sessionName.isBlank() ? "seclume" : sessionName;
        String endpoint = stsEndpoint == null || stsEndpoint.isBlank()
                ? "sts.amazonaws.com" : stsEndpoint.trim();
        int colon = endpoint.lastIndexOf(':');
        String host = colon > 0 ? endpoint.substring(0, colon) : endpoint;
        int port = colon > 0 ? parsePort(endpoint.substring(colon + 1)) : 443;
        return new AwsInstanceRole(() -> fetchWebIdentity(
                roleArn.trim(), tokenFile.trim(), session.trim(), host, port, verify, trust,
                10_000));
    }

    private static AwsInstanceRole containerFrom(Map<String, String> settings) {
        String uri = option(settings, "container-uri");
        String relative = option(settings, "container-relative-uri");
        if (uri == null && relative == null) {
            uri = env("AWS_CONTAINER_CREDENTIALS_FULL_URI");
            if (uri == null) {
                relative = env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
            }
        }
        boolean fromRelative = uri == null && relative != null;
        if (fromRelative) {
            uri = ECS_CONTAINER_HOST + (relative.startsWith("/") ? relative : "/" + relative);
        }
        if (uri == null || uri.isBlank()) {
            throw new IllegalArgumentException(
                    "container-uri is missing, and so are AWS_CONTAINER_CREDENTIALS_FULL_URI "
                    + "and AWS_CONTAINER_CREDENTIALS_RELATIVE_URI in the environment");
        }
        String tokenFile = option(settings, "container-token-file");
        if (tokenFile == null) {
            tokenFile = env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
        }
        if ((tokenFile == null || tokenFile.isBlank()) && !fromRelative) {
            throw new IllegalArgumentException(
                    "container-token-file is missing, and so is "
                    + "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE in the environment");
        }
        return container(uri, tokenFile);
    }

    private static AwsInstanceRole webIdentityFrom(Map<String, String> settings) {
        String roleArn = optionOrEnv(settings, "role-arn", "AWS_ROLE_ARN");
        String tokenFile = optionOrEnv(
                settings, "web-identity-token-file", "AWS_WEB_IDENTITY_TOKEN_FILE");
        String sessionName = option(settings, "role-session-name");
        String region = option(settings, "region");
        String stsEndpoint = option(settings, "sts-endpoint");
        if (stsEndpoint == null || stsEndpoint.isBlank()) {
            stsEndpoint = region == null || region.isBlank()
                    ? "sts.amazonaws.com" : "sts." + region.trim() + ".amazonaws.com";
        }
        String verifySetting = option(settings, "verify");
        boolean verify = !"false".equalsIgnoreCase(verifySetting == null ? "true" : verifySetting);
        return webIdentity(roleArn, tokenFile, sessionName, stsEndpoint, verify,
                TrustChoice.of(settings));
    }

    private static String optionOrEnv(Map<String, String> settings, String key, String variable) {
        String value = option(settings, key);
        if (value == null) {
            value = env(variable);
        }
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    key + " is missing, and so is " + variable + " in the environment");
        }
        return value;
    }

    private static String option(Map<String, String> settings, String key) {
        if (settings == null) {
            return null;
        }
        String direct = settings.get(key);
        if (direct != null && !direct.isBlank()) {
            return direct;
        }
        for (Map.Entry<String, String> entry : settings.entrySet()) {
            if (entry.getKey().replace("-", "").equalsIgnoreCase(key.replace("-", ""))) {
                String value = entry.getValue();
                return value == null || value.isBlank() ? null : value;
            }
        }
        return null;
    }

    private static String env(String variable) {
        // seclume-allow: a role name, a URI or a file path - the secrets are in the files
        String value = System.getenv(variable);
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static int parsePort(String text) {
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("sts-endpoint is host or host:port, and '"
                    + text + "' is not a port", e);
        }
    }

    /** What the credentials are used for, while they are valid - see {@link #use}. */
    @FunctionalInterface
    public interface Use<T> {
        T with(String accessKeyId, SecretProvider secretKey, SecretProvider sessionToken);
    }

    /**
     * Runs {@code use} with the current credentials, fetching them first if
     * they are missing or about to expire. The two providers it is given read
     * from this object's native memory and are good only during the call.
     */
    public synchronized <T> T use(Use<T> use) {
        if (secretKey == null || Instant.now().isAfter(expires.minusSeconds(MARGIN_SECONDS))) {
            refresh();
        }
        return use.with(accessKeyId, view(secretKey), view(sessionToken));
    }

    /**
     * When the credentials {@link #use} last handed out stop being valid -
     * {@link Instant#EPOCH} before the first use. A caller that copies them
     * knows from this when its copy is stale.
     */
    public synchronized Instant validUntil() {
        return expires;
    }

    private static SecretProvider view(SecretScope scope) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                if (scope.length() > target.byteSize()) {
                    throw new SecretUnavailableException("the role's credential is "
                            + scope.length() + " bytes and does not fit");
                }
                MemorySegment.copy(scope.segment(), 0, target, 0, scope.length());
                return scope.length();
            }

            @Override
            public int maxSecretLength() {
                return scope.length();
            }
        };
    }

    private void refresh() {
        Fetched fetched = source.fetch();
        close();
        accessKeyId = fetched.accessKeyId();
        secretKey = fetched.secretKey();
        sessionToken = fetched.sessionToken();
        expires = fetched.expires();
    }

    private static Fetched fetchImds(String host, int port, int timeoutMillis) {
        try (Arena arena = Arena.ofConfined();
             SecretScope imdsToken = SecretScope.in(arena, 256);
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {
            // IMDSv2: a session with the metadata service first. The token it
            // gives is sent back as a header on every question - and it too
            // stays out of the heap.
            SecretFetch.Response session = SecretFetch.sendLinkLocal(host, port, timeoutMillis,
                    "PUT", "/latest/api/token",
                    Map.of("X-aws-ec2-metadata-token-ttl-seconds", "300", "Content-Length", "0"),
                    imdsToken.segment());
            if (!session.ok()) {
                throw new SecretUnavailableException("the instance metadata service refused a "
                        + "session (" + session.status() + ") - is this an EC2 instance with "
                        + "IMDSv2 reachable from here?");
            }
            imdsToken.length(session.bodyLength());
            List<SecretFetch.SecretHeader> asked = List.of(new SecretFetch.SecretHeader(
                    "X-aws-ec2-metadata-token", imdsToken.secret(), imdsToken.length()));

            String base = "/latest/meta-data/iam/security-credentials/";
            SecretFetch.Response roles = SecretFetch.sendLinkLocal(host, port, timeoutMillis,
                    "GET", base, Map.of(), asked, answer.segment());
            if (!roles.ok() || roles.bodyLength() == 0) {
                throw new SecretUnavailableException("this instance has no role attached ("
                        + roles.status() + ") - attach one, or configure a key");
            }
            String role = ascii(answer.segment(), roles.bodyLength()).lines().findFirst()
                    .orElse("").trim();
            if (!role.matches("[A-Za-z0-9+=,.@_-]+")) {
                throw new SecretUnavailableException("the metadata service named no usable role");
            }

            answer.segment().fill((byte) 0);
            SecretFetch.Response credentials = SecretFetch.sendLinkLocal(host, port,
                    timeoutMillis, "GET", base + role, Map.of(), asked, answer.segment());
            if (!credentials.ok()) {
                throw new SecretUnavailableException("the metadata service did not hand out the "
                        + "credentials of " + role + " (" + credentials.status() + ")");
            }
            try {
                return parseJson(answer.segment(), credentials.bodyLength());
            } catch (RuntimeException e) {
                throw new SecretUnavailableException("the metadata service's answer for " + role
                        + " was not what was expected: " + e.getMessage(), e);
            }
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot reach the instance metadata service at "
                    + host + ": " + e.getMessage(), e);
        }
    }

    private static Fetched fetchContainer(URI uri, String tokenFile, int timeoutMillis) {
        String rawPath = uri.getRawPath();
        String path = (rawPath == null || rawPath.isEmpty() ? "/" : rawPath)
                + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
        int port = uri.getPort() < 0 ? 80 : uri.getPort();
        try (Arena arena = Arena.ofConfined();
             SecretScope auth = tokenFile == null || tokenFile.isBlank()
                     ? null
                     : SecretScope.fromProvider(new FileSecretProvider(Path.of(tokenFile),
                             TOKEN_ROOM));
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {
            List<SecretFetch.SecretHeader> headers = auth == null ? List.of()
                    : List.of(new SecretFetch.SecretHeader(
                            "Authorization", auth.secret(), auth.length()));
            SecretFetch.Response response = SecretFetch.sendLinkLocal(
                    uri.getHost(), port, timeoutMillis, "GET", path, Map.of(), headers,
                    answer.segment());
            if (!response.ok()) {
                throw new SecretUnavailableException("the container credentials endpoint "
                        + "answered " + response.status());
            }
            try {
                return parseJson(answer.segment(), response.bodyLength());
            } catch (RuntimeException e) {
                throw new SecretUnavailableException("the container credentials endpoint's answer "
                        + "was not what was expected: " + e.getMessage(), e);
            }
        } catch (IOException e) {
            throw new SecretUnavailableException("the container credentials endpoint "
                    + uri + " could not be reached: " + e.getMessage(), e);
        }
    }

    private static Fetched fetchWebIdentity(String roleArn, String tokenFile, String sessionName,
                                            String host, int port, boolean verify,
                                            TrustChoice.Choice trust, int timeoutMillis) {
        String form = "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&DurationSeconds=3600"
                + "&RoleArn=" + AwsSigV4.urlEncode(roleArn)
                + "&RoleSessionName=" + AwsSigV4.urlEncode(sessionName)
                + "&WebIdentityToken=";
        try (Arena arena = Arena.ofConfined();
             SecretScope jwt = SecretScope.fromProvider(
                     new FileSecretProvider(Path.of(tokenFile), 16_384));
             SecretScope body = SecretScope.in(arena, form.length() + 3 * jwt.length());
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {
            int at = AwsSigV4.writeAscii(body.segment(), form);
            at += AwsSigV4.urlEncode(jwt.secret(), jwt.length(), body.segment(), at);
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            headers.put("Accept", "application/xml");
            int bodyLength = at;
            SecretFetch.Response response = TrustChoice.using(trust, () -> {
                try {
                    return SecretFetch.sendSecretBody(host, port, verify, timeoutMillis,
                            "POST", "/", headers, List.of(),
                            new SecretFetch.SecretBody(body.segment(), bodyLength),
                            answer.segment());
                } catch (IOException e) {
                    throw new java.sql.SQLException(e.getMessage(), "08001", e);
                }
            });
            if (!response.ok()) {
                throw new SecretUnavailableException("STS refused AssumeRoleWithWebIdentity "
                        + "for " + roleArn + " with " + response.status());
            }
            return parseXml(answer.segment(), response.bodyLength());
        } catch (java.sql.SQLException e) {
            throw new SecretUnavailableException("STS at " + host + " could not be reached: "
                    + e.getMessage(), e);
        }
    }

    private static Fetched parseJson(MemorySegment json, int length) {
        SecretScope key = SecretScope.allocateShared(KEY_ROOM);
        SecretScope session;
        try {
            session = SecretScope.allocateShared(TOKEN_ROOM);
        } catch (Throwable e) {
            key.close();
            throw e;
        }
        try {
            key.length(JsonOff.string(json, length, key.segment(), "SecretAccessKey"));
            session.length(JsonOff.string(json, length, session.segment(), "Token"));
            String id = text(json, length, "AccessKeyId");
            Instant until = Instant.parse(text(json, length, "Expiration"));
            return new Fetched(id, until, key, session);
        } catch (Throwable e) {
            key.close();
            session.close();
            throw e;
        }
    }

    private static Fetched parseXml(MemorySegment xml, int length) {
        SecretScope key = SecretScope.allocateShared(KEY_ROOM);
        SecretScope session;
        try {
            session = SecretScope.allocateShared(TOKEN_ROOM);
        } catch (Throwable e) {
            key.close();
            throw e;
        }
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment out = scratch.allocate(256);
            String id = ascii(out, xmlElement(xml, length, "AccessKeyId", out)).trim();
            String exp = ascii(out, xmlElement(xml, length, "Expiration", out)).trim();
            key.length(xmlElement(xml, length, "SecretAccessKey", key.segment()));
            session.length(xmlElement(xml, length, "SessionToken", session.segment()));
            return new Fetched(id, Instant.parse(exp), key, session);
        } catch (Throwable e) {
            key.close();
            session.close();
            throw e;
        }
    }

    private static int xmlElement(MemorySegment xml, int length, String elementName,
                                  MemorySegment out) {
        int start = indexOf(xml, length, "<" + elementName + ">", 0);
        int end = start < 0 ? -1 : indexOf(xml, length, "</" + elementName + ">", start);
        if (start < 0 || end < 0) {
            throw new SecretUnavailableException("STS's answer has no " + elementName);
        }
        int from = start + elementName.length() + 2;
        int size = end - from;
        if (size > out.byteSize()) {
            throw new SecretUnavailableException(elementName + " is longer than expected");
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

    /** A public field of the answer - the key id, the expiry. */
    private static String text(MemorySegment json, int length, String field) {
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment out = scratch.allocate(256);
            return ascii(out, JsonOff.string(json, length, out, field));
        }
    }

    private static String ascii(MemorySegment bytes, int length) {
        StringBuilder text = new StringBuilder(length); // seclume-allow: a role name, a key id or a date - public
        for (int i = 0; i < length; i++) {
            text.append((char) (bytes.get(ValueLayout.JAVA_BYTE, i) & 0x7f));
        }
        return text.toString();
    }

    /** Wipes what is kept. */
    synchronized void close() {
        if (secretKey != null) {
            secretKey.close();
            sessionToken.close();
            secretKey = null;
            sessionToken = null;
        }
    }
}
