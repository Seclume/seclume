package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import space.seclume.internal.AwsSigV4;
import space.seclume.internal.Base64Off;
import space.seclume.internal.CanonicalRequest;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * The body of a Vault login request, written into native memory.
 *
 * <p>Every login method sends a credential: a JWT, a secret id, or - for
 * AWS - a signed {@code sts:GetCallerIdentity} request that Vault replays to
 * AWS. All of it is a secret while it is valid, so all of it is assembled in a
 * {@link SecretScope}, and only the public parts around it - field names, a
 * role, an account id - are text.
 */
interface VaultLoginBody extends AutoCloseable {

    /** The JSON for {@code auth/<mount>/login}, in a scope of {@code arena}. */
    SecretScope write(Arena arena);

    /** What the credential is called in messages - "JWT", "secret id". */
    String what();

    /** What a refused login usually means for this method. */
    String hint(String role);

    /** Closes the credential's sources. */
    @Override
    void close();

    // ---------------------------------------------------------------- JSON --

    /** Appends to a scope; public text escaped as JSON, secrets checked and escaped. */
    final class Json {
        private final MemorySegment out;
        private int at;

        Json(MemorySegment out) {
            this.out = out;
        }

        /** Raw ASCII - punctuation and field names. */
        Json raw(String text) {
            for (int i = 0; i < text.length(); i++) {
                out.set(ValueLayout.JAVA_BYTE, at++, (byte) text.charAt(i));
            }
            return this;
        }

        /** Refuses what is not printable ASCII - a role, a header value, a name. */
        static String printable(String value) {
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (c < 0x20 || c > 0x7e) {
                    throw new IllegalArgumentException("a value for a Vault login is printable "
                            + "ASCII; this one has a character outside it at " + i);
                }
            }
            return value;
        }

        /** A public value as a JSON string: printable ASCII, quotes and backslashes escaped. */
        Json string(String value) {
            printable(value);
            raw("\"");
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (c == '"' || c == '\\') {
                    out.set(ValueLayout.JAVA_BYTE, at++, (byte) '\\');
                }
                out.set(ValueLayout.JAVA_BYTE, at++, (byte) c);
            }
            return raw("\"");
        }

        /**
         * A secret as a JSON string. A quote or backslash is escaped; a control
         * character is refused - no token, key or JWT has one, and a file that
         * does holds something else.
         */
        Json secret(MemorySegment value, int length, String what) {
            raw("\"");
            secretBytes(value, length, what);
            return raw("\"");
        }

        /** The same without the quotes, for a value that goes on after it. */
        Json secretBytes(MemorySegment value, int length, String what) {
            for (int i = 0; i < length; i++) {
                byte b = value.get(ValueLayout.JAVA_BYTE, i);
                if ((b & 0xff) < 0x20 || b == 0x7f) {
                    throw new SecretUnavailableException("the " + what + " for the Vault login "
                            + "has a control character at byte " + i);
                }
                if (b == '"' || b == '\\') {
                    out.set(ValueLayout.JAVA_BYTE, at++, (byte) '\\');
                }
                out.set(ValueLayout.JAVA_BYTE, at++, b);
            }
            return this;
        }

        /** Base64 of {@code length} bytes, as a JSON string. */
        Json base64(MemorySegment value, int length) {
            raw("\"");
            at += Base64Off.encode(value, 0, length, out, at);
            return raw("\"");
        }

        int length() {
            return at;
        }
    }

    /** Room for a JSON string of {@code length} secret bytes, escapes included. */
    static int escapedRoom(int length) {
        return 2 * length + 2;
    }

    // ---------------------------------------------------- JWT and the like --

    /**
     * {@code {"<roleField>":"<role>","<secretField>":"<secret>", extras}} -
     * Kubernetes, JWT, AppRole, GCP and Azure all have this shape.
     */
    final class Simple implements VaultLoginBody {
        private final String roleField;
        private final String role;
        private final String secretField;
        private final SecretProvider secret;
        private final Supplier<Map<String, String>> extras;
        private final String what;
        private final String hint;

        Simple(String roleField, String role, String secretField, SecretProvider secret,
                Supplier<Map<String, String>> extras, String what, String hint) {
            this.roleField = roleField;
            this.role = role;
            this.secretField = secretField;
            this.secret = secret;
            this.extras = extras;
            this.what = what;
            this.hint = hint;
        }

        @Override
        public SecretScope write(Arena arena) {
            Map<String, String> extra = extras == null ? Map.of() : extras.get();
            try (SecretScope value = SecretScope.fromProvider(secret)) {
                if (value.length() == 0) {
                    throw new SecretUnavailableException("the " + what + " for the Vault login "
                            + "is empty");
                }
                int room = 64 + (role == null ? 0 : 2 * role.length() + roleField.length())
                        + secretField.length() + escapedRoom(value.length());
                for (Map.Entry<String, String> entry : extra.entrySet()) {
                    room += 8 + entry.getKey().length() + 2 * entry.getValue().length();
                }
                SecretScope body = SecretScope.in(arena, room);
                try {
                    Json json = new Json(body.segment()).raw("{");
                    if (role != null) {
                        json.string(roleField).raw(":").string(role).raw(",");
                    }
                    json.string(secretField).raw(":").secret(value.segment(), value.length(), what);
                    for (Map.Entry<String, String> entry : extra.entrySet()) {
                        json.raw(",").string(entry.getKey()).raw(":").string(entry.getValue());
                    }
                    body.length(json.raw("}").length());
                    return body;
                } catch (Throwable e) {
                    body.close();
                    throw e;
                }
            }
        }

        @Override
        public String what() {
            return what;
        }

        @Override
        public String hint(String role) {
            return hint;
        }

        @Override
        public void close() {
            secret.close();
        }
    }

    // ------------------------------------------------------------- AWS IAM --

    /**
     * Vault's {@code aws} method, {@code iam} type: a signed
     * {@code sts:GetCallerIdentity} request that Vault sends to AWS on the
     * caller's behalf, learning from the answer who the caller is.
     *
     * <p>The request is signed here with SigV4 - the secret access key never
     * leaves native memory - and handed to Vault as base64 of its URL, body
     * and headers. The headers carry the {@code Authorization} signature and,
     * with temporary credentials, the session token: together they are a
     * login anyone could replay for fifteen minutes, so the header document,
     * the signature in it and its base64 are all native memory.
     *
     * <p>{@code X-Vault-AWS-IAM-Server-ID}, when configured, is signed into the
     * request: a Vault configured with the same value refuses a request meant
     * for another Vault.
     */
    final class AwsIam implements VaultLoginBody {
        static final String STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15";
        static final String CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8";
        private static final DateTimeFormatter STAMP =
                DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
        private static final DateTimeFormatter DAY =
                DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

        /** The credentials to sign with: a workload's role, or a key pair from providers. */
        interface Credentials {
            <T> T use(AwsInstanceRole.Use<T> use);

            default void close() {
            }

            static Credentials of(AwsInstanceRole role) {
                return role::use;
            }

            static Credentials of(String accessKeyId, SecretProvider secretKey,
                    SecretProvider sessionToken) {
                return new Credentials() {
                    @Override
                    public <T> T use(AwsInstanceRole.Use<T> use) {
                        return use.with(accessKeyId, secretKey, sessionToken);
                    }

                    @Override
                    public void close() {
                        secretKey.close();
                        if (sessionToken != null) {
                            sessionToken.close();
                        }
                    }
                };
            }
        }

        private final String role;
        private final Credentials credentials;
        private final String stsHost;
        private final String stsRegion;
        private final String serverId;
        private final Clock clock;

        AwsIam(String role, Credentials credentials, String stsHost, String stsRegion,
                String serverId, Clock clock) {
            this.role = role;
            this.credentials = credentials;
            this.stsHost = stsHost;
            this.stsRegion = stsRegion;
            this.serverId = serverId == null || serverId.isBlank() ? null : serverId;
            this.clock = clock;
            if (this.serverId != null) {
                Json.printable(this.serverId);          // refused now, not at the first login
            }
            if (role != null) {
                Json.printable(role);
            }
        }

        @Override
        public SecretScope write(Arena arena) {
            return credentials.use((keyId, key, session) -> sign(arena, keyId, key, session));
        }

        private SecretScope sign(Arena arena, String keyId, SecretProvider key,
                SecretProvider session) {
            Instant now = clock.instant();
            String stamp = STAMP.format(now);
            String day = DAY.format(now);
            String scope = AwsSigV4.scope(day, stsRegion, "sts");
            try (SecretScope token = session == null ? null : SecretScope.fromProvider(session)) {
                List<String> signed = new ArrayList<>(List.of("content-type", "host",
                        "x-amz-date"));
                if (token != null) {
                    signed.add("x-amz-security-token");
                }
                if (serverId != null) {
                    signed.add("x-vault-aws-iam-server-id");
                }
                String signedHeaders = String.join(";", signed);

                String canonicalHash;
                try (CanonicalRequest canonical = new CanonicalRequest(arena,
                        1024 + stsHost.length() + (serverId == null ? 0 : serverId.length())
                                + (token == null ? 0 : token.length()))) {
                    canonical.text("POST\n/\n\n")
                            .text("content-type:" + CONTENT_TYPE + "\n")
                            .text("host:" + stsHost + "\n")
                            .text("x-amz-date:" + stamp + "\n");
                    if (token != null) {
                        canonical.text("x-amz-security-token:");
                        canonical.secret(token.secret(), token.length());
                        canonical.text("\n");
                    }
                    if (serverId != null) {
                        canonical.text("x-vault-aws-iam-server-id:" + serverId + "\n");
                    }
                    canonical.text("\n").text(signedHeaders + "\n")
                            .text(AwsSigV4.sha256Hex(STS_BODY));
                    canonicalHash = canonical.sha256Hex();
                }
                String toSign = AwsSigV4.ALGORITHM + "\n" + stamp + "\n" + scope + "\n"
                        + canonicalHash;
                MemorySegment signature;
                try {
                    signature = AwsSigV4.sign(arena, key::writeSecret, toSign, day, stsRegion,
                            "sts");
                } catch (IllegalStateException empty) {
                    throw new SecretUnavailableException("the AWS secret key source gave "
                            + "nothing - the login to Vault cannot be signed without it", empty);
                }

                // The headers, as Vault wants them: a JSON object, base64'd.
                String authorizationStart = AwsSigV4.ALGORITHM + " Credential=" + keyId + "/"
                        + scope + ", SignedHeaders=" + signedHeaders + ", Signature=";
                int headerRoom = 512 + authorizationStart.length() + 2 * (int) signature.byteSize()
                        + stsHost.length() + (serverId == null ? 0 : 2 * serverId.length())
                        + (token == null ? 0 : escapedRoom(token.length()));
                try (SecretScope headers = SecretScope.in(arena, headerRoom);
                     SecretScope hex = SecretScope.in(arena, 2 * (int) signature.byteSize())) {
                    hex(signature, hex.segment());
                    hex.length(2 * (int) signature.byteSize());
                    signature.fill((byte) 0);
                    Json json = new Json(headers.segment()).raw("{")
                            .string("Authorization").raw(":\"")
                            .secretBytes(ascii(arena, authorizationStart),
                                    authorizationStart.length(), "signature")
                            .secretBytes(hex.segment(), hex.length(), "signature").raw("\",")
                            .string("Content-Type").raw(":").string(CONTENT_TYPE).raw(",")
                            .string("Host").raw(":").string(stsHost).raw(",")
                            .string("X-Amz-Date").raw(":").string(stamp);
                    if (token != null) {
                        json.raw(",").string("X-Amz-Security-Token").raw(":")
                                .secret(token.secret(), token.length(), "session token");
                    }
                    if (serverId != null) {
                        json.raw(",").string("X-Vault-AWS-IAM-Server-ID").raw(":")
                                .string(serverId);
                    }
                    headers.length(json.raw("}").length());

                    String url = "https://" + stsHost + "/";
                    int room = 256 + (role == null ? 0 : 2 * role.length())
                            + Base64Off.encodedLength(url.length())
                            + Base64Off.encodedLength(STS_BODY.length())
                            + Base64Off.encodedLength(headers.length());
                    SecretScope body = SecretScope.in(arena, room);
                    try {
                        Json out = new Json(body.segment()).raw("{");
                        if (role != null) {
                            out.string("role").raw(":").string(role).raw(",");
                        }
                        out.string("iam_http_request_method").raw(":").string("POST").raw(",")
                                .string("iam_request_url").raw(":")
                                .base64(ascii(arena, url), url.length()).raw(",")
                                .string("iam_request_body").raw(":")
                                .base64(ascii(arena, STS_BODY), STS_BODY.length()).raw(",")
                                .string("iam_request_headers").raw(":")
                                .base64(headers.segment(), headers.length()).raw("}");
                        body.length(out.length());
                        return body;
                    } catch (Throwable e) {
                        body.close();
                        throw e;
                    }
                }
            }
        }

        private static MemorySegment ascii(Arena arena, String text) {
            MemorySegment out = arena.allocate(Math.max(1, text.length()));
            for (int i = 0; i < text.length(); i++) {
                out.set(ValueLayout.JAVA_BYTE, i, (byte) text.charAt(i));
            }
            return out;
        }

        private static void hex(MemorySegment bytes, MemorySegment out) {
            String digits = "0123456789abcdef";
            for (long i = 0; i < bytes.byteSize(); i++) {
                int b = bytes.get(ValueLayout.JAVA_BYTE, i) & 0xff;
                out.set(ValueLayout.JAVA_BYTE, 2 * i, (byte) digits.charAt(b >> 4));
                out.set(ValueLayout.JAVA_BYTE, 2 * i + 1, (byte) digits.charAt(b & 0xf));
            }
        }

        @Override
        public String what() {
            return "signed AWS request";
        }

        @Override
        public String hint(String role) {
            return "400 or 403 usually means no Vault role " + (role == null
                    ? "is named after this IAM principal" : "'" + role + "' is bound to it")
                    + ", the Vault and this login disagree on the STS endpoint or region, or "
                    + "the server id header (aws-iam-server-id) does not match Vault's "
                    + "iam_server_id_header_value";
        }

        @Override
        public void close() {
            credentials.close();
        }
    }

    // --------------------------------------------------------------- Azure --

    /**
     * What Vault's {@code azure} login asks for besides the token: where the
     * machine lives. Configured, or read from the instance metadata service -
     * none of it is a secret.
     */
    record AzureVm(String subscriptionId, String resourceGroupName, String vmName,
            String vmScaleSetName) {

        static final String COMPUTE_PATH = "/metadata/instance/compute?api-version=2021-02-01";

        Map<String, String> fields() {
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("subscription_id", subscriptionId);
            fields.put("resource_group_name", resourceGroupName);
            if (vmScaleSetName != null && !vmScaleSetName.isBlank()) {
                fields.put("vmss_name", vmScaleSetName);
            } else {
                fields.put("vm_name", vmName);
            }
            return fields;
        }

        /** From IMDS on this machine; link-local, no secret asked or answered. */
        static AzureVm fromMetadata(String host, int port, int timeoutMillis) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment answer = arena.allocate(SecretFetch.MAX_RESPONSE);
                SecretFetch.Response response;
                try {
                    response = SecretFetch.sendLinkLocal(host, port, timeoutMillis, "GET",
                            COMPUTE_PATH, Map.of("Metadata", "true"), answer);
                } catch (IOException e) {
                    throw new SecretUnavailableException("the Azure instance metadata service "
                            + "could not be reached at " + host + ":" + port + " for the "
                            + "machine's subscription, resource group and name - set "
                            + "azure-subscription-id, azure-resource-group and azure-vm-name "
                            + "outside Azure VMs: " + e.getMessage(), e);
                }
                if (!response.ok()) {
                    throw new SecretUnavailableException("the Azure instance metadata service "
                            + "answered " + response.status() + " for the compute metadata");
                }
                int length = response.bodyLength();
                return new AzureVm(text(answer, length, "subscriptionId"),
                        text(answer, length, "resourceGroupName"), text(answer, length, "name"),
                        optional(answer, length, "vmScaleSetName"));
            }
        }

        private static String text(MemorySegment json, int length, String field) {
            String value = optional(json, length, field);
            if (value == null) {
                throw new SecretUnavailableException("the Azure compute metadata has no "
                        + field);
            }
            return value;
        }

        private static String optional(MemorySegment json, int length, String field) {
            if (!JsonOff.has(json, length, field)) {
                return null;
            }
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment out = arena.allocate(1024);
                int n = JsonOff.string(json, length, out, field);
                StringBuilder text = new StringBuilder(n); // seclume-allow: a subscription id, a resource group or a VM name - public
                for (int i = 0; i < n; i++) {
                    text.append((char) (out.get(ValueLayout.JAVA_BYTE, i) & 0xff));
                }
                return text.isEmpty() ? null : text.toString();
            } catch (JsonOff.NotFound notText) {
                return null;
            }
        }
    }
}
