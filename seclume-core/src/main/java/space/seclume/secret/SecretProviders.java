package space.seclume.secret;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Builds a {@link SecretProvider} from configuration.
 *
 * <p>The same place serves both ways into the library: the JDBC URL parameters
 * of the driver and the {@code application.properties} of the Spring starter.
 * That way a source is called the same everywhere, and there is exactly one
 * place where a name turns into a provider.
 *
 * <p>Recognised keys:
 *
 * <ul>
 *   <li>{@code provider} - {@code file}, {@code env-file}, {@code unix-socket},
 *       {@code process}, {@code dpapi}, {@code credential-manager}</li>
 *   <li>{@code path} - the file or socket</li>
 *   <li>{@code key} - the entry name for {@code env-file}</li>
 *   <li>{@code target} - the target name in the Credential Manager</li>
 *   <li>{@code entropy} - the second factor for DPAPI</li>
 *   <li>{@code command} - the command for {@code process}, space separated</li>
 *   <li>{@code max-length} - upper bound in bytes, 256 by default</li>
 * </ul>
 *
 * <p>A key named {@code password} or {@code secret} leads to an abort with an
 * explanation. That is not pedantry but the very point: a password in the
 * configuration is a {@code String} in the {@code Environment} and therefore in
 * the heap for the lifetime of the application.
 */
public final class SecretProviders {

    /** Default upper bound; no database password is longer than this. */
    public static final int DEFAULT_MAX_LENGTH = 256;

    private SecretProviders() {
    }

    /**
     * A provider from one line - {@code file:/run/secrets/db},
     * {@code env-file:/run/secrets/app.env?key=DB_PASSWORD},
     * {@code vault?address=https://vault:8200&path=secret/data/app&token-provider=file&token-path=...}.
     * The same spelling the JDBC URL and the Spring starter's {@code secret-uri} take.
     */
    public static SecretProvider fromUri(String uri) {
        return of(settingsOf(uri));
    }

    /**
     * The settings a one-line secret URI stands for: the provider before the
     * colon, its path after it (for {@code encrypted} the ciphertext file), the
     * rest as query options.
     */
    public static Map<String, String> settingsOf(String uri) {
        String text = uri.trim();
        int question = text.indexOf('?');
        String head = question < 0 ? text : text.substring(0, question);
        String query = question < 0 ? "" : text.substring(question + 1);
        int colon = head.indexOf(':');
        String provider = (colon < 0 ? head : head.substring(0, colon)).trim();
        String path = colon < 0 ? "" : head.substring(colon + 1).trim();
        if (provider.isEmpty()) {
            throw new IllegalArgumentException("a secret URI starts with its provider, as in "
                    + "file:/run/secrets/db - this one does not: " + uri);
        }
        Map<String, String> settings = new java.util.LinkedHashMap<>();
        settings.put("provider", provider);
        if (!path.isEmpty()) {
            // For "encrypted" the leading path is the ciphertext, almost always a file.
            if ("encrypted".equalsIgnoreCase(provider)) {
                settings.put("cipher-provider", "file");
                settings.put("cipher-path", path);
            } else {
                settings.put("path", path);
            }
        }
        for (String pair : query.split("&")) {
            if (pair.isBlank()) {
                continue;
            }
            int equals = pair.indexOf('=');
            if (equals < 0) {
                throw new IllegalArgumentException("a secret URI setting without a value: '"
                        + pair + "'");
            }
            settings.put(pair.substring(0, equals).trim(), pair.substring(equals + 1).trim());
        }
        return settings;
    }

    public static SecretProvider of(Map<String, String> settings) {
        rejectInlineSecrets(settings);
        String kind = value(settings, "provider");
        if (kind == null) {
            throw new IllegalArgumentException(
                    "no secret provider configured - set 'provider' to one of "
                    + "file, env-file, unix-socket, process, dpapi, credential-manager, "
                    + "rds-iam, encrypted, vault, aws-secrets-manager, azure-key-vault, "
                    + "gcp-secret-manager, azure-managed-identity, gcp-metadata, or none for a "
                    + "login by client certificate alone");
        }
        int maxLength = maxLength(settings);
        return switch (kind.toLowerCase(Locale.ROOT)) {
            case "file" -> new FileSecretProvider(path(settings, "file"), maxLength);
            case "env-file", "envfile" -> new EnvFileSecretProvider(path(settings, "env-file"),
                    required(settings, "key", "env-file"), maxLength);
            case "unix-socket", "unixsocket" -> new UnixSocketSecretProvider(
                    path(settings, "unix-socket"), value(settings, "request"), maxLength);
            case "process" -> new ProcessSecretProvider(
                    List.of(required(settings, "command", "process").split("\\s+")), maxLength);
            case "dpapi" -> new DpapiSecretProvider(path(settings, "dpapi"),
                    value(settings, "entropy"), maxLength);
            case "credential-manager", "credentialmanager" -> new CredentialManagerSecretProvider(
                    required(settings, "target", "credential-manager"), maxLength);
            // The password is built, not stored: an AWS RDS IAM token, signed
            // here so that the short-lived credential never becomes a String.
            // The AWS key itself comes from one of the sources above, named in
            // "key-provider".
            // credentials=instance: the EC2 instance role's temporary
            // credentials instead of a key pair - see AwsInstanceRole.
            case "rds-iam", "rdsiam" -> "instance".equalsIgnoreCase(value(settings, "credentials"))
                    ? new RdsIamSecretProvider(AwsInstanceRole.shared(),
                            required(settings, "region", "rds-iam"),
                            required(settings, "host", "rds-iam"),
                            Integer.parseInt(required(settings, "port", "rds-iam")),
                            required(settings, "db-user", "rds-iam"))
                    : new RdsIamSecretProvider(
                    of(nested(settings, "key-")),
                    required(settings, "access-key-id", "rds-iam"),
                    required(settings, "region", "rds-iam"),
                    required(settings, "host", "rds-iam"),
                    Integer.parseInt(required(settings, "port", "rds-iam")),
                    required(settings, "db-user", "rds-iam"));
            // Stored encrypted, decrypted straight into the target segment. Two
            // inner sources rather than one, and they should not be the same
            // place: "cipher-" says where the ciphertext is, "key-" where the
            // key is. Both are Base64.
            case "encrypted" -> new EncryptedSecretProvider(
                    of(nested(settings, "cipher-")),
                    of(nested(settings, "key-")),
                    value(settings, "aad"));
            // HashiCorp Vault over HTTPS, with the answer parsed in native
            // memory. "token-" says where the Vault token comes from - it is
            // a secret too and gets a provider of its own, not a property.
            case "vault" -> new VaultSecretProvider(
                    required(settings, "address", "vault"),
                    required(settings, "path", "vault"),
                    settings.getOrDefault("field", "password"),
                    of(nested(settings, "token-")),
                    value(settings, "namespace"),
                    !"false".equalsIgnoreCase(settings.getOrDefault("verify", "true")),
                    Integer.parseInt(settings.getOrDefault("timeout-millis", "10000")),
                    maxLength);
            // The three cloud vaults. All of them build on the same two
            // pieces - SecretFetch for the HTTPS, JsonOff for the answer - so
            // that no SDK ever hands out a String. "token-" says where the
            // bearer token comes from; for AWS it is "key-", because a
            // signature is made rather than a token presented.
            case "aws-secrets-manager", "awssecretsmanager" ->
                    "instance".equalsIgnoreCase(value(settings, "credentials"))
                    ? new AwsSecretsManagerSecretProvider(AwsInstanceRole.shared(),
                            required(settings, "region", "aws-secrets-manager"),
                            required(settings, "secret-id", "aws-secrets-manager"),
                            value(settings, "field"), maxLength)
                    : new AwsSecretsManagerSecretProvider(
                            of(nested(settings, "key-")),
                            // Optional, and only for temporary credentials.
                            // It is signed as well as sent, which is why it
                            // is a provider rather than a setting: a value
                            // written here would be a String in the
                            // configuration, which is the one thing this
                            // library refuses everywhere else.
                            nested(settings, "session-token-").isEmpty() ? null
                                    : of(nested(settings, "session-token-")),
                            required(settings, "access-key-id", "aws-secrets-manager"),
                            required(settings, "region", "aws-secrets-manager"),
                            required(settings, "secret-id", "aws-secrets-manager"),
                            value(settings, "field"),
                            maxLength);
            case "azure-key-vault", "azurekeyvault" -> new AzureKeyVaultSecretProvider(
                    required(settings, "vault-uri", "azure-key-vault"),
                    required(settings, "name", "azure-key-vault"),
                    value(settings, "version"),
                    of(nested(settings, "token-")),
                    maxLength);
            case "gcp-secret-manager", "gcpsecretmanager" -> new GcpSecretManagerSecretProvider(
                    required(settings, "project", "gcp-secret-manager"),
                    required(settings, "name", "gcp-secret-manager"),
                    value(settings, "version"),
                    of(nested(settings, "token-")),
                    maxLength);
            // Workload identity: no stored credential at all. Tokens are a
            // couple of kilobytes, far past a password's default bound.
            case "azure-managed-identity", "azuremanagedidentity" ->
                    new AzureManagedIdentitySecretProvider(
                            required(settings, "resource", "azure-managed-identity"),
                            value(settings, "client-id"),
                            tokenLength(settings));
            case "gcp-metadata", "gcpmetadata" -> new GcpMetadataSecretProvider(
                    value(settings, "account"),
                    value(settings, "scopes"),
                    tokenLength(settings));
            // No password: the client certificate is the login - see
            // NoSecretProvider for why this is a word and not an absence.
            case "none" -> NoSecretProvider.INSTANCE;
            default -> throw new IllegalArgumentException(
                    "unknown secret provider '" + kind + "' - known are file, env-file, "
                    + "unix-socket, process, dpapi, credential-manager, rds-iam, encrypted, "
                    + "vault, aws-secrets-manager, azure-key-vault, gcp-secret-manager, "
                    + "azure-managed-identity, gcp-metadata, none");
        };
    }

    /**
     * The settings of the inner provider, by prefix.
     *
     * <p>{@code key-provider=file} and {@code key-path=...} configure where the
     * AWS secret key comes from, without a second configuration block and
     * without the two sets of settings getting in each other's way.
     */
    private static Map<String, String> nested(Map<String, String> settings, String prefix) {
        Map<String, String> inner = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, String> entry : settings.entrySet()) {
            if (entry.getKey().startsWith(prefix)) {
                inner.put(entry.getKey().substring(prefix.length()), entry.getValue());
            }
        }
        return inner;
    }

    /**
     * The reason a password in the configuration does not work - as a message
     * you read once and then understand.
     */
    private static void rejectInlineSecrets(Map<String, String> settings) {
        for (String forbidden : List.of("password", "secret", "value")) {
            if (settings.containsKey(forbidden)) {
                throw new IllegalArgumentException(
                        "'" + forbidden + "' is not a seclume setting. A password in the "
                        + "configuration is a String in the environment and stays in the heap "
                        + "for the lifetime of the application - which is exactly what this "
                        + "library exists to prevent. Configure where the secret comes from "
                        + "instead: provider=file and path=/run/secrets/db-password.");
            }
        }
    }

    /**
     * The bound for an access token, unless the configuration names one.
     *
     * <p>A Microsoft Entra token is around two kilobytes and a Google one
     * smaller; the password default of 256 would refuse either on the first
     * connection.
     */
    private static int tokenLength(Map<String, String> settings) {
        return value(settings, "max-length") == null && value(settings, "maxLength") == null
                ? 8192 : maxLength(settings);
    }

    private static int maxLength(Map<String, String> settings) {
        String value = value(settings, "max-length");
        if (value == null) {
            value = value(settings, "maxLength");
        }
        if (value == null) {
            return DEFAULT_MAX_LENGTH;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed <= 0) {
                throw new NumberFormatException(value);
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("max-length must be a positive number: " + value);
        }
    }

    private static Path path(Map<String, String> settings, String kind) {
        return Path.of(required(settings, "path", kind));
    }

    private static String required(Map<String, String> settings, String key, String kind) {
        String value = value(settings, key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    "the secret provider '" + kind + "' needs '" + key + "'");
        }
        return value;
    }

    private static String value(Map<String, String> settings, String key) {
        String direct = settings.get(key);
        if (direct != null) {
            return direct;
        }
        // Lower case with hyphens is the spelling in application.properties;
        // camelCase the one in a JDBC URL.
        for (Map.Entry<String, String> entry : settings.entrySet()) {
            if (entry.getKey().replace("-", "").equalsIgnoreCase(key.replace("-", ""))) {
                return entry.getValue();
            }
        }
        return null;
    }
}
