package space.seclume.helidon;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import space.seclume.field.FieldKeys;
import space.seclume.pool.PoolConfiguration;
import space.seclume.pool.SeclumePool;
import space.seclume.secret.SecretProviders;

/**
 * What seclume reads from a configuration, whoever holds it - Helidon SE's
 * {@code Config} or MicroProfile Config - as flat keys:
 *
 * <pre>
 *   seclume.datasources.&lt;name&gt;.url            jdbc:seclume:postgresql://...?provider=file&amp;path=...
 *   seclume.datasources.&lt;name&gt;.pool.&lt;setting&gt;  see PoolConfiguration
 *   seclume.field-encryption.keys.&lt;n&gt;.&lt;provider setting&gt;   or .uri
 *   seclume.field-encryption.primary          the number new values are encrypted under
 * </pre>
 */
public final class SeclumeSettings {

    static final String DATASOURCES = "seclume.datasources.";
    static final String KEYS = "seclume.field-encryption.keys.";
    static final String PRIMARY = "seclume.field-encryption.primary";

    /** Helidon's own data sources: {@code javax.sql.DataSource.<name>.dataSource.password} and the like. */
    private static final Pattern HELIDON_PASSWORD = Pattern.compile(
            "javax\\.sql\\.datasource\\.([^.]+)\\.(?:datasource\\.)?password");
    private static final Pattern OWN_PASSWORD = Pattern.compile("seclume\\.datasources\\.([^.]+)\\.password");
    /** The same as environment variables; a data source's name may hold {@code _} itself. */
    private static final Pattern HELIDON_PASSWORD_VARIABLE = Pattern.compile("javax_sql_datasource_.+_password");
    private static final Pattern OWN_PASSWORD_VARIABLE = Pattern.compile("seclume_datasources_.+_password");

    private final Map<String, String> all;

    private SeclumeSettings(Map<String, String> all) {
        this.all = Map.copyOf(all);
    }

    /** From flat keys and their values. */
    public static SeclumeSettings of(Map<String, String> all) {
        return new SeclumeSettings(all);
    }

    /** The data sources, by name, with their {@code pool.*} settings. */
    public Map<String, Map<String, String>> dataSources() {
        Map<String, Map<String, String>> sources = new TreeMap<>();
        for (Map.Entry<String, String> entry : all.entrySet()) {
            if (!entry.getKey().startsWith(DATASOURCES)) {
                continue;
            }
            String rest = entry.getKey().substring(DATASOURCES.length());
            int dot = rest.indexOf('.');
            if (dot <= 0) {
                continue;
            }
            sources.computeIfAbsent(rest.substring(0, dot), ignored -> new LinkedHashMap<>())
                    .put(rest.substring(dot + 1), entry.getValue());
        }
        return sources;
    }

    /** A pool for each data source, not yet connected (or warmed up, if asked); the caller closes them. */
    public Map<String, SeclumePool> pools() throws java.sql.SQLException {
        Map<String, SeclumePool> pools = new LinkedHashMap<>();
        try {
            for (Map.Entry<String, Map<String, String>> source : dataSources().entrySet()) {
                Map<String, String> pool = new LinkedHashMap<>();
                String url = null;
                for (Map.Entry<String, String> setting : source.getValue().entrySet()) {
                    if (setting.getKey().equals("url")) {
                        url = setting.getValue();
                    } else if (setting.getKey().startsWith("pool.")) {
                        pool.put(setting.getKey().substring(5), setting.getValue());
                    } else if (!setting.getKey().equals("password")) {
                        throw new IllegalArgumentException(DATASOURCES + source.getKey() + "." + setting.getKey()
                                + " is not a setting - url and pool.* are");
                    }
                }
                SeclumePool created = PoolConfiguration.pool(source.getKey(), url, pool);
                pools.put(source.getKey(), created);
                if (created.settings().isWarmup()) {
                    created.warmup();
                }
            }
        } catch (java.sql.SQLException | RuntimeException e) {
            pools.values().forEach(SeclumePool::close);
            throw e;
        }
        return pools;
    }

    /** The key ring, or {@code null} when no keys are configured. A key that cannot be read is an exception. */
    public FieldKeys fieldKeys() {
        Map<Integer, Map<String, String>> byId = new TreeMap<>();
        for (Map.Entry<String, String> entry : all.entrySet()) {
            if (!entry.getKey().startsWith(KEYS)) {
                continue;
            }
            String rest = entry.getKey().substring(KEYS.length());
            int dot = rest.indexOf('.');
            if (dot <= 0) {
                throw new IllegalArgumentException(entry.getKey() + " is not a key's setting - use "
                        + KEYS + "<number>.<provider setting>");
            }
            int id;
            try {
                id = Integer.parseInt(rest.substring(0, dot));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(entry.getKey() + ": a key is named by its number, not '"
                        + rest.substring(0, dot) + "'", e);
            }
            byId.computeIfAbsent(id, ignored -> new TreeMap<>()).put(rest.substring(dot + 1), entry.getValue());
        }
        if (byId.isEmpty()) {
            return null;
        }
        FieldKeys.Builder builder = FieldKeys.builder();
        for (Map.Entry<Integer, Map<String, String>> key : byId.entrySet()) {
            String uri = key.getValue().get("uri");
            builder.key(key.getKey(), uri != null ? SecretProviders.fromUri(uri) : SecretProviders.of(key.getValue()));
        }
        String primary = all.get(PRIMARY);
        if (primary != null && !primary.isBlank()) {
            try {
                builder.primary(Integer.parseInt(primary.trim()));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(PRIMARY + " is a key's number, not '" + primary + "'", e);
            }
        }
        return builder.build();
    }

    /**
     * The keys holding a password where seclume would have kept it off the
     * heap: {@code seclume.datasources.<name>.password}, and Helidon's own
     * {@code javax.sql.DataSource.<name>[.dataSource].password} beside a seclume URL -
     * as properties and as environment variables
     * ({@code JAVAX_SQL_DATASOURCE_APP_DATASOURCE_PASSWORD}), which MicroProfile
     * Config reads as the same property, the same {@code String} on the heap.
     */
    public List<String> passwords() {
        List<String> found = new ArrayList<>();
        for (String key : all.keySet()) {
            String normalized = key.toLowerCase(Locale.ROOT);
            if (OWN_PASSWORD.matcher(normalized).matches()
                    || OWN_PASSWORD_VARIABLE.matcher(normalized).matches()) {
                found.add(key);
                continue;
            }
            Matcher helidon = HELIDON_PASSWORD.matcher(normalized);
            boolean variable = HELIDON_PASSWORD_VARIABLE.matcher(normalized).matches();
            if (!helidon.matches() && !variable) {
                continue;
            }
            String owner = owner(normalized, "password");
            for (Map.Entry<String, String> other : all.entrySet()) {
                String otherKey = other.getKey().toLowerCase(Locale.ROOT);
                if (other.getValue() == null || !other.getValue().regionMatches(true, 0, "jdbc:seclume:", 0,
                        "jdbc:seclume:".length()) || !otherKey.endsWith("url")) {
                    continue;
                }
                boolean sameDataSource = helidon.matches()
                        && otherKey.startsWith("javax.sql.datasource." + helidon.group(1) + ".");
                if (sameDataSource || owner.equals(owner(otherKey, null))) {
                    found.add(key);
                    break;
                }
            }
        }
        return found;
    }

    /**
     * The data source a key belongs to, in one spelling for properties and
     * environment variables: {@code javax.sql.DataSource.app-db.dataSource.url}
     * and {@code JAVAX_SQL_DATASOURCE_APP_DB_PASSWORD} both belong to
     * {@code javax_sql_datasource_app_db}. The last part - {@code password},
     * {@code url}, {@code jdbcUrl} - and a {@code dataSource} before it are left off.
     */
    private static String owner(String lowerKey, String last) {
        String flat = lowerKey.replace('.', '_').replace('-', '_');
        int cut = last != null && flat.endsWith("_" + last) ? flat.length() - last.length() - 1
                : flat.lastIndexOf('_');
        String owner = cut < 0 ? flat : flat.substring(0, cut);
        return owner.endsWith("_datasource") && owner.length() > "javax_sql_datasource_datasource".length()
                ? owner.substring(0, owner.length() - "_datasource".length()) : owner;
    }

    /** {@link #passwords} as an exception, or nothing. */
    public void refusePasswords() {
        List<String> found = passwords();
        if (!found.isEmpty()) {
            throw new IllegalStateException("a password stands in the configuration (" + String.join(", ", found)
                    + "): it would be a String on the heap for the life of the application. Remove it and name "
                    + "where the secret comes from in the URL instead - provider=file&path=/run/secrets/db, "
                    + "provider=vault&..., provider=kms-decrypt&...");
        }
    }
}
