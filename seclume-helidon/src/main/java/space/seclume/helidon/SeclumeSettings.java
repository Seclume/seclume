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
     * {@code javax.sql.DataSource.<name>[.dataSource].password} beside a seclume URL.
     */
    public List<String> passwords() {
        List<String> found = new ArrayList<>();
        for (String key : all.keySet()) {
            String normalized = key.toLowerCase(Locale.ROOT);
            if (OWN_PASSWORD.matcher(normalized).matches()) {
                found.add(key);
                continue;
            }
            Matcher helidon = HELIDON_PASSWORD.matcher(normalized);
            if (helidon.matches()) {
                for (Map.Entry<String, String> other : all.entrySet()) {
                    String otherKey = other.getKey().toLowerCase(Locale.ROOT);
                    if (otherKey.startsWith("javax.sql.datasource." + helidon.group(1) + ".")
                            && otherKey.endsWith("url") && other.getValue() != null
                            && other.getValue().startsWith("jdbc:seclume:")) {
                        found.add(key);
                        break;
                    }
                }
            }
        }
        return found;
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
