package space.seclume.micronaut;

import java.util.LinkedHashMap;
import java.util.Map;

import io.micronaut.context.annotation.EachProperty;
import io.micronaut.context.annotation.Parameter;

/**
 * One data source under {@code seclume.datasources.<name>}:
 *
 * <pre>
 *   seclume:
 *     datasources:
 *       default:
 *         url: jdbc:seclume:postgresql://db/app?user=app&amp;provider=file&amp;path=/run/secrets/db
 *         pool:
 *           maximum-pool-size: 10
 *           connection-timeout: 30s
 * </pre>
 *
 * <p>The URL says where the secret comes from - a provider, as every seclume
 * URL does - and the driver reads it into native memory at each login. The
 * {@code pool} keys are {@link space.seclume.pool.PoolConfiguration}'s.
 */
@EachProperty(value = "seclume.datasources", primary = "default")
public class SeclumeDataSourceConfiguration {

    private final String name;
    private String url;
    private Map<String, String> pool = new LinkedHashMap<>();

    public SeclumeDataSourceConfiguration(@Parameter String name) {
        this.name = name;
    }

    /** The name under {@code seclume.datasources}: the bean's qualifier. */
    public String getName() {
        return name;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public Map<String, String> getPool() {
        return pool;
    }

    public void setPool(Map<String, String> pool) {
        this.pool = pool == null ? new LinkedHashMap<>() : new LinkedHashMap<>(pool);
    }
}
