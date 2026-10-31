package space.seclume.helidon;

import java.sql.SQLException;
import java.util.Map;

import io.helidon.config.Config;

import space.seclume.field.FieldKeys;
import space.seclume.pool.SeclumePool;

/**
 * seclume for Helidon SE, from its {@code Config}:
 *
 * <pre>{@code
 * Config config = Config.create();
 * try (SeclumeHelidon seclume = SeclumeHelidon.create(config)) {
 *     DataSource orders = seclume.dataSource("orders");
 *     ...
 * }
 * }</pre>
 *
 * <p>{@code create} refuses a password in the configuration, makes a pool for
 * each {@code seclume.datasources.<name>} and builds and installs the field
 * encryption key ring when keys are configured; {@code close} closes the pools
 * and wipes the ring. The keys are {@link SeclumeSettings}'.
 */
public final class SeclumeHelidon implements AutoCloseable {

    private final Map<String, SeclumePool> pools;
    private final FieldKeys keys;

    private SeclumeHelidon(Map<String, SeclumePool> pools, FieldKeys keys) {
        this.pools = pools;
        this.keys = keys;
    }

    /** Everything seclume has to set up for {@code config}. */
    public static SeclumeHelidon create(Config config) throws SQLException {
        SeclumeSettings settings = SeclumeSettings.of(config.asMap().orElse(Map.of()));
        settings.refusePasswords();
        FieldKeys keys = settings.fieldKeys();
        Map<String, SeclumePool> pools;
        try {
            pools = settings.pools();
        } catch (SQLException | RuntimeException e) {
            if (keys != null) {
                keys.close();
            }
            throw e;
        }
        if (keys != null) {
            FieldKeys.install(keys);
        }
        return new SeclumeHelidon(pools, keys);
    }

    /** The pool named {@code name} under {@code seclume.datasources}. */
    public SeclumePool dataSource(String name) {
        SeclumePool pool = pools.get(name);
        if (pool == null) {
            throw new IllegalArgumentException("no data source " + name + " - configured are " + pools.keySet());
        }
        return pool;
    }

    /** Every pool, by name. */
    public Map<String, SeclumePool> dataSources() {
        return Map.copyOf(pools);
    }

    /** The key ring, or {@code null} when none is configured. */
    public FieldKeys fieldKeys() {
        return keys;
    }

    @Override
    public void close() {
        pools.values().forEach(SeclumePool::close);
        if (keys != null) {
            keys.close();
        }
    }
}
