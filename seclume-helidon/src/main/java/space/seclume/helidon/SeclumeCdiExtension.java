package space.seclume.helidon;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Default;
import jakarta.enterprise.inject.literal.NamedLiteral;
import jakarta.enterprise.inject.spi.AfterBeanDiscovery;
import jakarta.enterprise.inject.spi.BeforeShutdown;
import jakarta.enterprise.inject.spi.Extension;
import jakarta.inject.Singleton;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.spi.ConfigSource;

import space.seclume.field.FieldKeys;
import space.seclume.pool.SeclumePool;

/**
 * seclume for Helidon MP - or any CDI container with MicroProfile Config: each
 * {@code seclume.datasources.<name>} a {@code DataSource} bean
 * {@code @Named("<name>")} ({@code default} also {@code @Default}), and the
 * field encryption key ring a {@link FieldKeys} bean, built and installed when
 * the container starts and wiped when it stops. A password in the
 * configuration is a deployment error. The keys are {@link SeclumeSettings}'.
 */
public class SeclumeCdiExtension implements Extension {

    private final Map<String, SeclumePool> pools = new LinkedHashMap<>();
    private FieldKeys keys;

    void afterBeanDiscovery(@Observes AfterBeanDiscovery discovery) {
        SeclumeSettings settings = SeclumeSettings.of(flat(ConfigProvider.getConfig()));
        try {
            settings.refusePasswords();
            keys = settings.fieldKeys();
            pools.putAll(settings.pools());
        } catch (java.sql.SQLException | RuntimeException e) {
            discovery.addDefinitionError(e);
            return;
        }
        for (Map.Entry<String, SeclumePool> pool : pools.entrySet()) {
            SeclumePool instance = pool.getValue();
            // The qualifiers replaced, not added to: a bean with only @Named would get
            // @Default as well, and two pools would make DataSource ambiguous.
            Annotation[] qualifiers = pool.getKey().equals("default")
                    ? new Annotation[] {NamedLiteral.of(pool.getKey()), Any.Literal.INSTANCE, Default.Literal.INSTANCE}
                    : new Annotation[] {NamedLiteral.of(pool.getKey()), Any.Literal.INSTANCE};
            discovery.addBean()
                    .types(Object.class, DataSource.class, SeclumePool.class)
                    .scope(Singleton.class)
                    .qualifiers(qualifiers)
                    .createWith(context -> instance);
        }
        if (keys != null) {
            FieldKeys ring = keys;
            FieldKeys.install(ring);
            discovery.addBean()
                    .types(Object.class, FieldKeys.class)
                    .scope(Singleton.class)
                    .qualifiers(Default.Literal.INSTANCE, Any.Literal.INSTANCE)
                    .createWith(context -> ring);
        }
    }

    /** The data sources this extension made beans of, by name - for a look from outside. */
    java.util.Set<String> dataSourceNames() {
        return java.util.Set.copyOf(pools.keySet());
    }

    void beforeShutdown(@Observes BeforeShutdown shutdown) {
        pools.values().forEach(SeclumePool::close);
        pools.clear();
        if (keys != null) {
            keys.close();
            keys = null;
        }
    }

    /**
     * Every {@code seclume.*} and {@code javax.sql.DataSource.*} property, as
     * flat keys. The names come from the config sources themselves as well as
     * from {@link Config#getPropertyNames()}: Helidon's MP config builds a tree
     * of its sources, and a name with a number in it -
     * {@code seclume.field-encryption.keys.1.uri} - can come out of that tree
     * as a list element under another name, or not at all. The value is the
     * config's where it has one, else that of the source of highest ordinal.
     */
    static Map<String, String> flat(Config config) {
        java.util.Set<String> names = new java.util.LinkedHashSet<>();
        config.getPropertyNames().forEach(names::add);
        List<ConfigSource> sources = new ArrayList<>();
        config.getConfigSources().forEach(sources::add);
        sources.sort(java.util.Comparator.comparingInt(ConfigSource::getOrdinal).reversed());
        for (ConfigSource source : sources) {
            names.addAll(source.getPropertyNames());
        }
        Map<String, String> all = new java.util.TreeMap<>();
        for (String name : names) {
            if (!name.startsWith("seclume.")
                    && !name.toLowerCase(java.util.Locale.ROOT).startsWith("javax.sql.datasource.")) {
                continue;
            }
            String value = null;
            try {
                value = config.getOptionalValue(name, String.class).orElse(null);
            } catch (RuntimeException notInTheTree) {
                // read from the sources below
            }
            for (int i = 0; value == null && i < sources.size(); i++) {
                value = sources.get(i).getValue(name);
            }
            if (value != null) {
                all.put(name, value);
            }
        }
        return all;
    }
}
