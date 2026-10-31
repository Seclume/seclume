package space.seclume.helidon;

import java.lang.annotation.Annotation;
import java.util.LinkedHashMap;
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

    void beforeShutdown(@Observes BeforeShutdown shutdown) {
        pools.values().forEach(SeclumePool::close);
        pools.clear();
        if (keys != null) {
            keys.close();
            keys = null;
        }
    }

    /** Every property MicroProfile Config knows, as flat keys. */
    static Map<String, String> flat(Config config) {
        Map<String, String> all = new LinkedHashMap<>();
        for (String name : config.getPropertyNames()) {
            if (name.startsWith("seclume.") || name.toLowerCase(java.util.Locale.ROOT).startsWith("javax.sql.datasource.")) {
                config.getOptionalValue(name, String.class).ifPresent(value -> all.put(name, value));
            }
        }
        return all;
    }
}
