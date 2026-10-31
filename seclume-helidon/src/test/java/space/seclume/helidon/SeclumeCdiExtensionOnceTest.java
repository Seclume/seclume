package space.seclume.helidon;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.enterprise.inject.spi.AfterBeanDiscovery;
import jakarta.enterprise.inject.spi.configurator.BeanConfigurator;

import org.eclipse.microprofile.config.spi.ConfigProviderResolver;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import space.seclume.field.FieldKeys;

/**
 * The extension makes its beans once, however often a container calls it: an
 * observer called twice by one container - once per archive that sees it -
 * and a second instance of the extension add nothing more, and once the
 * container is gone the next one gets its beans again. The container's side is
 * a stand-in that counts what is added and keeps the definition errors.
 *
 * <p>Isolated: the system properties, the installed ring and the extension's
 * record of the running container are each one per JVM.
 */
@Isolated
class SeclumeCdiExtensionOnceTest {

    private static final Map<String, String> SETTINGS = new LinkedHashMap<>();

    /** The container's last event, which carries nothing the extension reads. */
    private static final jakarta.enterprise.inject.spi.BeforeShutdown SHUTDOWN =
            (jakarta.enterprise.inject.spi.BeforeShutdown) Proxy.newProxyInstance(
                    SeclumeCdiExtensionOnceTest.class.getClassLoader(),
                    new Class<?>[] {jakarta.enterprise.inject.spi.BeforeShutdown.class},
                    (proxy, method, arguments) -> {
                        throw new UnsupportedOperationException(method.getName());
                    });
    private static Path keyFile;

    /** What a container would have been asked to do. */
    static final class Discovery {
        final List<Object[]> beans = new ArrayList<>();
        final List<Throwable> errors = new ArrayList<>();

        AfterBeanDiscovery event() {
            return (AfterBeanDiscovery) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {AfterBeanDiscovery.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "addBean" -> configurator();
                        case "addDefinitionError" -> errors.add((Throwable) arguments[0]);
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
        }

        private BeanConfigurator<?> configurator() {
            Object[] bean = new Object[3];
            beans.add(bean);
            return (BeanConfigurator<?>) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {BeanConfigurator.class}, (proxy, method, arguments) -> {
                        switch (method.getName()) {
                            case "types" -> bean[0] = arguments[0];
                            case "qualifiers" -> bean[1] = arguments[0];
                            case "createWith" -> bean[2] = arguments[0];
                            default -> {
                                // scope and the rest: nothing to count
                            }
                        }
                        return proxy;
                    });
        }
    }

    @BeforeAll
    static void configuration() throws Exception {
        StubDriver.INSTANCE.urls.size();
        keyFile = Files.createTempFile("seclume-helidon-once", ".key");
        Files.writeString(keyFile, Base64.getEncoder().encodeToString(new byte[32]));
        SETTINGS.put("seclume.datasources.default.url", "jdbc:seclume:stub://db/app?user=a&provider=file&path=/x");
        SETTINGS.put("seclume.datasources.orders.url", "jdbc:seclume:stub://db/orders?user=o&provider=file&path=/y");
        SETTINGS.put("seclume.field-encryption.keys.1.provider", "file");
        SETTINGS.put("seclume.field-encryption.keys.1.path", keyFile.toString());
        SETTINGS.forEach(System::setProperty);
        fresh();
    }

    @AfterAll
    static void clear() throws Exception {
        SETTINGS.keySet().forEach(System::clearProperty);
        fresh();
        Files.deleteIfExists(keyFile);
    }

    /** A configuration read anew, with the system properties as they are now. */
    private static void fresh() {
        ConfigProviderResolver resolver = ConfigProviderResolver.instance();
        resolver.releaseConfig(resolver.getConfig(Thread.currentThread().getContextClassLoader()));
    }

    @Test
    void theBeansAreMadeOnceAndAgainForTheNextContainer() {
        assertNull(SeclumeCdiExtension.active(), "no container is running");
        SeclumeCdiExtension first = new SeclumeCdiExtension();
        SeclumeCdiExtension second = new SeclumeCdiExtension();
        Discovery discovery = new Discovery();
        try {
            first.afterBeanDiscovery(discovery.event());
            assertEquals(3, discovery.beans.size(), "two pools and the key ring");
            assertTrue(discovery.errors.isEmpty(), discovery.errors.toString());
            first.afterBeanDiscovery(discovery.event());
            assertEquals(3, discovery.beans.size(), "the same instance, called again, adds nothing");
            second.afterBeanDiscovery(discovery.event());
            assertEquals(3, discovery.beans.size(), "a second instance stands aside");
            assertSame(first, SeclumeCdiExtension.active());
            assertEquals(java.util.Set.of("default", "orders"), first.dataSourceNames());
            assertEquals(java.util.Set.of(), second.dataSourceNames());
            assertSame(FieldKeys.installed(), creator(discovery, 2).apply(null),
                    "the ring bean is the installed ring");
            // CDI gives a bean with only @Named and @Any the @Default qualifier too:
            // every pool carries @SeclumeDataSource, and only "default" is @Default.
            for (Object[] bean : discovery.beans.subList(0, 2)) {
                List<String> qualifiers = java.util.Arrays.stream((java.lang.annotation.Annotation[]) bean[1])
                        .map(q -> q.annotationType().getSimpleName()).toList();
                assertTrue(qualifiers.contains("SeclumeDataSource"), qualifiers.toString());
                boolean isDefault = java.util.Arrays.stream((java.lang.annotation.Annotation[]) bean[1])
                        .anyMatch(q -> q instanceof SeclumeDataSource named && named.value().equals("default"));
                assertEquals(isDefault, qualifiers.contains("Default"), qualifiers.toString());
            }
        } finally {
            first.beforeShutdown(SHUTDOWN);
            second.beforeShutdown(SHUTDOWN);
        }
        assertNull(SeclumeCdiExtension.active(), "the slot is free once the container stopped");

        Discovery next = new Discovery();
        try {
            second.afterBeanDiscovery(next.event());
            assertEquals(3, next.beans.size(), "the next container gets its beans");
            assertSame(second, SeclumeCdiExtension.active());
        } finally {
            second.beforeShutdown(SHUTDOWN);
        }
    }

    @Test
    void aContainerThatFailsToStartLeavesTheSlotFree() {
        System.setProperty("seclume.datasources.orders.password", "zl-once-canary");
        fresh();
        SeclumeCdiExtension refused = new SeclumeCdiExtension();
        Discovery discovery = new Discovery();
        try {
            refused.afterBeanDiscovery(discovery.event());
            assertEquals(0, discovery.beans.size());
            assertEquals(1, discovery.errors.size());
            assertTrue(discovery.errors.get(0).getMessage().contains("seclume.datasources.orders.password"),
                    discovery.errors.get(0).getMessage());
            assertTrue(!discovery.errors.get(0).getMessage().contains("zl-once-canary"));
            assertNull(SeclumeCdiExtension.active(), "a failed start holds no slot - no BeforeShutdown follows it");
        } finally {
            System.clearProperty("seclume.datasources.orders.password");
            fresh();
        }
        SeclumeCdiExtension after = new SeclumeCdiExtension();
        Discovery next = new Discovery();
        try {
            after.afterBeanDiscovery(next.event());
            assertEquals(3, next.beans.size(), "and the next start works");
        } finally {
            after.beforeShutdown(SHUTDOWN);
        }
    }

    /** What the bean is made with: {@code createWith}'s function. */
    @SuppressWarnings("unchecked")
    private static java.util.function.Function<Object, Object> creator(Discovery discovery, int bean) {
        return (java.util.function.Function<Object, Object>) discovery.beans.get(bean)[2];
    }
}
