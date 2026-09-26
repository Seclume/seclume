package space.seclume.spring;

import java.sql.SQLException;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;
import space.seclume.secret.ExpiringCredentials;

/**
 * The auto-configuration.
 *
 * <p>With this the goal of the library is reached: add the dependency, fill in
 * {@code application.properties}, done. For every entry under
 * {@code seclume.datasources} one pooled {@link DataSource} comes into being,
 * and everything Spring hangs off a {@code DataSource} - {@code JdbcClient},
 * {@code JdbcTemplate}, {@code DataSourceTransactionManager}, JPA, Actuator -
 * finds it like any other.
 *
 * <p>The only difference to {@code spring.datasource.*} is the one line that
 * does not exist: the password is not in the configuration, only where it comes
 * from. Whoever writes it there anyway gets an abort with a reason at startup -
 * passing over it quietly would defeat the core property, and unnoticed at
 * that.
 */
@AutoConfiguration(beforeName = {
    // Boot registers a bean called "dataSource" of its own as soon as any pool
    // is on the class path - and Hikari comes along with spring-boot-starter-
    // data-jpa whether anybody wants it or not. Ours has to be registered
    // first; then Boot's @ConditionalOnMissingBean sees it and steps aside.
    // Found the moment a real Spring Data application was built against this
    // starter: without it the context fails with a BeanDefinitionOverride.
    "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
    "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration"})
@ConditionalOnClass(SeclumePool.class)
@EnableConfigurationProperties(SeclumeProperties.class)
@org.springframework.context.annotation.Import(SeclumeAutoConfiguration.SeclumeDataSourceRegistrar.class)
public class SeclumeAutoConfiguration {

    // One bean per configured data source - a fixed @Bean method could only
    // ever make one, and how many there are is known at runtime.
    //
    // Imported, not a @Bean: a BeanFactoryPostProcessor runs after every
    // configuration class has been read, and by then Spring Boot has already
    // registered a "dataSource" of its own - the context then fails with a
    // BeanDefinitionOverrideException. An ImportBeanDefinitionRegistrar runs
    // while the configuration classes are being read, so this definition
    // exists before Boot's @ConditionalOnMissingBean(DataSource.class) is
    // evaluated, and Boot steps aside as it is meant to. Found by building a
    // real Spring Data application against this starter.

    /**
     * Metrics and health live in classes of their own - and that is not
     * cosmetic.
     *
     * <p>A {@code @Bean} method on this class would make Spring look at its
     * signature, and looking at {@code SeclumePoolHealth} means loading
     * {@code HealthIndicator}. Where the Actuator is not on the class path
     * that is a {@code NoClassDefFoundError} at startup - the auto-configuration
     * would break exactly the applications that never asked for it. Inside a
     * nested class the condition is decided first, and the methods are never
     * looked at.
     */
    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "io.micrometer.core.instrument.MeterRegistry")
    static class MetricsConfiguration {

        /** Every pool of the application at once - a second one needs no line. */
        @Bean
        @ConditionalOnMissingBean(SeclumePoolMetrics.class)
        SeclumePoolMetrics seclumePoolMetrics(
                org.springframework.beans.factory.ObjectProvider<SeclumePool> pools,
                Environment environment) {
            boolean hikariNames = Boolean.parseBoolean(
                    environment.getProperty("seclume.metrics.hikari-names", "false"));
            return new SeclumePoolMetrics(pools.stream().toList(), hikariNames);
        }

        /**
         * The Flight Recorder's events as meters - off unless asked for.
         *
         * <p>See {@link SeclumeQueryMetrics}: it starts a recording stream,
         * which changes the state of the process it runs in, and a library
         * does not do that on its own initiative. The bean is only defined
         * when the property is set, so without it there is no thread and no
         * stream.
         */
        @Bean(destroyMethod = "close")
        @ConditionalOnMissingBean(SeclumeQueryMetrics.class)
        @org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(
                name = "seclume.metrics.queries", havingValue = "true")
        SeclumeQueryMetrics seclumeQueryMetrics(Environment environment) {
            java.time.Duration threshold = environment.getProperty(
                    "seclume.metrics.query-threshold", java.time.Duration.class,
                    java.time.Duration.ofMillis(10));
            int bound = environment.getProperty(
                    "seclume.metrics.query-fingerprints", Integer.class, 100);
            return new SeclumeQueryMetrics(threshold, bound);
        }
    }

    /**
     * Statements as spans - only with the OpenTelemetry API on the class
     * path, an {@code OpenTelemetry} bean to hang them on, and the property
     * set.
     *
     * <p>Three conditions rather than one because each removes a different
     * surprise: without the API this class must not be looked at, without an
     * SDK the spans would go nowhere, and without the property a library
     * would have installed a process-wide listener on its own initiative.
     * See {@link SeclumeTracing} for why tracing is the one thing here that
     * needed a hook in the drivers at all.
     */
    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "io.opentelemetry.api.OpenTelemetry")
    static class TracingConfiguration {

        @Bean(destroyMethod = "close")
        @ConditionalOnMissingBean(SeclumeTracing.class)
        @org.springframework.boot.autoconfigure.condition.ConditionalOnBean(
                io.opentelemetry.api.OpenTelemetry.class)
        @org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(
                name = "seclume.tracing", havingValue = "true")
        SeclumeTracing seclumeTracing(io.opentelemetry.api.OpenTelemetry openTelemetry,
                org.springframework.core.env.Environment environment) {
            SeclumeTracing tracing = new SeclumeTracing(openTelemetry,
                    SeclumeTracing.optedIntoDuplicates(
                            environment.getProperty("OTEL_SEMCONV_STABILITY_OPT_IN")));
            tracing.install();
            return tracing;
        }
    }

    /** The health check - only when the health API is on the class path. */
    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.boot.health.contributor.HealthIndicator")
    static class HealthConfiguration {

        /**
         * Borrows a connection and gives it straight back; see
         * {@link SeclumePoolHealth} for why it deliberately runs no query.
         */
        @Bean
        @ConditionalOnMissingBean(SeclumePoolHealth.class)
        SeclumePoolHealth seclumePoolHealth(
                org.springframework.beans.factory.ObjectProvider<SeclumePool> pools) {
            return new SeclumePoolHealth(pools.stream().toList());
        }
    }

    /** {@code /actuator/seclume} - only when the actuator is on the class path. */
    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.boot.actuate.endpoint.annotation.Endpoint")
    static class EndpointConfiguration {

        @Bean
        @ConditionalOnMissingBean(SeclumeEndpoint.class)
        SeclumeEndpoint seclumeEndpoint(
                org.springframework.beans.factory.ObjectProvider<SeclumePool> pools) {
            return new SeclumeEndpoint(pools.stream().toList());
        }
    }

    /** Registers the pools as beans and checks the configuration. */
    static final class SeclumeDataSourceRegistrar
            implements org.springframework.context.annotation.ImportBeanDefinitionRegistrar,
                       org.springframework.context.EnvironmentAware,
                       org.springframework.beans.factory.BeanFactoryAware {

        private Environment environment;
        private org.springframework.beans.factory.BeanFactory beanFactory;

        @Override
        public void setEnvironment(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void setBeanFactory(org.springframework.beans.factory.BeanFactory beanFactory) {
            this.beanFactory = beanFactory;
        }

        @Override
        public void registerBeanDefinitions(
                org.springframework.core.type.AnnotationMetadata metadata,
                BeanDefinitionRegistry registry) {
            org.springframework.beans.factory.BeanFactory factory = beanFactory;
            rejectInlinePasswords(environment);
            SeclumeProperties properties = bind(environment);
            if (properties.getDatasources().isEmpty()) {
                return;
            }
            String primary = properties.getPrimary();
            boolean single = properties.getDatasources().size() == 1;
            SeclumeProperties.ReadWriteSplitProperties split = properties.getReadWriteSplit();
            boolean splitting = split.getPrimary() != null && split.getReplica() != null;
            if (splitting) {
                for (String part : new String[] {split.getPrimary(), split.getReplica()}) {
                    if (!properties.getDatasources().containsKey(part)) {
                        throw new IllegalStateException("seclume.read-write-split names '" + part
                                + "', which is not under seclume.datasources");
                    }
                }
                single = false;          // the split is the application's DataSource
            }

            for (Map.Entry<String, SeclumeProperties.DataSourceProperties> entry
                    : properties.getDatasources().entrySet()) {
                String name = entry.getKey();
                String beanName = single ? "dataSource" : name + "DataSource";
                RootBeanDefinition definition = new RootBeanDefinition(SeclumePool.class);
                definition.setPrimary(!splitting && (single || name.equals(primary)));
                definition.setDestroyMethodName("close");
                definition.setInstanceSupplier(() -> build(name, entry.getValue(), factory));
                registry.registerBeanDefinition(beanName, definition);
            }
            if (splitting) {
                String primaryBean = split.getPrimary() + "DataSource";
                String replicaBean = split.getReplica() + "DataSource";
                java.time.Duration wait = split.getReadYourWrites();
                RootBeanDefinition both = new RootBeanDefinition(
                        space.seclume.pool.ReadWriteSplit.class);
                both.setPrimary(true);
                both.setInstanceSupplier(() -> new space.seclume.pool.ReadWriteSplit(
                        factory.getBean(primaryBean, javax.sql.DataSource.class),
                        factory.getBean(replicaBean, javax.sql.DataSource.class))
                        .readYourWrites(wait));
                registry.registerBeanDefinition("dataSource", both);
            }
        }

        private static SeclumeProperties bind(Environment environment) {
            return org.springframework.boot.context.properties.bind.Binder.get(environment)
                    .bind("seclume", SeclumeProperties.class)
                    .orElseGet(SeclumeProperties::new);
        }

        /**
         * A password in the configuration is exactly what this library exists
         * to prevent. Ignoring it would be worse than aborting: the application
         * would run, the password would sit on the heap, and nobody would
         * know.
         */
        private static void rejectInlinePasswords(Environment environment) {
            if (!(environment instanceof ConfigurableEnvironment configurable)) {
                return;
            }
            for (String key : new String[] {"spring.datasource.password", "seclume.password"}) {
                if (configurable.containsProperty(key)) {
                    throw new IllegalStateException(
                            key + " is set. seclume exists to keep database passwords out of "
                            + "the heap, and a password in the configuration is a String in "
                            + "the Environment for the lifetime of the application - visible "
                            + "in every heap dump and in the Actuator's /env endpoint. "
                            + "Configure where the secret comes from instead: "
                            + "seclume.datasources.main.secret.provider=file and "
                            + "seclume.datasources.main.secret.path=/run/secrets/db-password.");
                }
            }
            String prefix = "seclume.datasources.";
            for (org.springframework.core.env.PropertySource<?> source
                    : configurable.getPropertySources()) {
                if (source instanceof org.springframework.core.env.EnumerablePropertySource<?> e) {
                    for (String name : e.getPropertyNames()) {
                        if (name.startsWith(prefix)
                                && (name.endsWith(".password") || name.endsWith(".secret.value"))) {
                            throw new IllegalStateException(
                                    name + " is not a seclume setting. Configure the source of "
                                    + "the secret, not the secret: "
                                    + "...secret.provider=file, ...secret.path=/run/secrets/db");
                        }
                    }
                }
            }
        }

        private static SeclumePool build(String name,
                                          SeclumeProperties.DataSourceProperties properties,
                                          BeanFactory beans) {
            DataSource source = SeclumeDataSources.create(name, properties, beans);
            PoolSettings settings = poolSettings(name, properties.getPool());
            // The one place that knows both halves. The pool deliberately
            // knows nothing about secret sources - see its module comment -
            // and the driver's DataSource knows nothing about pooling. Here
            // both are in hand, so a credential with an expiry (Vault's
            // database engine, an RDS IAM token) can tell the pool when to
            // replace its connections. A static password answers null and
            // nothing changes.
            if (source instanceof ExpiringCredentials expiring) {
                settings.setCredentialExpiry(expiring::credentialsValidUntil);
            }
            // The tenant of the request, on every borrow - see SeclumeSessionContext.
            beans.getBeanProvider(SeclumeSessionContext.class)
                    .ifAvailable(context -> settings.setSessionContext(context::current));
            SeclumePool pool = new SeclumePool(source, settings);
            if (settings.isWarmup()) {
                try {
                    pool.warmup();
                } catch (SQLException e) {
                    pool.close();
                    throw new IllegalStateException(
                            "seclume.datasources." + name + " could not open its connections "
                            + "during warmup", e);
                }
            }
            return pool;
        }

        private static PoolSettings poolSettings(String name, SeclumeProperties.Pool pool) {
            PoolSettings settings = new PoolSettings();
            settings.setName("seclume-" + name);
            if (pool.getMaximumPoolSize() != null) {
                settings.setMaximumPoolSize(pool.getMaximumPoolSize());
            }
            if (pool.getMinimumIdle() != null) {
                settings.setMinimumIdle(pool.getMinimumIdle());
            }
            if (pool.getConnectionTimeout() != null) {
                settings.setConnectionTimeout(pool.getConnectionTimeout());
            }
            if (pool.getIdleTimeout() != null) {
                settings.setIdleTimeout(pool.getIdleTimeout());
            }
            if (pool.getMaxLifetime() != null) {
                settings.setMaxLifetime(pool.getMaxLifetime());
            }
            if (pool.getCredentialMargin() != null) {
                settings.setCredentialMargin(pool.getCredentialMargin());
            }
            if (pool.getCredentialSpread() != null) {
                settings.setCredentialSpread(pool.getCredentialSpread());
            }
            if (pool.getShutdownTimeout() != null) {
                settings.setShutdownTimeout(pool.getShutdownTimeout());
            }
            if (pool.getKeepaliveTime() != null) {
                settings.setKeepaliveTime(pool.getKeepaliveTime());
            }
            if (pool.getValidationTimeout() != null) {
                settings.setValidationTimeout(pool.getValidationTimeout());
            }
            if (pool.getValidationBypassWindow() != null) {
                settings.setValidationBypassWindow(pool.getValidationBypassWindow());
            }
            if (pool.getLeakDetectionThreshold() != null) {
                settings.setLeakDetectionThreshold(pool.getLeakDetectionThreshold());
            }
            if (pool.getWarmup() != null) {
                settings.setWarmup(pool.getWarmup());
            }
            if (pool.getStatementCacheSize() != null) {
                settings.setStatementCacheSize(pool.getStatementCacheSize());
            }
            return settings;
        }
    }
}
