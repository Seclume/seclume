package space.seclume.spring;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The configuration under {@code seclume}.
 *
 * <p>Here lies the trap this whole library revolves around: Spring binds
 * configuration as {@code String}. A {@code password} field would therefore be
 * a {@code String} in the {@code Environment} - on the heap for the lifetime of
 * the application, in every dump, in every Actuator endpoint.
 *
 * <p>There is therefore no password field here, only the <b>reference to the
 * source</b>. Whoever tries to set one anyway gets an abort with a reason at
 * startup - see {@link SeclumeAutoConfiguration}.
 *
 * <pre>
 * seclume:
 *   datasources:
 *     main:
 *       url: jdbc:seclume:postgresql://db:5432/app
 *       username: app
 *       secret:
 *         provider: file
 *         path: /run/secrets/db-password
 *       pool:
 *         maximum-pool-size: 20
 * </pre>
 */
@ConfigurationProperties("seclume")
public class SeclumeProperties {

    /** Which {@code DataSource} is the primary one when there are several. */
    private String primary = "main";

    private Map<String, DataSourceProperties> datasources = new LinkedHashMap<>();

    public String getPrimary() {
        return primary;
    }

    public void setPrimary(String primary) {
        this.primary = primary;
    }

    public Map<String, DataSourceProperties> getDatasources() {
        return datasources;
    }

    public void setDatasources(Map<String, DataSourceProperties> datasources) {
        this.datasources = datasources;
    }

    /** One data source: where to, as whom, where the secret comes from, how pooled. */
    public static class DataSourceProperties {

        private String url;
        private String username;
        private Secret secret = new Secret();
        private Pool pool = new Pool();

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public Secret getSecret() {
            return secret;
        }

        public void setSecret(Secret secret) {
            this.secret = secret;
        }

        public Pool getPool() {
            return pool;
        }

        public void setPool(Pool pool) {
            this.pool = pool;
        }
    }

    /**
     * Where the password comes from - not what it is.
     *
     * <p>Every field here is a reference: a file path, an entry name, a bean
     * name. None of them is a secret, none of them has to be protected, and
     * none of them does any harm when it shows up in a log.
     */
    public static class Secret {

        /**
         * {@code file}, {@code env-file}, {@code unix-socket}, {@code process},
         * {@code dpapi}, {@code credential-manager}, {@code bean} or
         * {@code integrated}.
         */
        private String provider;
        /** File or socket, depending on the provider. */
        private String path;
        /** Entry name for {@code env-file}. */
        private String key;
        /** Target name in the Windows Credential Manager. */
        private String target;
        /** Second factor for DPAPI. */
        private String entropy;
        /** Command for {@code process}, space separated. */
        private String command;
        /** Name of the {@code SecretProvider} bean for {@code provider: bean}. */
        private String bean;
        /** Upper bound in bytes; no database password is longer. */
        private int maxLength = 256;

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getTarget() {
            return target;
        }

        public void setTarget(String target) {
            this.target = target;
        }

        public String getEntropy() {
            return entropy;
        }

        public void setEntropy(String entropy) {
            this.entropy = entropy;
        }

        public String getCommand() {
            return command;
        }

        public void setCommand(String command) {
            this.command = command;
        }

        public String getBean() {
            return bean;
        }

        public void setBean(String bean) {
            this.bean = bean;
        }

        public int getMaxLength() {
            return maxLength;
        }

        public void setMaxLength(int maxLength) {
            this.maxLength = maxLength;
        }
    }

    /** The pool settings; the defaults live in {@code PoolSettings}. */
    public static class Pool {

        private Integer maximumPoolSize;
        private Integer minimumIdle;
        private Duration connectionTimeout;
        private Duration idleTimeout;
        private Duration maxLifetime;
        private Duration keepaliveTime;
        private Duration validationTimeout;
        private Duration validationBypassWindow;
        private Duration leakDetectionThreshold;
        private Boolean warmup;
        private Integer statementCacheSize;

        public Integer getMaximumPoolSize() {
            return maximumPoolSize;
        }

        /** How many prepared statements a connection keeps between borrows. */
        public Integer getStatementCacheSize() {
            return statementCacheSize;
        }

        public void setStatementCacheSize(Integer statementCacheSize) {
            this.statementCacheSize = statementCacheSize;
        }

        public void setMaximumPoolSize(Integer maximumPoolSize) {
            this.maximumPoolSize = maximumPoolSize;
        }

        public Integer getMinimumIdle() {
            return minimumIdle;
        }

        public void setMinimumIdle(Integer minimumIdle) {
            this.minimumIdle = minimumIdle;
        }

        public Duration getConnectionTimeout() {
            return connectionTimeout;
        }

        public void setConnectionTimeout(Duration connectionTimeout) {
            this.connectionTimeout = connectionTimeout;
        }

        public Duration getIdleTimeout() {
            return idleTimeout;
        }

        public void setIdleTimeout(Duration idleTimeout) {
            this.idleTimeout = idleTimeout;
        }

        public Duration getMaxLifetime() {
            return maxLifetime;
        }

        public void setMaxLifetime(Duration maxLifetime) {
            this.maxLifetime = maxLifetime;
        }

        public Duration getKeepaliveTime() {
            return keepaliveTime;
        }

        public void setKeepaliveTime(Duration keepaliveTime) {
            this.keepaliveTime = keepaliveTime;
        }

        public Duration getValidationTimeout() {
            return validationTimeout;
        }

        public void setValidationTimeout(Duration validationTimeout) {
            this.validationTimeout = validationTimeout;
        }

        /**
         * How long a returned connection is trusted without being probed - a
         * probe is a round trip, and doing it on every handout is what makes a
         * pool slow. Zero means probe every time.
         */
        public Duration getValidationBypassWindow() {
            return validationBypassWindow;
        }

        public void setValidationBypassWindow(Duration validationBypassWindow) {
            this.validationBypassWindow = validationBypassWindow;
        }

        public Duration getLeakDetectionThreshold() {
            return leakDetectionThreshold;
        }

        public void setLeakDetectionThreshold(Duration leakDetectionThreshold) {
            this.leakDetectionThreshold = leakDetectionThreshold;
        }

        public Boolean getWarmup() {
            return warmup;
        }

        public void setWarmup(Boolean warmup) {
            this.warmup = warmup;
        }
    }
}
