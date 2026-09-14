package space.seclume.spring;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;

import space.seclume.internal.Platform;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * Turns configuration into a {@link SecretProvider}.
 *
 * <p>The actual mapping from names to sources lives in
 * {@link SecretProviders} and is used by the JDBC URL just the same. Only the
 * two cases that exist solely in Spring are added here:
 *
 * <ul>
 *   <li>{@code bean} - the application brings its own source (Vault, KMS, HSM)
 *       and plugs it in as a bean.</li>
 *   <li>{@code integrated} - there is no secret in the process at all, because
 *       authentication runs over Kerberos/SSPI. Then no provider
 *       is created.</li>
 * </ul>
 *
 * <p>{@code dpapi} and {@code credential-manager} exist only on Windows. On any
 * other platform the startup aborts with a clear message rather than quietly
 * falling back to something else - an application that authenticates
 * differently from how it was configured, without anyone noticing, is worse
 * than one that does not
 * start at all.
 */
final class SecretProviderFactory {

    private final BeanFactory beans;

    SecretProviderFactory(BeanFactory beans) {
        this.beans = beans;
    }

    /**
     * @return the provider, or {@code null} for {@code integrated} - then the
     *         driver itself brings along how it authenticates
     */
    SecretProvider create(String name, SeclumeProperties.Secret secret) {
        String provider = secret.getProvider();
        if (provider == null || provider.isBlank()) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + ".secret.provider is missing - set it to "
                    + "one of file, env-file, unix-socket, process, dpapi, credential-manager, "
                    + "bean, integrated");
        }
        String kind = provider.trim().toLowerCase(Locale.ROOT);
        return switch (kind) {
            case "integrated" -> null;
            case "bean" -> fromBean(name, secret);
            case "dpapi", "credential-manager", "credentialmanager" -> {
                requireWindows(name, kind);
                yield SecretProviders.of(settings(secret));
            }
            default -> SecretProviders.of(settings(secret));
        };
    }

    private SecretProvider fromBean(String name, SeclumeProperties.Secret secret) {
        String beanName = secret.getBean();
        if (beanName == null || beanName.isBlank()) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + ".secret.provider is 'bean', so "
                    + ".secret.bean must name the SecretProvider bean to use");
        }
        try {
            return beans.getBean(beanName, SecretProvider.class);
        } catch (NoSuchBeanDefinitionException e) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + ".secret.bean names '" + beanName
                    + "', but there is no SecretProvider bean by that name", e);
        }
    }

    private static void requireWindows(String name, String kind) {
        if (!Platform.isWindows()) {
            throw new IllegalStateException(
                    "seclume.datasources." + name + ".secret.provider is '" + kind
                    + "', which exists only on Windows. This application is running on "
                    + System.getProperty("os.name") + ". seclume does not quietly fall back "
                    + "to another source - configure one that works here, for example "
                    + "provider=file with a path to a mounted secret.");
        }
    }

    /** Translates the Spring fields into the keys {@link SecretProviders} knows. */
    private static Map<String, String> settings(SeclumeProperties.Secret secret) {
        Map<String, String> settings = new LinkedHashMap<>();
        put(settings, "provider", secret.getProvider());
        put(settings, "path", secret.getPath());
        put(settings, "key", secret.getKey());
        put(settings, "target", secret.getTarget());
        put(settings, "entropy", secret.getEntropy());
        put(settings, "command", secret.getCommand());
        settings.put("max-length", String.valueOf(secret.getMaxLength()));
        return settings;
    }

    private static void put(Map<String, String> settings, String key, String value) {
        if (value != null && !value.isBlank()) {
            settings.put(key, value);
        }
    }
}
