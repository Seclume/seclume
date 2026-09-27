package space.seclume.spring;

import java.util.Locale;
import java.util.Map;

import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.ClassUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import space.seclume.http.SeclumeHttp;
import space.seclume.http.SeclumeHttpRequestFactory;

/**
 * HTTPS APIs from {@code application.properties}, as many as needed, each with
 * its own server and its own secret:
 *
 * <pre>
 * seclume.http.clients.payments.url=https://api.payments.example/v2?provider=file&amp;path=/run/secrets/payments
 * seclume.http.clients.search.url=https://search.internal:9200?auth=header&amp;header=Authorization&amp;prefix=ApiKey%20&amp;provider=vault&amp;...
 * seclume.http.clients.search.interface=com.example.SearchApi        (optional)
 * </pre>
 *
 * <p>Per name there is a {@link RestClient} bean of that name - injected with
 * {@code @Qualifier("payments") RestClient payments} - whose base URL is the
 * URL's origin and path, and whose credential is added by seclume below it,
 * off the heap (see {@link SeclumeHttp}). With {@code interface=}, an
 * {@code @HttpExchange} interface is made on it as well and can be injected by
 * its type. The underlying {@link SeclumeHttp} is a bean too, named
 * {@code <name>SeclumeHttp}.
 *
 * <p>Where Spring Boot's {@code RestClient.Builder} is there, each client
 * starts from it - its message converters, its customizers, its observation -
 * and seclume sets the request factory and the base URL on top. No builder
 * bean is registered here: Boot's own would step aside for it.
 */
@AutoConfiguration
@ConditionalOnClass(name = {"space.seclume.http.SeclumeHttp",
        "org.springframework.web.client.RestClient"})
@Import(SeclumeHttpClientsAutoConfiguration.Registrar.class)
public class SeclumeHttpClientsAutoConfiguration {

    static final String PREFIX = "seclume.http.clients";

    /** One {@code seclume.http.clients.<name>} entry. */
    public static class ClientProperties {

        /** The API's URL with its secret provider - see SeclumeHttp. */
        private String url;

        /** An {@code @HttpExchange} interface to make on this client, by class name. */
        private String interfaceName;

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getInterface() {
            return interfaceName;
        }

        public void setInterface(String interfaceName) {
            this.interfaceName = interfaceName;
        }
    }

    static final class Registrar implements ImportBeanDefinitionRegistrar, EnvironmentAware,
            BeanFactoryAware, BeanClassLoaderAware {

        private Environment environment;
        private BeanFactory beanFactory;
        private ClassLoader classLoader;

        @Override
        public void setEnvironment(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void setBeanFactory(BeanFactory beanFactory) {
            this.beanFactory = beanFactory;
        }

        @Override
        public void setBeanClassLoader(ClassLoader classLoader) {
            this.classLoader = classLoader;
        }

        @Override
        public void registerBeanDefinitions(AnnotationMetadata metadata,
                                            BeanDefinitionRegistry registry) {
            Map<String, ClientProperties> clients = Binder.get(environment)
                    .bind(PREFIX, Bindable.mapOf(String.class, ClientProperties.class))
                    .orElse(Map.of());
            BeanFactory factory = beanFactory;
            for (Map.Entry<String, ClientProperties> entry : clients.entrySet()) {
                String name = entry.getKey();
                ClientProperties client = entry.getValue();
                if (client.getUrl() == null || client.getUrl().isBlank()) {
                    throw new IllegalStateException(PREFIX + "." + name + ".url is missing: "
                            + "the API's https:// URL with its secret provider");
                }
                String url = client.getUrl().trim();
                String httpBean = name + "SeclumeHttp";

                RootBeanDefinition http = new RootBeanDefinition(SeclumeHttp.class);
                http.setDestroyMethodName("close");
                http.setInstanceSupplier(() -> SeclumeHttp.of(url));
                registry.registerBeanDefinition(httpBean, http);

                RootBeanDefinition rest = new RootBeanDefinition(RestClient.class);
                rest.setInstanceSupplier(() -> restClient(factory,
                        factory.getBean(httpBean, SeclumeHttp.class), baseUrl(url)));
                registry.registerBeanDefinition(name, rest);

                if (client.getInterface() != null && !client.getInterface().isBlank()) {
                    Class<?> type = interfaceType(name, client.getInterface().trim());
                    RootBeanDefinition api = new RootBeanDefinition(type);
                    api.setInstanceSupplier(() -> HttpServiceProxyFactory
                            .builderFor(RestClientAdapter.create(
                                    factory.getBean(name, RestClient.class)))
                            .build().createClient(type));
                    registry.registerBeanDefinition(name + "HttpExchange", api);
                }
            }
        }

        private static RestClient restClient(BeanFactory factory, SeclumeHttp http,
                                             String baseUrl) {
            RestClient.Builder builder = factory.getBeanProvider(RestClient.Builder.class)
                    .getIfAvailable(RestClient::builder);
            return builder.requestFactory(new SeclumeHttpRequestFactory(http))
                    .baseUrl(baseUrl)
                    .build();
        }

        private Class<?> interfaceType(String name, String className) {
            try {
                Class<?> type = ClassUtils.forName(className, classLoader);
                if (!type.isInterface()) {
                    throw new IllegalStateException(PREFIX + "." + name + ".interface names "
                            + className + ", which is not an interface");
                }
                return type;
            } catch (ClassNotFoundException | LinkageError e) {
                throw new IllegalStateException(PREFIX + "." + name + ".interface names "
                        + className + ", which is not on the class path", e);
            }
        }

        /** The URL without its query - the origin and base path requests are made against. */
        static String baseUrl(String url) {
            int query = url.indexOf('?');
            String base = query < 0 ? url : url.substring(0, query);
            if (!base.toLowerCase(Locale.ROOT).startsWith("https://")) {
                throw new IllegalStateException("an API URL begins with https://: " + base);
            }
            return base;
        }
    }
}
