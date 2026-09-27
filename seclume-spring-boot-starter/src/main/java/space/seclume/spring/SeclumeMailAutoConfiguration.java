package space.seclume.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import jakarta.mail.Session;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import space.seclume.mail.SeclumeMail;

/**
 * Mail from {@code application.properties}, with the password or the OAuth
 * token off the heap:
 *
 * <pre>
 * seclume.mail.send=smtps://mail.example.com?user=reports&amp;provider=file&amp;path=/run/secrets/mail
 * seclume.mail.read=imaps://mail.example.com?user=reports&amp;provider=file&amp;path=/run/secrets/mail
 * </pre>
 *
 * <p>That is a {@link Session} made by {@link SeclumeMail#session} - in which
 * {@code smtp(s)}, {@code imap(s)} and {@code pop3(s)} are seclume's - and,
 * with a sending URL, a {@link JavaMailSender} on it. Boot's own
 * {@code MailSenderAutoConfiguration} sees the sender and steps aside, so
 * {@code @Autowired JavaMailSender} is this one. {@code spring.mail.properties.*}
 * (say {@code mail.debug}) still reach the session.
 *
 * <p>{@code spring.mail.password} is refused while this is on: it would be a
 * {@code String} in the {@code Environment} for as long as the application
 * runs - and not be used.
 */
@AutoConfiguration(beforeName = "org.springframework.boot.mail.autoconfigure.MailSenderAutoConfiguration")
@ConditionalOnClass(name = {"space.seclume.mail.SeclumeMail", "jakarta.mail.Session"})
@Conditional(SeclumeMailAutoConfiguration.OnMailUrl.class)
public class SeclumeMailAutoConfiguration {

    static final String SEND = "seclume.mail.send";
    static final String READ = "seclume.mail.read";

    @Bean
    @ConditionalOnMissingBean(Session.class)
    public Session seclumeMailSession(Environment environment) {
        if (environment.containsProperty("spring.mail.password")) {
            throw new IllegalStateException("spring.mail.password is set, and seclume.mail."
                    + "send/read as well. The password would be a String in the Environment "
                    + "for as long as the application runs, and it is not used: seclume logs "
                    + "in with the secret the URL names (provider=...). Remove "
                    + "spring.mail.password");
        }
        List<String> urls = new ArrayList<>();
        for (String name : List.of(SEND, READ)) {
            String url = environment.getProperty(name);
            if (url != null && !url.isBlank()) {
                urls.add(url.trim());
            }
        }
        Properties base = new Properties();
        base.putAll(Binder.get(environment).bind("spring.mail.properties",
                Bindable.mapOf(String.class, String.class)).orElse(Map.of()));
        return SeclumeMail.session(base, urls.toArray(String[]::new));
    }

    /** The sender - only where Spring's mail support is and a sending URL is set. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.mail.javamail.JavaMailSenderImpl")
    @ConditionalOnProperty(SEND)
    static class SenderConfiguration {

        @Bean
        @ConditionalOnMissingBean(JavaMailSender.class)
        JavaMailSenderImpl mailSender(Session seclumeMailSession) {
            JavaMailSenderImpl sender = new JavaMailSenderImpl();
            sender.setSession(seclumeMailSession);
            return sender;
        }
    }

    /** {@code seclume.mail.send} or {@code seclume.mail.read}, either will do. */
    static final class OnMailUrl implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            Environment environment = context.getEnvironment();
            return environment.containsProperty(SEND) || environment.containsProperty(READ);
        }
    }
}
