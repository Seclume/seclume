package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.mail.Session;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.mail.autoconfigure.MailSenderAutoConfiguration;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import space.seclume.mail.SeclumeImapStore;
import space.seclume.mail.SeclumeTransport;

/**
 * Mail from properties alone: {@code seclume.mail.send} and
 * {@code seclume.mail.read} make the Session and the JavaMailSender, Boot's
 * own mail sender steps aside, and {@code spring.mail.password} is refused.
 * No server is needed - that the session logs in and delivers is
 * seclume-mail's own tests (SpringJavaMailSenderTest among them).
 */
class MailAutoConfigurationTest {

    private static final String SEND =
            "smtps://mail.example.com?user=reports&provider=file&path=/run/secrets/mail";
    private static final String READ =
            "imaps://mail.example.com?user=reports&provider=file&path=/run/secrets/mail";

    private static AnnotationConfigApplicationContext context(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("test", properties));
        // Boot's order: ours first, as @AutoConfiguration(before=...) says
        for (Class<?> configuration : AutoConfigurations.getClasses(AutoConfigurations.of(
                SeclumeMailAutoConfiguration.class, MailSenderAutoConfiguration.class))) {
            context.register(configuration);
        }
        context.refresh();
        return context;
    }

    @Test
    void propertiesAloneMakeTheSenderAndTheStore() throws Exception {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.mail.send", SEND);
        properties.put("seclume.mail.read", READ);
        properties.put("spring.mail.properties.mail.debug", "false");
        // Boot's own sender would be made from this - and is not
        properties.put("spring.mail.host", "legacy.example.com");
        try (AnnotationConfigApplicationContext context = context(properties)) {
            Session session = context.getBean(Session.class);
            JavaMailSender sender = context.getBean(JavaMailSender.class);
            assertTrue(sender instanceof JavaMailSenderImpl);
            assertSame(session, ((JavaMailSenderImpl) sender).getSession());
            assertTrue(session.getTransport() instanceof SeclumeTransport);
            assertTrue(session.getStore() instanceof SeclumeImapStore);
            assertEquals("false", session.getProperty("mail.debug"));
            assertEquals(1, context.getBeansOfType(JavaMailSender.class).size());
        }
    }

    @Test
    void readingAloneMakesASessionButNoSender() throws Exception {
        try (AnnotationConfigApplicationContext context = context(
                Map.of("seclume.mail.read", READ))) {
            assertTrue(context.getBean(Session.class).getStore() instanceof SeclumeImapStore);
            assertTrue(context.getBeansOfType(JavaMailSender.class).isEmpty());
        }
    }

    @Test
    void withoutTheUrlsNothingHappens() {
        try (AnnotationConfigApplicationContext context = context(
                Map.of("spring.mail.host", "legacy.example.com"))) {
            assertTrue(context.getBeansOfType(Session.class).isEmpty());
            // Boot's sender, untouched
            JavaMailSenderImpl boot = (JavaMailSenderImpl) context.getBean(JavaMailSender.class);
            assertEquals("legacy.example.com", boot.getHost());
            assertFalse(boot.getSession().getProperties()
                    .containsKey("space.seclume.mail.settings.smtp"));
        }
    }

    @Test
    void springMailPasswordIsRefused() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("seclume.mail.send", SEND);
        properties.put("spring.mail.password", "hunter2");
        BeanCreationException e = assertThrows(BeanCreationException.class,
                () -> context(properties).close());
        Throwable cause = e;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        assertTrue(cause.getMessage().contains("Remove spring.mail.password"), cause.getMessage());
    }
}
