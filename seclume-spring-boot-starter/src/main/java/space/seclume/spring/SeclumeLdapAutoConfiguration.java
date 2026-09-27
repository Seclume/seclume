package space.seclume.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.ldap.core.support.LdapContextSource;

import space.seclume.ldap.SeclumeLdap;

/**
 * LDAP and Active Directory with the bind password off the heap:
 *
 * <pre>
 * seclume.ldap.url=ldaps://ad.example.com/dc=example,dc=com?user=svc-app@example.com&amp;provider=file&amp;path=/run/secrets/ldap
 * </pre>
 *
 * <p>An {@link LdapContextSource} bean whose URL, base and user are the URL's
 * and whose password is seclume's placeholder; the socket factory writes the
 * real one (see {@link SeclumeLdap}). Spring Boot's own LDAP configuration
 * steps aside for it and makes its {@code LdapTemplate} on it, and Spring
 * Security's LDAP authentication takes it as its context source.
 */
@AutoConfiguration
@AutoConfigureBefore(name = "org.springframework.boot.ldap.autoconfigure.LdapAutoConfiguration")
@ConditionalOnClass(name = {"space.seclume.ldap.SeclumeLdap",
        "org.springframework.ldap.core.support.LdapContextSource"})
@ConditionalOnProperty("seclume.ldap.url")
public class SeclumeLdapAutoConfiguration {

    @Bean
    public LdapContextSource ldapContextSource(Environment environment) {
        SeclumeLdap ldap = SeclumeLdap.of(environment.getRequiredProperty("seclume.ldap.url"));
        LdapContextSource source = new LdapContextSource();
        source.setUrl(ldap.url());
        source.setBase(ldap.base());
        source.setUserDn(ldap.user());
        source.setPassword(ldap.password());
        source.setBaseEnvironmentProperties(ldap.socketFactory());
        return source;
    }
}
