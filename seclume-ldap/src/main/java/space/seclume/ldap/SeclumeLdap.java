package space.seclume.ldap;

import java.util.Hashtable;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import javax.naming.Context;

/**
 * LDAP and Active Directory with the bind password off the heap.
 *
 * <pre>
 * SeclumeLdap ldap = SeclumeLdap.of("ldaps://ad.example.com/dc=example,dc=com"
 *         + "?user=svc-app@example.com&amp;provider=file&amp;path=/run/secrets/ldap");
 *
 * // JNDI
 * DirContext context = new InitialDirContext(ldap.environment());
 *
 * // Spring LDAP / Spring Security's LDAP support
 * LdapContextSource source = new LdapContextSource();
 * source.setUrl(ldap.url());
 * source.setBase(ldap.base());
 * source.setUserDn(ldap.user());
 * source.setPassword(ldap.password());                       // the placeholder
 * source.setBaseEnvironmentProperties(ldap.socketFactory());
 * </pre>
 *
 * <p>JNDI is given a placeholder as the password and seclume's socket
 * factory. The socket encrypts with seclume's own TLS 1.3, and in the simple
 * bind whose password is the placeholder it writes the real one - read from
 * the secret provider into native memory - and the BER lengths that follow
 * from it. Everything else JNDI sends and receives goes through unchanged,
 * including binds with other passwords: an end user logging in through
 * Spring Security binds with the password they typed, which is theirs to
 * have on the heap.
 *
 * <p>{@code ldaps://} only; StartTLS and SASL binds are not supported. The
 * service account's password is the one protected - which is the one that
 * lives as long as the application does.
 */
public final class SeclumeLdap {

    /** What JNDI holds instead of the password, followed by the registration's id. */
    static final String PLACEHOLDER_PREFIX = "seclume-ldap-binds-in-native-memory:";

    private static final AtomicLong IDS = new AtomicLong();
    static final Map<String, LdapSettings> BY_PLACEHOLDER = new ConcurrentHashMap<>();
    static final Map<String, LdapSettings> BY_AUTHORITY = new ConcurrentHashMap<>();

    private final LdapSettings settings;
    private final String placeholder;

    private SeclumeLdap(LdapSettings settings, String placeholder) {
        this.settings = settings;
        this.placeholder = placeholder;
    }

    /** Reads the URL and registers it with the socket factory. */
    public static SeclumeLdap of(String url) {
        LdapSettings settings = LdapSettings.of(url);
        LdapSettings earlier = BY_AUTHORITY.putIfAbsent(settings.authority(), settings);
        if (earlier != null && !Objects.equals(String.valueOf(earlier.trust),
                String.valueOf(settings.trust))) {
            throw new IllegalArgumentException(settings.authority() + " is already set up with "
                    + "another tlsRootCert/tlsPin; one server has one certificate");
        }
        String placeholder = PLACEHOLDER_PREFIX + IDS.incrementAndGet();
        BY_PLACEHOLDER.put(placeholder, settings);
        return new SeclumeLdap(settings, placeholder);
    }

    /** {@code ldaps://host:port} - for a context source's URL. */
    public String url() {
        return "ldaps://" + settings.authority();
    }

    /** The base DN from the URL's path, or empty. */
    public String base() {
        return settings.base;
    }

    /** The bind DN. */
    public String user() {
        return settings.user;
    }

    /** The placeholder to give as the password - never the password. */
    public String password() {
        return placeholder;
    }

    /** Only the socket factory - to add to an environment built elsewhere. */
    public Map<String, Object> socketFactory() {
        return Map.of("java.naming.ldap.factory.socket", SeclumeLdapSocketFactory.class.getName(),
                "com.sun.jndi.ldap.connect.timeout", String.valueOf(settings.connectTimeout),
                "com.sun.jndi.ldap.read.timeout", String.valueOf(settings.timeout));
    }

    /** A complete JNDI environment: URL with base, simple bind as the user, the socket factory. */
    public Hashtable<String, Object> environment() {
        Hashtable<String, Object> environment = new Hashtable<>(socketFactory());
        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, url() + "/"
                + settings.base.replace(" ", "%20"));
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        environment.put(Context.SECURITY_PRINCIPAL, settings.user);
        environment.put(Context.SECURITY_CREDENTIALS, placeholder);
        return environment;
    }

    @Override
    public String toString() {
        return url() + " as " + settings.user;
    }
}
