package space.seclume.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.ref.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Hashtable;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.query.LdapQueryBuilder;

import space.seclume.tck.NoSecretInHeap;

/** JNDI and Spring LDAP bind as the service account, whose password JNDI never has. */
class LdapBindTest {

    @TempDir
    static Path directory;

    static LdapServer server;

    @BeforeAll
    static void start() throws Exception {
        server = LdapServer.start(directory);
    }

    @AfterAll
    static void stop() throws Exception {
        if (server != null) {
            server.close();
        }
    }

    private static String mailOf(DirContext context, String uid) throws Exception {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> found = context.search("", "(uid=" + uid + ")",
                controls);
        return (String) found.next().getAttributes().get("mail").get();
    }

    /** The bind is a SecretUse event - ldap, simple-bind, the server - and no password. */
    @Test
    void theBindIsRecorded() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.url());
        var events = space.seclume.tck.Recorded.during(() -> {
            DirContext context = new InitialDirContext(ldap.environment());
            context.close();
        }, "space.seclume.SecretUse");
        assertEquals(1, events.size(), events.toString());
        assertEquals("ldap", events.get(0).getString("kind"));
        assertEquals("simple-bind", events.get(0).getString("mechanism"));
    }

    @Test
    void jndiBindsAndSearches() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.url());
        DirContext context = new InitialDirContext(ldap.environment());
        try {
            assertEquals("alice@example.com", mailOf(context, "alice"));
        } finally {
            context.close();
        }
    }

    @Test
    void springLdapBindsAndSearches() {
        SeclumeLdap ldap = SeclumeLdap.of(server.url());
        LdapContextSource source = new LdapContextSource();
        source.setUrl(ldap.url());
        source.setBase(ldap.base());
        source.setUserDn(ldap.user());
        source.setPassword(ldap.password());
        source.setBaseEnvironmentProperties(ldap.socketFactory());
        source.afterPropertiesSet();
        List<String> mails = new LdapTemplate(source).search(
                LdapQueryBuilder.query().where("uid").is("alice"),
                (org.springframework.ldap.core.AttributesMapper<String>) attributes ->
                        (String) attributes.get("mail").get());
        assertEquals(List.of("alice@example.com"), mails);
    }

    @Test
    void aWrongPasswordIsRefusedByTheServer() throws Exception {
        Path wrong = directory.resolve("wrong-password");
        Files.writeString(wrong, "not-the-password");
        SeclumeLdap ldap = SeclumeLdap.of(server.url(wrong));
        assertThrows(AuthenticationException.class,
                () -> new InitialDirContext(ldap.environment()).close());
    }

    @Test
    void anEndUserBindsWithWhatTheyTyped() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.url());
        Hashtable<String, Object> environment = ldap.environment();
        environment.put(Context.SECURITY_PRINCIPAL, LdapServer.ALICE);
        environment.put(Context.SECURITY_CREDENTIALS, LdapServer.ALICE_PASSWORD);
        new InitialDirContext(environment).close();
    }

    @Test
    void onlyLdapsAndAUserAreTaken() {
        assertThrows(IllegalArgumentException.class, () -> SeclumeLdap.of(
                "ldap://localhost/dc=x?user=cn=a&provider=file&path=/x"));
        assertThrows(IllegalArgumentException.class, () -> SeclumeLdap.of(
                "ldaps://localhost/dc=x?provider=file&path=/x"));
        assertThrows(IllegalArgumentException.class, () -> SeclumeLdap.of(
                "ldaps://cn=a:secret@localhost/dc=x?user=cn=a&provider=file&path=/x"));
    }

    @Test
    void thePasswordIsNotOnTheHeap() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.url());
        for (int i = 0; i < 3; i++) {
            DirContext context = new InitialDirContext(ldap.environment());
            mailOf(context, "alice");
            context.close();
        }
        NoSecretInHeap.assertAbsent(server.password);

        String leaked = Files.readString(server.password); // the control, on the heap on purpose
        AssertionError found = assertThrows(AssertionError.class,
                () -> NoSecretInHeap.assertAbsent(server.password));
        assertTrue(found.getMessage().contains("the secret is on the heap"), found.getMessage());
        Reference.reachabilityFence(leaked);
    }
}
