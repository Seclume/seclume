package space.seclume.ldap;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.util.Hashtable;

import javax.naming.AuthenticationException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The service account's placeholder, read from a heap dump and typed into a
 * login form whose user name maps to the service account's DN, logged the
 * attacker in as the service account: on the wire a user's bind looks like
 * the context source's own. A placeholder made serviceBindsOnly() becomes
 * the password only in binds opened through SeclumeLdap.asService.
 */
class ServiceBindTest {

    @TempDir
    static Path directory;

    static LdapServer server;

    @BeforeAll
    static void start() throws Exception {
        server = LdapServer.start(directory);
    }

    @AfterEach
    void forgetTheServersOfThisTest() {
        SeclumeLdap.BY_AUTHORITY.clear();
    }

    @AfterAll
    static void stop() throws Exception {
        if (server != null) {
            server.close();
        }
    }

    @Test
    void theApplicationsOwnBindIsAnswered() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.url()).serviceBindsOnly();
        DirContext context = SeclumeLdap.asService(() -> new InitialDirContext(ldap.environment()));
        context.close();
    }

    @Test
    void thePlaceholderTypedIntoALoginIsRefused() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.url()).serviceBindsOnly();
        // What a login form's bind looks like: the DN the user name maps to,
        // and what was typed as the password - the placeholder.
        Hashtable<String, Object> login = ldap.environment();
        login.put(javax.naming.Context.SECURITY_PRINCIPAL, ldap.user());
        login.put(javax.naming.Context.SECURITY_CREDENTIALS, ldap.password());
        assertThrows(AuthenticationException.class, () -> new InitialDirContext(login).close());
    }

    @Test
    void withoutTheMarkThePlaceholderWorksAsBefore() throws Exception {
        SeclumeLdap ldap = SeclumeLdap.of(server.url());
        new InitialDirContext(ldap.environment()).close();       // the control
    }
}
