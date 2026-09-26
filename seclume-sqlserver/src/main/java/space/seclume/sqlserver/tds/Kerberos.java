package space.seclume.sqlserver.tds;

import java.lang.foreign.MemorySegment;

import space.seclume.secret.SecretProvider;

/**
 * An integrated login: no password at all, a Kerberos ticket for the
 * server's service principal instead, taken from the credentials the process
 * already has (a ticket cache from {@code kinit}, or a keytab through
 * {@code KRB5_CLIENT_KTNAME}). Stands in the place of the secret provider, as
 * {@link AccessToken} does for a token login.
 *
 * <p>The ticket and its session key stay inside the GSSAPI library; what
 * crosses the wire are Kerberos tokens, and what the server sends back is
 * checked - a login only counts once the server proved it holds the
 * service's key (mutual authentication).
 */
public final class Kerberos implements SecretProvider {

    private final String servicePrincipal;

    private Kerberos(String servicePrincipal) {
        this.servicePrincipal = servicePrincipal;
    }

    /**
     * @param servicePrincipal the server's SPN, {@code MSSQLSvc/host.example:1433},
     *                         optionally with {@code @REALM}
     */
    public static SecretProvider of(String servicePrincipal) {
        return new Kerberos(servicePrincipal);
    }

    /** Whether the login is integrated. */
    public static boolean is(SecretProvider provider) {
        return provider instanceof Kerberos;
    }

    /** The SPN the ticket is for. */
    public static String servicePrincipal(SecretProvider provider) {
        return ((Kerberos) provider).servicePrincipal;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        throw new IllegalStateException("an integrated login has no secret to write");
    }

    @Override
    public int maxSecretLength() {
        return 0;
    }
}
