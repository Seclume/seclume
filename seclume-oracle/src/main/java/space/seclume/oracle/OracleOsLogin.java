package space.seclume.oracle;

import java.lang.foreign.MemorySegment;

import space.seclume.secret.SecretProvider;

/**
 * An Oracle login by the operating system: no user and no password, the
 * system's own credentials instead. Stands in the place of the secret
 * provider, as the SQL Server driver's Kerberos does.
 *
 * <ul>
 *   <li>{@link #KERBEROS} ({@code authentication=kerberos}): a ticket from
 *       {@code kinit} or a keytab through the system's GSSAPI on Linux, from
 *       the logon session through SSPI on Windows. The login counts only
 *       once the server has proved it holds the service's key. The database
 *       user is the one the server maps the principal to
 *       ({@code IDENTIFIED EXTERNALLY AS 'alice@REALM'}).</li>
 *   <li>{@link #NTS} ({@code authentication=nts}): Oracle's Windows native
 *       authentication - NTLM through SSPI with the logon session's
 *       credentials, against a database server that runs on Windows. The
 *       database user is the Windows account
 *       ({@code IDENTIFIED EXTERNALLY}, e.g. {@code "OPS$HOST\ALICE"}). Windows
 *       only, and NTLM proves nothing about the server: prefer Kerberos where
 *       there is a domain.</li>
 * </ul>
 *
 * <p>Both exchanges run inside Oracle's advanced negotiation.
 */
public enum OracleOsLogin implements SecretProvider {

    /** Kerberos 5. */
    KERBEROS("KERBEROS5"),
    /** Windows native authentication (NTLM). */
    NTS("NTS");

    private final String service;

    OracleOsLogin(String service) {
        this.service = service;
    }

    /** The login, when {@code provider} is one; null for a password. */
    public static OracleOsLogin of(SecretProvider provider) {
        return provider instanceof OracleOsLogin login ? login : null;
    }

    /** The authentication service's name in the negotiation. */
    public String service() {
        return service;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        throw new IllegalStateException("a login by the operating system has no secret to write");
    }

    @Override
    public int maxSecretLength() {
        return 0;
    }
}
