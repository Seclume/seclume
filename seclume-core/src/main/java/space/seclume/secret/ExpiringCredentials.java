package space.seclume.secret;

import java.time.Instant;

/**
 * A credential that stops working at a known moment.
 *
 * <p>Static passwords do not need this. Dynamic ones do: HashiCorp Vault's
 * database engine hands out a database user that exists for an hour, AWS RDS
 * IAM signs a token good for fifteen minutes, and cloud secret managers are
 * moving the same way. What they have in common is that the credential a
 * connection was opened with <b>expires while the connection is still in the
 * pool</b>.
 *
 * <p>What normally happens then is that nothing happens - until the pool hands
 * out a connection the server has since disowned, or opens a new one with a
 * password that has just lapsed, and an application sees an authentication
 * failure in the middle of a working day for no reason it can see. The usual
 * answer is to set {@code maxLifetime} shorter than the TTL by hand, in a
 * second place, and to remember to change it when the TTL changes.
 *
 * <p>This is the other answer: the credential says when it stops, and the pool
 * retires connections before that. It is the half of dynamic credentials
 * nobody ships, and it is what turns them from a liability into something
 * worth switching on.
 *
 * <p>Implemented by providers that know ({@code VaultSecretProvider}) and by
 * the drivers' {@code DataSource}s, which only pass the question on to their
 * provider - so a pool can ask its source without knowing what kind of secret
 * is underneath.
 */
public interface ExpiringCredentials {

    /**
     * When the credential a connection would be opened with right now stops
     * being accepted, or {@code null} if it does not expire.
     *
     * <p>{@code null} is the honest answer for a password in a file, and the
     * only safe default: a caller that reads it as "never" behaves exactly as
     * it did before this interface existed.
     */
    Instant credentialsValidUntil();
}
