package space.seclume.secret;

import java.lang.foreign.MemorySegment;

/**
 * No password, on purpose: the client certificate is the login.
 *
 * <p>PostgreSQL's {@code cert} method in {@code pg_hba.conf} and a MySQL
 * account created with an empty password and {@code REQUIRE SUBJECT} both
 * authenticate a connection by the certificate the client presented in the TLS
 * handshake and by nothing else. There is no credential to fetch, so the
 * connection says so:
 *
 * <pre>
 * provider=none
 * clientCert=/etc/tls/app.crt
 * clientKey-provider=file
 * clientKey-path=/etc/tls/app.key
 * </pre>
 *
 * <p>It is a provider rather than an absent setting because an absent setting
 * is what a mistake looks like. {@code provider=none} is a sentence someone
 * wrote down; a URL that merely forgot the password still fails with "no
 * secret provider configured".
 *
 * <p>What a driver does when the server asks for a password anyway is up to
 * the driver, and each one says it rather than sending nothing: PostgreSQL
 * refuses before anything goes out, because a server that asks has not been
 * set up for {@code cert}. MySQL sends the empty answer, because an empty
 * password is how a certificate-only account is written there.
 */
public final class NoSecretProvider implements SecretProvider {

    /** The one instance; there is nothing to configure. */
    public static final NoSecretProvider INSTANCE = new NoSecretProvider();

    private NoSecretProvider() {
    }

    /** Whether this connection was configured to log in without a password. */
    public static boolean isNone(SecretProvider provider) {
        return provider == INSTANCE;
    }

    @Override
    public int maxSecretLength() {
        return 1;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        return 0;
    }
}
