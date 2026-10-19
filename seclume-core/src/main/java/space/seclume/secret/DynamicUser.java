package space.seclume.secret;

/**
 * A secret that comes with its own user: Vault's database engine creates a
 * new database user for each credential it hands out, so the password alone
 * logs in nobody - the user name of the same answer belongs to it.
 *
 * <p>The user name is not a secret and is a {@code String}. A driver asks for
 * it once per login, right before it reads the password: the provider then
 * keeps the two together - it renews or replaces the credential when it is
 * asked for the user, not between that and the password.
 */
public interface DynamicUser {

    /**
     * The user the credential belongs to, or {@code null} when the secret is
     * a password alone and the configured user is the one.
     */
    String currentUser();

    /** The user a login goes out with: the secret's own, or else the configured one. */
    static String loginUser(String configured, SecretProvider secret) {
        if (secret instanceof DynamicUser dynamic) {
            String user = dynamic.currentUser();
            if (user != null && !user.isEmpty()) {
                return user;
            }
        }
        return configured;
    }
}
