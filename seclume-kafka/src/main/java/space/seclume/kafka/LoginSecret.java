package space.seclume.kafka;

import java.util.Map;

import space.seclume.secret.SecretProvider;

/**
 * Where a PLAIN password or an OAUTHBEARER token comes from - kept in the
 * JAAS subject beside the user name, as {@link ScramSecret} is for SCRAM. It
 * holds the provider, never the secret.
 *
 * @param mechanism  {@code PLAIN} or {@code OAUTHBEARER}
 * @param extensions OAUTHBEARER's SASL extensions, sent beside the token; public
 */
record LoginSecret(String mechanism, SecretProvider provider, Map<String, String> extensions) {

    LoginSecret {
        extensions = Map.copyOf(extensions);
    }

    @Override
    public String toString() {
        return "LoginSecret[" + mechanism + ", " + provider.getClass().getSimpleName() + "]";
    }
}
