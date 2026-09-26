package space.seclume.kafka;

import space.seclume.secret.SecretProvider;

/**
 * Where a login's password comes from - kept in the JAAS subject beside the
 * user name, as Kafka's own login module keeps the password there. It holds
 * the provider, never the secret.
 */
record ScramSecret(SecretProvider provider) {

    @Override
    public String toString() {
        return "ScramSecret[" + provider.getClass().getSimpleName() + "]";
    }
}
