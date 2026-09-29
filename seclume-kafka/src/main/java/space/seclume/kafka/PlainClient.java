package space.seclume.kafka;

import space.seclume.secret.SecretProvider;

/**
 * SASL PLAIN (RFC 4616): {@code \0user\0password} in one message - with the
 * placeholder where the password goes.
 */
final class PlainClient extends PlaceholderClient {

    private final String username;

    PlainClient(String username, SecretProvider provider) {
        super("PLAIN", provider);
        if (username.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("a PLAIN user name cannot hold a NUL");
        }
        this.username = username;
    }

    @Override
    String initialResponse(String placeholder) {
        return "\0" + username + "\0" + placeholder;
    }

    @Override
    boolean completeAfterInitialResponse() {
        return true;
    }
}
