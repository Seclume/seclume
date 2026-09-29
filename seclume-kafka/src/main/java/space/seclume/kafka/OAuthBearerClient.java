package space.seclume.kafka;

import java.util.Map;

import space.seclume.secret.SecretProvider;

/**
 * SASL OAUTHBEARER (RFC 7628) as Kafka speaks it:
 * {@code n,,^Aauth=Bearer <token>[^Akey=value...]^A^A} - with the placeholder
 * where the token goes. The broker answers nothing when it takes the token,
 * and a JSON error when it does not, to which the client answers {@code ^A}
 * and the broker then fails the login with its reason.
 */
final class OAuthBearerClient extends PlaceholderClient {

    private static final char SEPARATOR = '\u0001';

    private final Map<String, String> extensions;

    OAuthBearerClient(SecretProvider provider, Map<String, String> extensions) {
        super("OAUTHBEARER", provider);
        this.extensions = extensions;
    }

    @Override
    String initialResponse(String placeholder) {
        StringBuilder message = new StringBuilder("n,,").append(SEPARATOR) // seclume-allow: the message around the placeholder
                .append("auth=Bearer ").append(placeholder);
        for (Map.Entry<String, String> extension : extensions.entrySet()) {
            message.append(SEPARATOR).append(extension.getKey()).append('=')
                    .append(extension.getValue());
        }
        return message.append(SEPARATOR).append(SEPARATOR).toString();
    }

    @Override
    byte[] afterFailure() {
        return new byte[] {SEPARATOR};
    }
}
