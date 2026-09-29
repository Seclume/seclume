package space.seclume.kafka;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.secret.SecretUnavailableException;

/**
 * A SASL client whose one secret goes into its first message - PLAIN's
 * password, OAUTHBEARER's token - as a placeholder: the secret is read into
 * native memory for the login, registered under the placeholder, and written
 * into the request by {@link SaslAuthenticateRewriter} as it is encrypted.
 * Kafka's buffers and the message this returns hold the placeholder only.
 */
abstract class PlaceholderClient implements SaslClient {

    private final String mechanism;
    private final SecretProvider provider;
    private String placeholder;
    private boolean complete;
    private boolean failed;

    PlaceholderClient(String mechanism, SecretProvider provider) {
        this.mechanism = mechanism;
        this.provider = provider;
    }

    /** The first message, around the placeholder. */
    abstract String initialResponse(String placeholder);

    /**
     * The server's answer to the first message: true when the login is done,
     * false when it asked for one more message, which is then {@link #afterFailure}.
     */
    boolean accepts(byte[] challenge) {
        return challenge == null || challenge.length == 0;
    }

    byte[] afterFailure() {
        return null;
    }

    /** For a mechanism that is done once its first message has gone. */
    boolean completeAfterInitialResponse() {
        return false;
    }

    @Override
    public String getMechanismName() {
        return mechanism;
    }

    @Override
    public boolean hasInitialResponse() {
        return true;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        if (placeholder == null) {
            if (!SeclumeSslEngineFactory.configured()) {
                throw new SaslException(mechanism + " through seclume sends its secret only over "
                        + "seclume's TLS: set security.protocol=SASL_SSL and "
                        + "ssl.engine.factory.class=" + SeclumeSslEngineFactory.class.getName());
            }
            SecretScope secret;
            try {
                secret = readShared(provider);
            } catch (SecretUnavailableException e) {
                failed = true;
                throw new SaslException(mechanism + " login failed: " + e.getMessage(), e);
            }
            placeholder = SaslPlaceholders.register(secret);
            complete = completeAfterInitialResponse();
            return initialResponse(placeholder).getBytes(StandardCharsets.UTF_8); // seclume-allow: the message around the placeholder; the secret is not in it
        }
        if (complete || failed) {
            throw new SaslException(mechanism + " expects no further challenge");
        }
        if (accepts(challenge)) {
            complete = true;
            return null;
        }
        failed = true;
        return afterFailure();
    }

    @Override
    public boolean isComplete() {
        return complete;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
        throw new IllegalStateException(mechanism + " has no security layer");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
        throw new IllegalStateException(mechanism + " has no security layer");
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (!complete) {
            throw new IllegalStateException("the " + mechanism + " login has not completed");
        }
        return null;
    }

    /** The secret, should the request never have gone out: wiped. */
    @Override
    public void dispose() {
        if (placeholder != null) {
            SecretScope unused = SaslPlaceholders.take(placeholder);
            if (unused != null) {
                unused.close();
            }
        }
    }

    /** Read on the thread of the login, taken up on the one that encrypts - so shared. */
    private static SecretScope readShared(SecretProvider provider) {
        try (SecretScope read = SecretScope.fromProvider(provider)) {
            SecretScope shared = SecretScope.allocateShared(Math.max(1, read.length()));
            MemorySegment.copy(read.segment(), 0, shared.segment(), 0, read.length());
            shared.length(read.length());
            return shared;
        }
    }
}
