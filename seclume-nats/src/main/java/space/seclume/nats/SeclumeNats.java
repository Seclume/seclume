package space.seclume.nats;

import java.io.IOException;
import java.time.Duration;

import io.nats.client.AuthHandler;
import io.nats.client.Connection;
import io.nats.client.Nats;
import io.nats.client.Options;

/**
 * NATS ({@code io.nats:jnats}) with the NKey seed, {@code .creds} file,
 * password or token off the heap:
 *
 * <pre>
 * // NKey challenge-response or .creds (JWT + NKey seed) over TLS 1.3:
 * try (Connection nc = SeclumeNats.connect(
 *         "tls://nats.example.com:4222?auth=creds&amp;provider=file&amp;path=/run/secrets/user.creds")) {
 *     nc.publish("orders.created", payload);
 * }
 *
 * // Or as a standalone AuthHandler on your own Options.Builder:
 * AuthHandler auth = SeclumeNats.authHandler("provider=file&amp;path=/run/secrets/user.nk");
 *
 * // Password or token login written into CONNECT from native memory over TLS 1.3:
 * try (Connection nc = SeclumeNats.connect(
 *         "tls://nats.example.com:4222?user=app&amp;provider=file&amp;path=/run/secrets/nats-password")) {
 *     ...
 * }
 * </pre>
 *
 * <p>The official client's {@code Nats.credentials(...)} and {@code NKey} read
 * the Base32 Ed25519 seed into a {@code byte[]} and a {@code char[]} on the
 * heap, decode the 32-byte seed into another {@code byte[]}, and pass it to
 * BouncyCastle or JCA; password and token logins keep the secret in
 * {@link Options} for the life of the connection and format {@code CONNECT} in
 * a {@code CharBuffer} on the heap.
 *
 * <p>Here:
 * <ul>
 *   <li>for {@code auth=nkey} and {@code auth=creds}, {@link SeclumeNatsAuthHandler}
 *       reads the seed or {@code .creds} file from its {@link space.seclume.secret.SecretProvider}
 *       into a {@link space.seclume.secret.SecretScope}, decodes Base32 and
 *       verifies the CRC-16 in a confined off-heap arena, and signs the
 *       server's nonce with {@link space.seclume.crypto.Ed25519} in native
 *       memory. Only the public key ({@code U...}), the user JWT, and the
 *       64-byte signature reach the heap;
 *   <li>for {@code user=} (password) and {@code auth=token}, {@link Options}
 *       is given a placeholder and {@link SeclumeNatsDataPort} writes the real
 *       secret from native memory into the {@code CONNECT} line on its way into
 *       seclume's own TLS 1.3 cipher.
 * </ul>
 */
public final class SeclumeNats {

    /** What the client is given where it wants a password or token. Not a secret; never sent. */
    static final String PLACEHOLDER = "seclume-nats-logs-in-itself";
    private static final char[] PLACEHOLDER_CHARS = PLACEHOLDER.toCharArray(); // seclume-allow: the placeholder, not a secret

    private SeclumeNats() {
    }

    /**
     * An {@link AuthHandler} that reads an NKey seed (for example
     * {@code SU...}) or a NATS {@code .creds} file from the secret provider
     * named by {@code secretSpec} and signs server challenges in native memory.
     */
    public static AuthHandler authHandler(String secretSpec) {
        return new SeclumeNatsAuthHandler(NatsSettings.providerOf(secretSpec), null, "");
    }

    /**
     * An {@link AuthHandler} that reads the user JWT from {@code jwtSpec} and
     * the NKey seed from {@code seedSpec}, signing server challenges in native
     * memory.
     */
    public static AuthHandler authHandler(String jwtSpec, String seedSpec) {
        return new SeclumeNatsAuthHandler(
                NatsSettings.providerOf(seedSpec),
                NatsSettings.providerOf(jwtSpec),
                "");
    }

    /**
     * Configures {@code builder} from a seclume NATS URL (server, TLS, data
     * port, timeouts, and authentication) and returns {@code builder} so the
     * caller may set listeners, reconnect policies or buffer sizes before
     * calling {@link #build(Options.Builder, String)}.
     */
    public static Options.Builder configure(Options.Builder builder, String url) {
        return apply(builder, NatsSettings.of(url));
    }

    /**
     * Builds {@link Options} for {@code url}, with {@link SeclumeNatsDataPort}
     * registered to carry the connection over seclume's TLS 1.3 and native
     * memory login.
     */
    public static Options options(String url) {
        return build(new Options.Builder(), url);
    }

    /**
     * Builds {@link Options} from a caller-supplied {@link Options.Builder}
     * together with {@code url}.
     */
    public static Options build(Options.Builder builder, String url) {
        NatsSettings settings = NatsSettings.of(url);
        apply(builder, settings);
        Options built = builder.build();
        SeclumeNatsDataPort.register(built, settings);
        return built;
    }

    /**
     * Opens a NATS {@link Connection} configured by {@code url}.
     */
    public static Connection connect(String url) throws IOException, InterruptedException {
        return Nats.connect(options(url));
    }

    private static Options.Builder apply(Options.Builder builder, NatsSettings settings) {
        builder.server(settings.serverUri())
                .dataPortType(SeclumeNatsDataPort.class.getName())
                .connectionTimeout(Duration.ofMillis(Math.max(settings.connectTimeout, 1)))
                .socketReadTimeoutMillis(settings.timeout);
        if (settings.tls) {
            try {
                builder.secure();
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
        switch (settings.mode) {
            case PASSWORD -> builder.userInfo(settings.user.toCharArray(), PLACEHOLDER_CHARS.clone());
            case TOKEN -> builder.token(PLACEHOLDER_CHARS.clone());
            case NKEY, CREDS -> builder.authHandler(
                    new SeclumeNatsAuthHandler(settings.secret, null, settings.target()));
        }
        return builder;
    }
}
