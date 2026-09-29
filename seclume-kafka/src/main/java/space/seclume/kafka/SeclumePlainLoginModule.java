package space.seclume.kafka;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

/**
 * The JAAS login module for Kafka's SASL/PLAIN that names where the password
 * comes from instead of the password:
 *
 * <pre>
 * security.protocol=SASL_SSL
 * ssl.engine.factory.class=space.seclume.kafka.SeclumeSslEngineFactory
 * sasl.mechanism=PLAIN
 * sasl.jaas.config=space.seclume.kafka.SeclumePlainLoginModule required \
 *     username="orders" provider="file" path="/run/secrets/kafka";
 * </pre>
 *
 * <p>Kafka's own {@code PlainLoginModule} keeps {@code password="..."} as a
 * {@code String} in the configuration and the JAAS subject, and PLAIN then
 * sends it as it is - through Kafka's request buffer and JSSE's, all heap.
 * Here Kafka is given a placeholder, and {@link SeclumeSslEngineFactory}'s
 * engine writes the password, read for this login into native memory, in
 * its place as the request is encrypted. That is why this module needs
 * {@code SASL_SSL} with that engine factory, and refuses to log in without
 * it: PLAIN over anything else sends the password in the clear anyway.
 *
 * <p>The options other than {@code username} are a secret provider's, as in
 * a seclume JDBC URL ({@code file}, {@code vault}, {@code aws-secrets-manager},
 * ...). The password is read again at every login, so a rotated one takes
 * effect without a restart. Confluent Cloud's API key is the user name and
 * its secret the password.
 */
public final class SeclumePlainLoginModule implements LoginModule {

    /** For JAAS, which makes one per login context. */
    public SeclumePlainLoginModule() {
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {
        LoginOptions.Parsed parsed = LoginOptions.parse("SeclumePlainLoginModule", options, true);
        subject.getPublicCredentials().add(parsed.username());
        subject.getPublicCredentials().add(new LoginSecret("PLAIN",
                LoginOptions.provider(parsed.settings()), Map.of()));
    }

    @Override
    public boolean login() {
        return true;
    }

    @Override
    public boolean commit() {
        return true;
    }

    @Override
    public boolean abort() {
        return false;
    }

    @Override
    public boolean logout() {
        return true;
    }
}
