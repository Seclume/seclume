package space.seclume.micronaut;

import io.micronaut.context.annotation.Factory;
import jakarta.inject.Singleton;

import space.seclume.field.FieldKeys;

/** {@link FieldKeys} to inject - the ring {@link SeclumeFieldEncryption} built. */
@Factory
public class SeclumeFieldKeysFactory {

    @Singleton
    public FieldKeys fieldKeys(SeclumeFieldEncryption encryption) {
        FieldKeys keys = encryption.keys();
        if (keys == null) {
            throw new IllegalStateException("no field encryption keys are configured: "
                    + SeclumeFieldEncryption.PREFIX + ".keys.<number>.<provider setting>");
        }
        return keys;
    }
}
