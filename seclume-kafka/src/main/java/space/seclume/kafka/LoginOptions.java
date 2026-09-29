package space.seclume.kafka;

import java.util.LinkedHashMap;
import java.util.Map;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/** What the PLAIN and OAUTHBEARER login modules have in common with each other. */
final class LoginOptions {

    record Parsed(String username, Map<String, String> settings) {
    }

    private LoginOptions() {
    }

    /**
     * The user name, if one is needed, and every other option as a setting -
     * with the options that hold a secret refused before anything else.
     */
    static Parsed parse(String module, Map<String, ?> options, boolean needsUsername) {
        SeclumeSaslProvider.install();
        Object username = options.get("username");
        if (needsUsername && (!(username instanceof String name) || name.isEmpty())) {
            throw new IllegalArgumentException(module + " needs username=\"...\" in "
                    + "sasl.jaas.config");
        }
        Map<String, String> settings = new LinkedHashMap<>();
        for (Map.Entry<String, ?> option : options.entrySet()) {
            if (!option.getKey().equals("username") && option.getValue() instanceof String value) {
                settings.put(option.getKey(), value);
            }
        }
        if (settings.containsKey("clientSecret") || settings.containsKey("client-secret")) {
            throw new IllegalArgumentException("a client secret in sasl.jaas.config is a String "
                    + "for the life of the client - name it with provider= and its options");
        }
        return new Parsed(needsUsername ? (String) username : null, settings);
    }

    /** The secret provider the settings name; refuses {@code password=...}. */
    static SecretProvider provider(Map<String, String> settings) {
        return SecretProviders.of(settings);
    }
}
