package space.seclume.spring;

import java.util.regex.Pattern;

import org.springframework.core.env.Environment;

/**
 * Spring Boot's own settings that carry a password, refused while seclume
 * configures the same client: the password would be a {@code String} in the
 * {@code Environment} for as long as the application runs - in every heap
 * dump, and in the Actuator's {@code /env} - and it would not even be used.
 */
final class InlineSecrets {

    /** {@code scheme://user:password@...} - a password in a connection URI. */
    private static final Pattern PASSWORD_IN_URI = Pattern.compile("://[^/@?#]*:[^/@?#]*@");

    private InlineSecrets() {
    }

    /**
     * @param setting   seclume's setting that is on, for the message
     * @param passwords Spring's password settings
     * @param uris      Spring's URI settings, refused only with a password in them
     */
    static void refuse(Environment environment, String setting, String[] passwords,
                       String... uris) {
        for (String key : passwords) {
            if (environment.containsProperty(key)) {
                throw new IllegalStateException(key + " is set, and " + setting + " as well. "
                        + "The password would be a String in the Environment for as long as "
                        + "the application runs, and it is not used: seclume logs in with the "
                        + "secret the URL names (provider=...). Remove " + key);
            }
        }
        for (String key : uris) {
            String uri = environment.getProperty(key);
            if (uri != null && PASSWORD_IN_URI.matcher(uri).find()) {
                throw new IllegalStateException(key + " carries a password, and " + setting
                        + " is set as well. That password is a String in the Environment, and "
                        + "it is not used. Remove " + key);
            }
        }
    }
}
