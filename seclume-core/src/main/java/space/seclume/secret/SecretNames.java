package space.seclume.secret;

/**
 * The names a cloud secret store is asked for, checked before they go into a
 * request path.
 *
 * <p>Key Vault allows letters, digits and dashes in a secret's name, Secret
 * Manager letters, digits, dashes and underscores, and a project id is of the
 * same kind; versions are numbers, hex or {@code latest}. A name outside that
 * - a slash, a {@code ?}, a {@code ..}, a line break - is not a name but a
 * different request, made with the application's token.
 */
final class SecretNames {

    private SecretNames() {
    }

    /**
     * {@code value}, if it is a plain name.
     *
     * @param optional whether null or empty is allowed - and then returned as given
     */
    static String require(String what, String value, boolean optional) {
        if (value == null || value.isEmpty()) {
            if (optional) {
                return value;
            }
            throw new IllegalArgumentException(what + " is missing");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!plain) {
                throw new IllegalArgumentException(what + " has a character a secret store "
                        + "does not use in a name: letters, digits, '-' and '_' only");
            }
        }
        return value;
    }
}
