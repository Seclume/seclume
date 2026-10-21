package space.seclume.postgresql;

import java.sql.SQLInvalidAuthorizationSpecException;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * libpq's {@code require_auth}: which login methods the server may ask for.
 *
 * <p>Which method a login uses is the server's choice, made in
 * {@code pg_hba.conf} - a client that answers whatever it is asked sends an
 * {@code md5} hash to a server configured for it, or to anybody in the middle
 * who asks for one. {@code requireAuth=scram-sha-256} refuses everything else
 * before a byte of the answer leaves; {@code requireAuth=!md5,!password} refuses
 * only those. The names and the rules are libpq's: {@code password},
 * {@code md5}, {@code gss}, {@code sspi}, {@code scram-sha-256}, {@code oauth}
 * and {@code none} (the server asks for nothing), all positive or all negated.
 */
public final class RequireAuth {

    /** No restriction - what a URL without the option means. */
    public static final RequireAuth ANY = new RequireAuth(null, Set.of(), true);

    private static final Set<String> METHODS = Set.of("password", "md5", "gss", "sspi",
            "scram-sha-256", "oauth", "none");

    private final String spec;
    private final Set<String> methods;
    private final boolean negated;

    private RequireAuth(String spec, Set<String> methods, boolean negated) {
        this.spec = spec;
        this.methods = methods;
        this.negated = negated;
    }

    /**
     * Parses the option; null or blank is {@link #ANY}.
     *
     * @throws IllegalArgumentException for an unknown method, a method named
     *                                  twice, or positive and negated mixed
     */
    public static RequireAuth of(String value) {
        if (value == null || value.isBlank()) {
            return ANY;
        }
        Set<String> methods = new LinkedHashSet<>();
        String[] parts = value.split(",", -1);
        boolean negated = parts[0].strip().startsWith("!");     // the first says which kind
        for (String part : parts) {
            String method = part.strip().toLowerCase(Locale.ROOT);
            boolean not = method.startsWith("!");
            if (not) {
                method = method.substring(1).strip();
            }
            if (not != negated) {
                throw new IllegalArgumentException("requireAuth=" + value + " mixes methods "
                        + "and negated methods - it is all of one kind, as in libpq");
            }
            if (!METHODS.contains(method)) {
                throw new IllegalArgumentException("requireAuth names '" + part.strip()
                        + "' - it knows password, md5, gss, sspi, scram-sha-256, oauth and none");
            }
            if (!methods.add(method)) {
                throw new IllegalArgumentException("requireAuth names " + method + " twice");
            }
        }
        return new RequireAuth(value.strip(), Set.copyOf(methods), negated);
    }

    /** Whether the server may log this connection in by {@code method}. */
    public boolean allows(String method) {
        return negated != methods.contains(method);
    }

    /**
     * Refuses a method the option does not allow - before anything of the
     * answer is sent.
     */
    public void check(String method) throws SQLInvalidAuthorizationSpecException {
        if (!allows(method)) {
            throw new SQLInvalidAuthorizationSpecException("the server asks for "
                    + ("none".equals(method) ? "no authentication at all"
                       : method + " authentication")
                    + ", which requireAuth=" + spec + " does not allow; nothing was sent",
                    "28000");
        }
    }

    @Override
    public String toString() {
        return spec == null ? "" : spec;
    }
}
