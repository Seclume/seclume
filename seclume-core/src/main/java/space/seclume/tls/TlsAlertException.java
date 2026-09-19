package space.seclume.tls;

import java.io.IOException;

/**
 * The peer said why it is stopping.
 *
 * <p>Worth its own type because the alternative is what makes TLS problems
 * expensive to diagnose: a handshake that fails with "connection reset" or a
 * read that returns -1 tells you nothing, while
 * {@code bad_certificate} or {@code handshake_failure} tells you where to
 * look. A {@code close_notify} is the one alert that is not a fault - it is
 * the peer saying goodbye - and {@link #isCloseNotify()} separates it.
 */
public class TlsAlertException extends IOException {

    private static final long serialVersionUID = 1L;

    public static final int WARNING = 1;
    public static final int FATAL = 2;
    public static final int CLOSE_NOTIFY = 0;

    private final int level;
    private final int description;

    public TlsAlertException(int level, int description) {
        super("the peer sent a TLS alert: " + name(description) + " (" + description + "), "
                + (level == FATAL ? "fatal" : level == WARNING ? "warning" : "level " + level));
        this.level = level;
        this.description = description;
    }

    public int level() {
        return level;
    }

    public int description() {
        return description;
    }

    public boolean isCloseNotify() {
        return description == CLOSE_NOTIFY;
    }

    /** The names from RFC 8446 section 6; an unknown number is reported as itself. */
    static String name(int description) {
        return switch (description) {
            case 0 -> "close_notify";
            case 10 -> "unexpected_message";
            case 20 -> "bad_record_mac";
            case 22 -> "record_overflow";
            case 40 -> "handshake_failure";
            case 42 -> "bad_certificate";
            case 43 -> "unsupported_certificate";
            case 44 -> "certificate_revoked";
            case 45 -> "certificate_expired";
            case 46 -> "certificate_unknown";
            case 47 -> "illegal_parameter";
            case 48 -> "unknown_ca";
            case 49 -> "access_denied";
            case 50 -> "decode_error";
            case 51 -> "decrypt_error";
            case 70 -> "protocol_version";
            case 71 -> "insufficient_security";
            case 80 -> "internal_error";
            case 86 -> "inappropriate_fallback";
            case 90 -> "user_canceled";
            case 109 -> "missing_extension";
            case 110 -> "unsupported_extension";
            case 112 -> "unrecognized_name";
            case 113 -> "bad_certificate_status_response";
            case 115 -> "unknown_psk_identity";
            case 116 -> "certificate_required";
            case 120 -> "no_application_protocol";
            default -> "alert " + description;
        };
    }
}
