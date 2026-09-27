package space.seclume.mail;

import java.io.IOException;
import java.util.Locale;

import space.seclume.jfr.Observed;
import space.seclume.jfr.SeclumeEvents;

/** The login of a mail connection as a {@code space.seclume.Authentication} event. */
final class MailEvents {

    /** A login step that talks to the server. */
    interface Login {
        void run() throws IOException;
    }

    private MailEvents() {
    }

    /**
     * Runs {@code login} and records it: the protocol, the server, the
     * mechanism asked for - never the user or anything sent.
     */
    static void login(String kind, MailSettings settings, Login login) throws IOException {
        SeclumeEvents.Authentication event = Observed.beginLogin();
        boolean succeeded = false;
        try {
            login.run();
            succeeded = true;
        } finally {
            Observed.endLogin(event, kind, settings.host + ":" + settings.port,
                    settings.auth.name().toLowerCase(Locale.ROOT), succeeded);
        }
    }
}
