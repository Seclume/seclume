package space.seclume.mail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** What a mail URL means, and the ones refused before anything connects. */
class SmtpSettingsTest {

    private static final String SECRET = "&provider=file&path=/run/secrets/smtp";

    @Test
    void defaults() {
        SmtpSettings submission = SmtpSettings.of("smtp://mail.example.com?user=r" + SECRET);
        assertEquals(587, submission.port);
        assertTrue(submission.startTls);
        assertFalse(submission.implicitTls);
        assertEquals(SmtpSettings.Auth.BEST, submission.auth);

        SmtpSettings implicit = SmtpSettings.of("smtps://mail.example.com?user=r" + SECRET);
        assertEquals(465, implicit.port);
        assertTrue(implicit.implicitTls);
        assertFalse(implicit.startTls);

        SmtpSettings relay = SmtpSettings.of("smtp://relay:25?tls=none");
        assertEquals(SmtpSettings.Auth.NONE, relay.auth);
        assertFalse(relay.startTls);
        assertEquals(null, relay.secret, "no login, no provider");
    }

    @Test
    void aPasswordInTheUrlIsRefused() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SmtpSettings.of("smtp://reports:hunter2@mail.example.com"));
        assertFalse(refused.getMessage().contains("hunter2"), refused.getMessage());
    }

    @Test
    void aLoginIsNeverSentInTheClear() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> SmtpSettings.of("smtp://mail.example.com?tls=none&user=r" + SECRET));
        assertTrue(refused.getMessage().contains("never sent"), refused.getMessage());
    }

    @Test
    void nonsenseIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> SmtpSettings.of("imap://mail.example.com"));
        assertThrows(IllegalArgumentException.class,
                () -> SmtpSettings.of("smtps://mail.example.com?tls=none"));
        assertThrows(IllegalArgumentException.class,
                () -> SmtpSettings.of("smtp://mail.example.com?user=r&auth=cram-md5" + SECRET));
        assertThrows(IllegalArgumentException.class,
                () -> SmtpSettings.of("smtp://mail.example.com?auth=plain" + SECRET));
        assertThrows(IllegalArgumentException.class,
                () -> SmtpSettings.of("smtp://mail.example.com?user=r"),
                "a login without a secret provider");
    }

    @Test
    void xoauth2IsOnlyChosenByName() {
        assertEquals(SmtpSettings.Auth.XOAUTH2, SmtpSettings.of(
                "smtps://smtp.office365.com?user=r@example.com&auth=xoauth2" + SECRET).auth);
    }
}
