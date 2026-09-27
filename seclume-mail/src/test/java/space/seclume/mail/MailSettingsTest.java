package space.seclume.mail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** What a mail URL means, and the ones refused before anything connects. */
class MailSettingsTest {

    private static final String SECRET = "&provider=file&path=/run/secrets/smtp";

    @Test
    void defaults() {
        MailSettings submission = MailSettings.of("smtp://mail.example.com?user=r" + SECRET);
        assertEquals(587, submission.port);
        assertTrue(submission.startTls);
        assertFalse(submission.implicitTls);
        assertEquals(MailSettings.Auth.BEST, submission.auth);

        MailSettings implicit = MailSettings.of("smtps://mail.example.com?user=r" + SECRET);
        assertEquals(465, implicit.port);
        assertTrue(implicit.implicitTls);
        assertFalse(implicit.startTls);

        MailSettings relay = MailSettings.of("smtp://relay:25?tls=none");
        assertEquals(MailSettings.Auth.NONE, relay.auth);
        assertFalse(relay.startTls);
        assertEquals(null, relay.secret, "no login, no provider");
    }

    @Test
    void aPasswordInTheUrlIsRefused() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> MailSettings.of("smtp://reports:hunter2@mail.example.com"));
        assertFalse(refused.getMessage().contains("hunter2"), refused.getMessage());
    }

    @Test
    void aLoginIsNeverSentInTheClear() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> MailSettings.of("smtp://mail.example.com?tls=none&user=r" + SECRET));
        assertTrue(refused.getMessage().contains("never sent"), refused.getMessage());
    }

    @Test
    void nonsenseIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> MailSettings.of("http://mail.example.com"));
        assertThrows(IllegalArgumentException.class,
                () -> MailSettings.of("smtps://mail.example.com?tls=none"));
        assertThrows(IllegalArgumentException.class,
                () -> MailSettings.of("smtp://mail.example.com?user=r&auth=cram-md5" + SECRET));
        assertThrows(IllegalArgumentException.class,
                () -> MailSettings.of("smtp://mail.example.com?auth=plain" + SECRET));
        assertThrows(IllegalArgumentException.class,
                () -> MailSettings.of("smtp://mail.example.com?user=r"),
                "a login without a secret provider");
    }

    @Test
    void imapAndPop3TakeTheirPortsAndNeedALogin() {
        MailSettings imap = MailSettings.of("imap://mail.example.com?user=r" + SECRET);
        assertEquals(MailSettings.Protocol.IMAP, imap.protocol);
        assertEquals(143, imap.port);
        assertTrue(imap.startTls);
        assertEquals(993, MailSettings.of("imaps://mail.example.com?user=r" + SECRET).port);
        assertEquals(110, MailSettings.of("pop3://mail.example.com?user=r" + SECRET).port);
        MailSettings pop3s = MailSettings.of("pop3s://mail.example.com?user=r" + SECRET);
        assertEquals(995, pop3s.port);
        assertEquals("pop3s", pop3s.scheme());

        IllegalArgumentException noLogin = assertThrows(IllegalArgumentException.class,
                () -> MailSettings.of("imaps://mail.example.com"));
        assertTrue(noLogin.getMessage().contains("read with a login"), noLogin.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> MailSettings.of("pop3://mail.example.com?tls=none&user=r" + SECRET));
    }

    @Test
    void aUserNameCannotCarryACommand() {
        assertThrows(IllegalArgumentException.class, () -> MailSettings.of(
                "pop3s://mail.example.com?user=r%0D%0ADELE%201" + SECRET));
    }

    @Test
    void xoauth2IsOnlyChosenByName() {
        assertEquals(MailSettings.Auth.XOAUTH2, MailSettings.of(
                "smtps://smtp.office365.com?user=r@example.com&auth=xoauth2" + SECRET).auth);
    }
}
