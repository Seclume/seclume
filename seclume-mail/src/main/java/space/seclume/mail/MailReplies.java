package space.seclume.mail;

import java.nio.charset.StandardCharsets;
import java.util.Base64; // seclume-allow: decodes the server's refusal, which holds no secret

/** What the three protocols share in reading a server's answer. */
final class MailReplies {

    private MailReplies() {
    }

    /**
     * The reason an XOAUTH2 login was refused: the server sends it as base64
     * JSON (Google's {@code {"status":"401",...}}), in a continuation. Shown
     * as it came when it is not base64.
     */
    static String oauthReason(String continuation) {
        String text = continuation.trim();
        try {
            // seclume-allow: the server's refusal reason, a JSON it sent us - no secret in it
            return new String(Base64.getDecoder().decode(text), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException notBase64) {
            return text;
        }
    }
}
