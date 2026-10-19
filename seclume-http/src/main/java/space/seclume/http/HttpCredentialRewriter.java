package space.seclume.http;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretScope;

/**
 * {@link CredentialSocket}'s rule for clients that take an {@code SSLEngine}
 * instead of a socket - Apache HttpClient's async client under the
 * Elasticsearch and OpenSearch clients: the secrets written into request
 * heads where their placeholders are, bodies untouched (see
 * {@link HttpFraming}, which both follow).
 *
 * <p>An engine is handed what the client writes in pieces of its choosing,
 * and a head may be split across two of them - a placeholder with it. So a
 * head is held, taken but not sent, until its blank line has come, and then
 * goes as one record, rewritten. It never goes out in parts, so a
 * placeholder is never sent unreplaced because it straddled two writes.
 */
final class HttpCredentialRewriter implements SeclumeSslEngine.Outgoing {

    private final HttpFraming framing = new HttpFraming();
    private final String where;

    HttpCredentialRewriter(String where) {
        this.where = where;
    }

    @Override
    public Step next(ByteBuffer plain) throws IOException {
        if (!framing.inHead()) {
            return Step.unchanged(framing.passThrough(plain,
                    Math.min(plain.remaining(), SeclumeSslEngine.MAX_PLAINTEXT)));
        }
        int consumed = 0;
        byte[] head = null;
        for (int at = plain.position(); at < plain.limit() && head == null; at++) {
            head = framing.headByte(plain.get(at));
            consumed++;
        }
        if (head == null) {
            return Step.replace(consumed, held());
        }
        SecretScope out = HttpFraming.carriesPlaceholder(head) ? rewritten(head) : copy(head);
        if (out.length() > SeclumeSslEngine.MAX_PLAINTEXT) {
            int length = out.length();
            out.close();
            throw new IOException("a request head of " + length + " bytes with its "
                    + "credentials written in; at most " + SeclumeSslEngine.MAX_PLAINTEXT
                    + " go in one TLS record, and a head is never sent in parts");
        }
        return Step.replace(consumed, out);
    }

    private SecretScope rewritten(byte[] head) throws IOException {
        String text = new String(head, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT); // seclume-allow: a request head with placeholders - no secret
        space.seclume.jfr.Observed.secretUse("http", where,
                text.contains(": basic ") ? "basic" : "header");
        return HttpFraming.rewrite(head);
    }

    /** A head without a placeholder, as it is - in a scope only because a step takes one. */
    private static SecretScope copy(byte[] head) {
        SecretScope out = SecretScope.allocateShared(Math.max(1, head.length));
        MemorySegment.copy(head, 0, out.segment(), ValueLayout.JAVA_BYTE, 0, head.length);
        out.length(head.length);
        return out;
    }

    /** Taken, and nothing sent yet: the rest of the head is still to come. */
    private static SecretScope held() {
        SecretScope nothing = SecretScope.allocateShared(1);
        nothing.length(0);
        return nothing;
    }
}
