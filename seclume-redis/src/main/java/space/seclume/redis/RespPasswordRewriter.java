package space.seclume.redis;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat; // seclume-allow: a random placeholder - public

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Finds the placeholder a Redis client was given for its password, where the
 * client writes it - a RESP bulk string of its own in {@code AUTH} or
 * {@code HELLO ... AUTH}: {@code $<length>\r\n<placeholder>} - and replaces
 * it with {@code $<length>\r\n<password>}, both written in native memory from
 * the password read for this one command. Every other byte goes through as
 * the client wrote it.
 *
 * <p>The placeholder is random per client, so no other value a client sends
 * is taken for it by accident, and nobody can have the password written into
 * a command of their making.
 */
final class RespPasswordRewriter implements SeclumeSslEngine.Outgoing {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int MAX_DIGITS = 10;

    private record Binding(byte[] placeholder, SecretProvider secret) {
    }

    private final Binding[] bindings;
    /** The server, for the event that says the password was written in. */
    private final String where;

    RespPasswordRewriter(String placeholder, SecretProvider secret) {
        this(placeholder, secret, null, null, "");
    }

    RespPasswordRewriter(String placeholder, SecretProvider secret, String where) {
        this(placeholder, secret, null, null, where);
    }

    RespPasswordRewriter(String placeholder, SecretProvider secret, String sentinelPlaceholder,
                         SecretProvider sentinelSecret, String where) {
        // seclume-allow: the placeholder, not the password
        Binding main = new Binding(placeholder.getBytes(StandardCharsets.US_ASCII), secret);
        if (sentinelPlaceholder != null && sentinelSecret != null) {
            // seclume-allow: the placeholder, not the password
            Binding sentinel = new Binding(sentinelPlaceholder.getBytes(StandardCharsets.US_ASCII),
                    sentinelSecret);
            this.bindings = new Binding[] {main, sentinel};
        } else {
            this.bindings = new Binding[] {main};
        }
        this.where = where;
    }

    /** A new random placeholder. */
    static String newPlaceholder() {
        byte[] random = new byte[16];
        RANDOM.nextBytes(random);
        return "seclume-redis-" + HexFormat.of().formatHex(random); // seclume-allow: a random placeholder - public
    }

    /** Whether {@code plain} holds any of our placeholders anywhere from its position. */
    boolean contains(ByteBuffer plain) {
        int from = plain.position();
        int to = plain.limit();
        for (Binding binding : bindings) {
            if (indexOf(plain, from, to, binding.placeholder) >= 0) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Step next(ByteBuffer plain) throws IOException {
        int from = plain.position();
        int to = plain.limit();
        int at = -1;
        Binding matched = null;
        for (Binding binding : bindings) {
            int found = indexOf(plain, from, to, binding.placeholder);
            if (found >= 0 && (at < 0 || found < at)) {
                at = found;
                matched = binding;
            }
        }
        if (at < 0) {
            return Step.unchanged(Math.min(plain.remaining(), SeclumeSslEngine.MAX_PLAINTEXT));
        }
        int placeholderLength = matched.placeholder.length;
        int header = bulkHeader(plain, from, at, placeholderLength);
        if (header < 0) {
            // Not a bulk string of its own: nothing to replace, and nothing to hide.
            return Step.unchanged(Math.min(at + placeholderLength - from,
                    SeclumeSslEngine.MAX_PLAINTEXT));
        }
        if (header > from) {
            return Step.unchanged(Math.min(header - from, SeclumeSslEngine.MAX_PLAINTEXT));
        }
        space.seclume.jfr.Observed.secretUse("redis", where, "AUTH");
        return Step.replace(at + placeholderLength - header, bulk(matched.secret));
    }

    /** {@code $<length>\r\n<password>} in native memory, from the password read now. */
    private static SecretScope bulk(SecretProvider secret) {
        try (SecretScope password = SecretScope.fromProvider(secret)) {
            int length = password.length();
            int digits = 1;
            for (int rest = length / 10; rest > 0; rest /= 10) {
                digits++;
            }
            SecretScope out = SecretScope.allocateShared(1 + digits + 2 + length);
            MemorySegment o = out.segment();
            o.set(ValueLayout.JAVA_BYTE, 0, (byte) '$');
            for (int i = digits, rest = length; i >= 1; i--, rest /= 10) {
                o.set(ValueLayout.JAVA_BYTE, i, (byte) ('0' + rest % 10));
            }
            o.set(ValueLayout.JAVA_BYTE, 1 + digits, (byte) '\r');
            o.set(ValueLayout.JAVA_BYTE, 2 + digits, (byte) '\n');
            MemorySegment.copy(password.segment(), 0, o, 3 + digits, length);
            out.length(3 + digits + length);
            return out;
        }
    }

    /**
     * Where {@code $<length>\r\n} begins right before {@code at}, with the
     * placeholder's length in it; -1 when that is not what is there.
     */
    private static int bulkHeader(ByteBuffer plain, int from, int at, int placeholderLength) {
        if (at - 2 < from || plain.get(at - 1) != '\n' || plain.get(at - 2) != '\r') {
            return -1;
        }
        int end = at - 2;
        int start = end;
        while (start > from && end - start < MAX_DIGITS && Character.isDigit(plain.get(start - 1))) {
            start--;
        }
        if (start == end || start - 1 < from || plain.get(start - 1) != '$') {
            return -1;
        }
        int declared = 0;
        for (int i = start; i < end; i++) {
            declared = declared * 10 + (plain.get(i) - '0');
        }
        return declared == placeholderLength ? start - 1 : -1;
    }

    private static int indexOf(ByteBuffer in, int from, int to, byte[] placeholder) {
        outer:
        for (int i = from; i <= to - placeholder.length; i++) {
            for (int j = 0; j < placeholder.length; j++) {
                if (in.get(i + j) != placeholder[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
