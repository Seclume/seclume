package space.seclume.internal;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Takes a secret out of text a server sent, before that text becomes a
 * {@code String}.
 *
 * <p>A server that does not understand a line answers with what it read, some
 * of them: "unknown command: ...". After a password was written to it - from
 * native memory, never an object - the line that comes back may hold it, and
 * a client that makes a {@code String} of every reply line, the message of an
 * exception, has it on the heap after all. So the replies that follow a secret
 * are searched in native memory for what was sent, in the form it was sent in
 * and as it is, and what is found is overwritten with {@code *}.
 *
 * <p>Any run of {@value #MIN_RUN} bytes or more that stands somewhere in the
 * secret is taken for a part of it - a server may cut what it repeats at
 * either end. A secret shorter than that is looked for whole. What this does
 * not find is a secret the server changed before it sent it back: in hex, in
 * another case. And it is no protection from the server, which was given the
 * secret - only from its echo.
 */
public final class EchoMask {

    /** The shortest run taken for a part of the secret. */
    public static final int MIN_RUN = 4;

    private EchoMask() {
    }

    /**
     * Overwrites with {@code *} every run of the first {@code length} bytes of
     * {@code text} that is a part of {@code secret}, and says how many bytes
     * that were.
     */
    public static int mask(MemorySegment text, int length, MemorySegment secret,
                           int secretLength) {
        if (secretLength <= 0) {
            return 0;
        }
        int min = Math.min(MIN_RUN, secretLength);
        int masked = 0;
        int at = 0;
        while (at <= length - min) {
            int longest = 0;
            byte first = text.get(ValueLayout.JAVA_BYTE, at);
            for (int from = 0; from <= secretLength - min; from++) {
                if (secret.get(ValueLayout.JAVA_BYTE, from) != first) {
                    continue;
                }
                int run = 1;
                while (at + run < length && from + run < secretLength
                        && text.get(ValueLayout.JAVA_BYTE, at + run)
                        == secret.get(ValueLayout.JAVA_BYTE, from + run)) {
                    run++;
                }
                longest = Math.max(longest, run);
            }
            if (longest >= min) {
                text.asSlice(at, longest).fill((byte) '*');
                masked += longest;
                at += longest;
            } else {
                at++;
            }
        }
        return masked;
    }
}
