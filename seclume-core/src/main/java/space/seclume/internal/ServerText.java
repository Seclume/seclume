package space.seclume.internal;

/**
 * Text a server wrote, made fit to quote in an exception or a log line.
 *
 * <p>An error message is the server's, and often holds the application's
 * input ("invalid input syntax for type integer: ..."). A CR or LF in it
 * forged a log line of its own, an ESC drove the terminal that showed it.
 * Control characters but the tab are written as {@code \xNN}, and the text is
 * cut at {@link #MAX} characters.
 */
public final class ServerText {

    /** The longest server text quoted whole. */
    public static final int MAX = 2048;

    private ServerText() {
    }

    /** {@code text} with its control characters escaped and its length bounded; null stays null. */
    public static String printable(String text) {
        if (text == null) {
            return null;
        }
        boolean clean = text.length() <= MAX;
        for (int i = 0; clean && i < text.length(); i++) {
            char c = text.charAt(i);
            clean = !(c < 0x20 && c != '\t') && c != 0x7f && !(c >= 0x80 && c < 0xa0);
        }
        if (clean) {
            return text;
        }
        StringBuilder out = new StringBuilder(Math.min(text.length(), MAX) + 16); // seclume-allow: the server's own message, made printable
        for (int i = 0; i < text.length() && out.length() < MAX; i++) {
            char c = text.charAt(i);
            if ((c < 0x20 && c != '\t') || c == 0x7f || (c >= 0x80 && c < 0xa0)) {
                out.append(String.format("\\x%02x", (int) c));
            } else {
                out.append(c);
            }
        }
        if (out.length() >= MAX) {
            out.setLength(MAX);
            out.append("... (cut)");
        }
        return out.toString();
    }
}
