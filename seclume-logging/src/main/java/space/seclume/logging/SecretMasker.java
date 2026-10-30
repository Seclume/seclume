package space.seclume.logging;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;
import space.seclume.internal.Entropy;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Finds the application's own secrets in text bound for a log and masks them -
 * {@code [redacted:<label>]} - <b>without holding any of them</b>.
 *
 * <p>A log line that carries a password has already put it on the heap; what
 * is left to prevent is the line reaching a file, a collector, a ticket. To
 * look for a secret one would normally keep it - a {@code String} in a
 * filter's configuration, on the heap for good. Here each secret is read once
 * ({@link SecretScope}, native memory) and kept as two numbers: a rolling
 * fingerprint of its characters and an HMAC-SHA-256 tag, both keyed with 32
 * random bytes that live in locked native memory. Neither says anything about
 * the secret without the key - a heap dump of the process finds no secret, no
 * hash to guess against - and the secret's own memory is wiped the moment both
 * are made.
 *
 * <p>A text is scanned with the fingerprint, rolled over every window as long
 * as a secret; a window that matches is confirmed by its tag. The secret is
 * looked for as itself and as its Base64. Secrets shorter than
 * {@value #SHORTEST} characters are not looked for: they would mask ordinary
 * words.
 *
 * <p>{@link #refresh()} reads the secrets again - after a rotation - and
 * replaces what was kept. {@link #install} makes one masker the one the
 * Logback converters use. The providers stay the caller's.
 */
public final class SecretMasker implements AutoCloseable {

    /** The fewest characters a secret has to have to be looked for. */
    public static final int SHORTEST = 6;

    private static final System.Logger LOG = System.getLogger(SecretMasker.class.getName());
    private static final String BASE64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private static volatile SecretMasker installed;

    /** One form a secret takes in text: its length in chars, fingerprint and tag. */
    private record Form(String label, int length, long fingerprint, byte[] tag) {
    }

    private final java.util.function.Supplier<Map<String, SecretProvider>> providers;
    private final SecretScope key;
    private volatile List<Form> forms = List.of();
    private volatile boolean closed;

    /**
     * @param providers the secrets to look for, by the label a masked one is
     *                  shown with; read now and on {@link #refresh()}. They stay
     *                  the caller's to close.
     */
    public SecretMasker(Map<String, SecretProvider> providers) {
        this(fixed(providers));
    }

    private static java.util.function.Supplier<Map<String, SecretProvider>> fixed(
            Map<String, SecretProvider> providers) {
        Map<String, SecretProvider> copy = new LinkedHashMap<>(providers);
        return () -> copy;
    }

    /**
     * @param providers asked at each {@link #refresh()} for the secrets to look
     *                  for - so that a data source made later is looked for from
     *                  the next refresh on
     */
    public SecretMasker(java.util.function.Supplier<Map<String, SecretProvider>> providers) {
        this.providers = providers;
        this.key = SecretScope.allocate(32);
        Entropy.fill(key.segment(), 0, 32);
        key.length(32);
        refresh();
    }

    /** Makes {@code masker} the one {@link #maskInstalled} and the Logback converters use. */
    public static void install(SecretMasker masker) {
        installed = masker;
    }

    /** {@code text} masked by the installed masker - unchanged when there is none. */
    public static String maskInstalled(String text) {
        SecretMasker masker = installed;
        return masker == null ? text : masker.mask(text);
    }

    /** How many forms are looked for - two per secret long enough. */
    public int forms() {
        return forms.size();
    }

    /** Reads every secret again and keeps its fingerprints instead of the old ones. */
    public synchronized void refresh() {
        List<Form> next = new ArrayList<>();
        for (Map.Entry<String, SecretProvider> entry : providers.get().entrySet()) {
            try (SecretScope secret = SecretScope.fromProvider(entry.getValue())) {
                if (secret.length() > 0) {
                    forms(entry.getKey(), secret.secret(), secret.length(), next);
                }
            } catch (RuntimeException unavailable) {
                LOG.log(System.Logger.Level.WARNING, "seclume: the secret " + entry.getKey()
                        + " could not be read, so log lines are not masked for it: "
                        + unavailable.getMessage());
            }
        }
        // Longest first: where two overlap, the longer one wins.
        next.sort(Comparator.comparingInt(Form::length).reversed());
        forms = List.copyOf(next);
    }

    /** The secret's forms - itself as UTF-16, its Base64 - kept as fingerprints and tags. */
    private void forms(String label, MemorySegment utf8, int length, List<Form> into) {
        int units = utf16Units(utf8, length);
        if (units < 0) {
            LOG.log(System.Logger.Level.WARNING, "seclume: the secret " + label + " is not "
                    + "UTF-8 text, so log lines are not masked for it");
            return;
        }
        if (units < SHORTEST) {
            LOG.log(System.Logger.Level.WARNING, "seclume: the secret " + label + " is shorter "
                    + "than " + SHORTEST + " characters and is not looked for in log lines - "
                    + "it would mask ordinary words");
            return;
        }
        try (SecretScope text = SecretScope.allocate(units * 2)) {
            utf16(utf8, length, text.segment());
            into.add(form(label, text.segment(), units));
        }
        int encoded = ((length + 2) / 3) * 4;
        try (SecretScope base64 = SecretScope.allocate(encoded * 2)) {
            base64(utf8, length, base64.segment());
            into.add(form(label, base64.segment(), encoded));
        }
    }

    private Form form(String label, MemorySegment units, int count) {
        long base = base();
        long fingerprint = 0;
        for (int i = 0; i < count; i++) {
            fingerprint = fingerprint * base + units.get(ValueLayout.JAVA_CHAR_UNALIGNED, 2L * i);
        }
        return new Form(label, count, fingerprint, tag(units, count));
    }

    private byte[] tag(MemorySegment units, int count) {
        try (Hmac hmac = new Hmac(HashAlgorithm.SHA_256, key.segment(), 0, 32);
             Arena arena = Arena.ofConfined()) {
            hmac.update(units, 0, 2L * count);
            MemorySegment out = arena.allocate(32);
            hmac.doFinal(out, 0);
            return out.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /** An odd multiplier from the key: odd, so that it is invertible modulo 2^64. */
    private long base() {
        return key.segment().get(ValueLayout.JAVA_LONG_UNALIGNED, 0) | 1L;
    }

    /**
     * {@code text} with every secret found in it replaced by
     * {@code [redacted:<label>]} - the same instance when there is none.
     */
    public String mask(String text) {
        List<Form> now = forms;
        if (text == null || now.isEmpty() || closed) {
            return text;
        }
        TreeSet<Integer> lengths = new TreeSet<>(Comparator.reverseOrder());
        for (Form form : now) {
            if (form.length() <= text.length()) {
                lengths.add(form.length());
            }
        }
        if (lengths.isEmpty()) {
            return text;
        }
        long base = base();
        List<int[]> hits = new ArrayList<>();
        for (int length : lengths) {
            long power = 1;
            for (int i = 1; i < length; i++) {
                power *= base;
            }
            long rolling = 0;
            for (int i = 0; i < length; i++) {
                rolling = rolling * base + text.charAt(i);
            }
            for (int start = 0; ; start++) {
                for (int f = 0; f < now.size(); f++) {
                    Form form = now.get(f);
                    if (form.length() == length && form.fingerprint() == rolling
                            && !covered(hits, start, start + length)
                            && confirmed(text, start, form)) {
                        hits.add(new int[] {start, start + length, f});
                    }
                }
                if (start + length >= text.length()) {
                    break;
                }
                rolling = (rolling - text.charAt(start) * power) * base
                        + text.charAt(start + length);
            }
        }
        if (hits.isEmpty()) {
            return text;
        }
        hits.sort(Comparator.comparingInt(hit -> hit[0]));
        StringBuilder masked = new StringBuilder(text.length());
        int at = 0;
        for (int[] hit : hits) {
            if (hit[0] < at) {
                continue;
            }
            masked.append(text, at, hit[0]).append("[redacted:").append(now.get(hit[2]).label())
                    .append(']');
            at = hit[1];
        }
        return masked.append(text, at, text.length()).toString();
    }

    private static boolean covered(List<int[]> hits, int start, int end) {
        for (int[] hit : hits) {
            if (start < hit[1] && end > hit[0]) {
                return true;
            }
        }
        return false;
    }

    /** Whether the window's tag is the form's - the window copied to native memory and wiped. */
    private boolean confirmed(String text, int start, Form form) {
        try (SecretScope window = SecretScope.allocate(form.length() * 2)) {
            for (int i = 0; i < form.length(); i++) {
                window.segment().set(ValueLayout.JAVA_CHAR_UNALIGNED, 2L * i,
                        text.charAt(start + i));
            }
            byte[] tag = tag(window.segment(), form.length());
            int difference = 0;
            for (int i = 0; i < tag.length; i++) {
                difference |= tag[i] ^ form.tag()[i];
            }
            return difference == 0;
        }
    }

    /** How many UTF-16 code units {@code length} bytes of UTF-8 decode to, or -1 if they are not UTF-8. */
    static int utf16Units(MemorySegment utf8, int length) {
        int units = 0;
        int i = 0;
        while (i < length) {
            int b = utf8.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            int bytes = b < 0x80 ? 1 : (b & 0xe0) == 0xc0 ? 2 : (b & 0xf0) == 0xe0 ? 3
                    : (b & 0xf8) == 0xf0 ? 4 : -1;
            if (bytes < 0 || i + bytes > length) {
                return -1;
            }
            for (int k = 1; k < bytes; k++) {
                if ((utf8.get(ValueLayout.JAVA_BYTE, i + k) & 0xc0) != 0x80) {
                    return -1;
                }
            }
            units += bytes == 4 ? 2 : 1;
            i += bytes;
        }
        return units;
    }

    /** Decodes valid UTF-8 into UTF-16 code units, in native memory. */
    static void utf16(MemorySegment utf8, int length, MemorySegment out) {
        int i = 0;
        long at = 0;
        while (i < length) {
            int b = utf8.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            int code;
            int bytes;
            if (b < 0x80) {
                code = b;
                bytes = 1;
            } else if ((b & 0xe0) == 0xc0) {
                code = b & 0x1f;
                bytes = 2;
            } else if ((b & 0xf0) == 0xe0) {
                code = b & 0x0f;
                bytes = 3;
            } else {
                code = b & 0x07;
                bytes = 4;
            }
            for (int k = 1; k < bytes; k++) {
                code = (code << 6) | (utf8.get(ValueLayout.JAVA_BYTE, i + k) & 0x3f);
            }
            i += bytes;
            if (code >= 0x10000) {
                int v = code - 0x10000;
                out.set(ValueLayout.JAVA_CHAR_UNALIGNED, at, (char) (0xd800 | (v >>> 10)));
                out.set(ValueLayout.JAVA_CHAR_UNALIGNED, at + 2, (char) (0xdc00 | (v & 0x3ff)));
                at += 4;
            } else {
                out.set(ValueLayout.JAVA_CHAR_UNALIGNED, at, (char) code);
                at += 2;
            }
        }
    }

    /** {@code length} bytes as Base64 with padding, one UTF-16 code unit per character. */
    static void base64(MemorySegment data, int length, MemorySegment out) {
        long at = 0;
        for (int i = 0; i < length; i += 3) {
            int b0 = data.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            int b1 = i + 1 < length ? data.get(ValueLayout.JAVA_BYTE, i + 1) & 0xff : 0;
            int b2 = i + 2 < length ? data.get(ValueLayout.JAVA_BYTE, i + 2) & 0xff : 0;
            out.set(ValueLayout.JAVA_CHAR_UNALIGNED, at, BASE64.charAt(b0 >>> 2));
            out.set(ValueLayout.JAVA_CHAR_UNALIGNED, at + 2,
                    BASE64.charAt(((b0 & 3) << 4) | (b1 >>> 4)));
            out.set(ValueLayout.JAVA_CHAR_UNALIGNED, at + 4, i + 1 < length
                    ? BASE64.charAt(((b1 & 0xf) << 2) | (b2 >>> 6)) : '=');
            out.set(ValueLayout.JAVA_CHAR_UNALIGNED, at + 6, i + 2 < length
                    ? BASE64.charAt(b2 & 0x3f) : '=');
            at += 8;
        }
    }

    /** Forgets every fingerprint and wipes the key; the providers stay open. */
    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        forms = List.of();
        if (installed == this) {
            installed = null;
        }
        key.close();
    }
}
