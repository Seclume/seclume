package space.seclume.heapdump;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Looks for secrets nobody named: credentials of known shapes in a heap dump.
 *
 * <p>{@code --secret-file} answers whether <i>this</i> password is in the
 * heap. An audit also needs the other question - what <i>else</i> is in it -
 * because the secrets that leak are rarely the ones somebody thought of: the
 * API key in a configuration object, the service-account token a client
 * library caches, the private key a TLS setup read into a {@code String}, the
 * connection string with the password still in it that an exception message
 * carries around.
 *
 * <p>So this goes through the dump the way {@code strings} does - runs of
 * printable characters, as single bytes (ASCII, how a Latin-1 {@code String}
 * and most {@code byte[]} hold text) and as UTF-16 in both byte orders (a
 * {@code char[]} is big-endian in an HPROF file, a {@code String} with
 * non-Latin-1 characters holds UTF-16 in the platform's order) - and holds
 * every run against a list of {@linkplain #DETECTORS detectors}: private keys
 * in PEM, JWTs, cloud and platform tokens, passwords in URLs.
 *
 * <p><b>What a result holds.</b> Which detector matched, how many distinct
 * values it found, how often each occurred, and where - the offset in the dump
 * file, the encoding, the length. Never the value, never a part of it, never a
 * hash of it: the report is a document that gets passed around. The values
 * themselves are held in this process while it runs, to tell one from
 * another; this process is the searcher, and it ends when the search does.
 *
 * <p><b>What it cannot do.</b> A credential without a recognisable shape - a
 * plain password, a random API key without a prefix - looks like any other
 * string; for those there is {@code --secret-file}. A match is a credential
 * of that shape, not proof that it is a live one: a test key, a revoked
 * token, an example from a library's documentation all match. And a value
 * that is split across objects, or compressed, or encrypted, is not found.
 */
public final class Discovery {

    /** Bytes read per window. */
    static final int CHUNK = 8 * 1024 * 1024;
    /**
     * How far windows overlap, and how far a match must be from a window's
     * edge to be taken from it. Larger than any match can be, so that every
     * match is whole in exactly one window.
     */
    static final int OVERLAP = 64 * 1024;
    /** Runs of printable text shorter than this cannot hold any of the shapes looked for. */
    static final int MIN_RUN = 12;
    /** Positions kept per value; the count goes on. */
    static final int POSITIONS_KEPT = 10;
    /** Distinct values per detector worth telling apart; beyond that only counted. */
    static final int VALUES_KEPT = 1000;

    /**
     * One shape of credential.
     *
     * @param id      stable, for {@code --ignore} and for SARIF rule ids
     * @param name    what it is, for people
     * @param advice  what usually puts it there and what to do about it
     * @param regex   the shape; a first capturing group, when there is one,
     *                marks the secret part of the match - the password of a
     *                URL, say - which is what tells two values apart
     */
    public record Detector(String id, String name, String advice, String regex) {

        Pattern pattern() {
            return Pattern.compile(regex);
        }
    }

    /**
     * Where one occurrence lies in the dump file, lengths in bytes: the whole
     * match, and within it the value - the password of a URL, the token after
     * {@code Bearer}, the whole of a PEM block - which is what has to go when
     * a dump is redacted.
     */
    public record Occurrence(String encoding, long position, int length, long valuePosition,
            int valueLength) {

        @Override
        public String toString() {
            return "raw file: " + encoding + " match of " + length + " bytes at " + position;
        }
    }

    /**
     * One distinct value a detector found: its number within that detector
     * (1, 2, ... in the order they were met - stable within one report and
     * meaningless outside it), how often, and the first positions.
     */
    public record Found(Detector detector, int value, long count,
            List<Occurrence> occurrences) {
    }

    /** What the search found, grouped by detector, and what it was told to leave out. */
    public record Result(List<Found> found, Set<String> ignored, Map<String, Long> uncounted) {

        public boolean clean() {
            return found.isEmpty();
        }

        /** Distinct values per detector id, in detector order. */
        public Map<String, Long> valuesByDetector() {
            Map<String, Long> values = new LinkedHashMap<>();
            for (Found found : found) {
                values.merge(found.detector().id(), 1L, Long::sum);
            }
            return values;
        }
    }

    private static final String NOT_BASE64URL = "(?![A-Za-z0-9_-])";
    private static final String NOT_AFTER_WORD = "(?<![A-Za-z0-9])";

    /** The shapes looked for. Ids are stable; names and advice are for reading. */
    static final List<Detector> DETECTORS = List.of(
            new Detector("private-key", "private key (PEM)",
                    "A private key read into a String or byte[] - a TLS setup, a signing key, an "
                            + "SSH client. Hold it where the JVM cannot dump it: a key store "
                            + "backed by the OS or an HSM, or seclume-keys.",
                    "-----BEGIN [A-Z ]{0,20}PRIVATE KEY(?: BLOCK)?-----[ \\t\\r\\n]{0,4}"
                            + "(?:[A-Za-z][A-Za-z-]{0,30}:[^\\r\\n]{0,200}\\r?\\n){0,6}"
                            + "[ \\t\\r\\n]{0,4}[A-Za-z0-9+/]{48}"),
            new Detector("jwt", "JSON Web Token (signed)",
                    "A bearer token: whoever holds it is its subject until it expires. Usually "
                            + "an access token or a Kubernetes service-account token cached by a "
                            + "client library.",
                    NOT_AFTER_WORD + "(eyJ[A-Za-z0-9_-]{8,4096}\\.eyJ[A-Za-z0-9_-]{8,8192}\\."
                            + "[A-Za-z0-9_-]{16,2048})" + NOT_BASE64URL),
            new Detector("aws-access-key-id", "AWS access key id",
                    "Not a secret by itself, but its secret access key is rarely far away - "
                            + "the AWS SDK keeps both in a credentials object.",
                    "(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z2-7]{16})(?![A-Z0-9])"),
            new Detector("aws-secret-access-key", "AWS secret access key",
                    "The signing key of an AWS identity, next to its name. Use the instance "
                            + "role, or seclume-aws, whose signer keeps the key in native memory.",
                    "(?i:aws.{0,24}?secret.{0,24}?)[=:\"' ]{1,4}([A-Za-z0-9/+]{40})"
                            + "(?![A-Za-z0-9/+])"),
            new Detector("vault-token", "HashiCorp Vault / OpenBao token",
                    "A Vault token can read whatever its policies allow. seclume's vault "
                            + "provider and VaultLogin keep it in native memory.",
                    NOT_AFTER_WORD + "(hv[sbr]\\.[A-Za-z0-9_-]{24,512})" + NOT_BASE64URL),
            new Detector("github-token", "GitHub token",
                    "A personal access, OAuth, app or refresh token for GitHub.",
                    NOT_AFTER_WORD + "(gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]"
                            + "{60,255})" + NOT_BASE64URL),
            new Detector("gitlab-token", "GitLab personal access token",
                    "A GitLab token, with the rights of the user who made it.",
                    NOT_AFTER_WORD + "(glpat-[A-Za-z0-9_-]{20,64})" + NOT_BASE64URL),
            new Detector("slack-token", "Slack token",
                    "A Slack bot, user or app token.",
                    NOT_AFTER_WORD + "(xox[abposr]-[A-Za-z0-9-]{10,250})" + NOT_BASE64URL),
            new Detector("stripe-key", "Stripe secret or restricted key",
                    "A Stripe API key; a live one moves money.",
                    NOT_AFTER_WORD + "((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,247})"
                            + NOT_BASE64URL),
            new Detector("google-api-key", "Google API key",
                    "A Google Cloud or Maps API key.",
                    NOT_AFTER_WORD + "(AIza[0-9A-Za-z_-]{35})" + NOT_BASE64URL),
            new Detector("npm-token", "npm access token",
                    "An npm registry token, often from a build tool running in the JVM.",
                    NOT_AFTER_WORD + "(npm_[A-Za-z0-9]{36})" + NOT_BASE64URL),
            new Detector("ai-api-key", "AI service API key (Anthropic, OpenAI)",
                    "An API key for a model provider, usually held by its client library.",
                    NOT_AFTER_WORD + "(sk-ant-[A-Za-z0-9_-]{20,200}|sk-proj-[A-Za-z0-9_-]"
                            + "{20,200})" + NOT_BASE64URL),
            new Detector("azure-storage-key", "Azure Storage account key",
                    "An account key in a storage connection string: full access to the "
                            + "account. seclume-azure signs with it from native memory.",
                    "(?i:AccountKey)=([A-Za-z0-9+/]{86}==)"),
            new Detector("azure-sas", "Azure shared access signature",
                    "The signature of a SAS URL or connection string.",
                    "(?i:[?&;]sig=)([A-Za-z0-9%+/=]{40,256})"),
            new Detector("url-password", "password in a URL",
                    "A connection string or URL with the password in it - kept by a "
                            + "configuration object, a data source's toString(), a log line "
                            + "or an exception message. Configure where the secret comes from "
                            + "instead of the secret.",
                    "(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,30}://"
                            + "[^\\s:/@?#\"'<>]{0,128}:([^\\s/@?#\"'<>]{3,256})@"
                            + "[A-Za-z0-9.\\[\\]-]{1,253}"),
            new Detector("url-password-parameter", "password parameter in a URL",
                    "A JDBC or other URL with password= in its parameters; the same places "
                            + "keep it as for a password in the user part.",
                    "(?i:[?&;](?:password|passwd|pwd)=)([^&;\\s\"'<>]{3,256})"),
            new Detector("http-authorization", "HTTP Authorization header value",
                    "A Basic password or bearer token as it is sent - a request object or a "
                            + "buffer of an HTTP client that was kept.",
                    "(?i:authorization:[ \\t]*(?:basic|bearer)[ \\t]+)"
                            + "([A-Za-z0-9._~+/=-]{16,4096})"));

    /**
     * What a value has to look like to be no example: templates, masks and
     * the word itself are what configuration and documentation show where a
     * password would be.
     */
    private static final Pattern PLACEHOLDER = Pattern.compile(
            "(?i)\\$\\{.*|\\{\\{.*|<.*>|%s|\\*+|x{3,}|\\.{3,}|redacted|hidden|masked"
                    + "|password|passwd|pwd|secret|changeit|example");

    /** Detectors whose secret part is a password a person chose, where examples abound. */
    private static final Set<String> CHOSEN = Set.of("url-password", "url-password-parameter");

    /**
     * Fixed text every match of a detector contains, and how far before it a
     * match can begin. Text is searched for these first, which is cheap, and
     * a detector's pattern is only tried around one - a pattern tried at
     * every position of a dump of several gigabytes is not a check anyone
     * waits for.
     */
    record Anchor(List<String> literals, boolean ignoreCase, int lookback) {
    }

    static final Map<String, Anchor> ANCHORS = Map.ofEntries(
            Map.entry("private-key", new Anchor(List.of("-----BEGIN "), false, 0)),
            Map.entry("jwt", new Anchor(List.of("eyJ"), false, 0)),
            Map.entry("aws-access-key-id", new Anchor(List.of("AKIA", "ASIA"), false, 0)),
            Map.entry("aws-secret-access-key", new Anchor(List.of("secret"), true, 30)),
            Map.entry("vault-token", new Anchor(List.of("hvs.", "hvb.", "hvr."), false, 0)),
            Map.entry("github-token", new Anchor(List.of("ghp_", "gho_", "ghu_", "ghs_",
                    "ghr_", "github_pat_"), false, 0)),
            Map.entry("gitlab-token", new Anchor(List.of("glpat-"), false, 0)),
            Map.entry("slack-token", new Anchor(List.of("xox"), false, 0)),
            Map.entry("stripe-key", new Anchor(List.of("sk_live_", "sk_test_", "rk_live_",
                    "rk_test_"), false, 0)),
            Map.entry("google-api-key", new Anchor(List.of("AIza"), false, 0)),
            Map.entry("npm-token", new Anchor(List.of("npm_"), false, 0)),
            Map.entry("ai-api-key", new Anchor(List.of("sk-ant-", "sk-proj-"), false, 0)),
            Map.entry("azure-storage-key", new Anchor(List.of("accountkey="), true, 0)),
            Map.entry("azure-sas", new Anchor(List.of("sig="), true, 1)),
            Map.entry("url-password", new Anchor(List.of("://"), false, 32)),
            Map.entry("url-password-parameter", new Anchor(List.of("password=", "passwd=",
                    "pwd="), true, 1)),
            Map.entry("http-authorization", new Anchor(List.of("authorization:"), true, 0)));

    /** Longest a match runs past its anchor; well inside {@link #OVERLAP}. */
    private static final int MAX_MATCH = 16 * 1024;

    /** An anchor literal and the detector it belongs to. */
    private record Hook(String literal, boolean ignoreCase, int lookback, int detector) {
    }

    private final List<Detector> detectors;
    private final List<Pattern> own;
    /** By first character (ASCII): the hooks that can begin there. */
    private final Hook[][] hooks = new Hook[128][];
    private final Set<String> ignored;
    /** Per detector: value -> its number, count and kept positions. */
    private final Map<String, Map<String, Tally>> tallies = new LinkedHashMap<>();
    private final Map<String, Long> uncounted = new LinkedHashMap<>();

    private static final class Tally {
        final int number;
        long count;
        final List<Occurrence> kept = new ArrayList<>();

        Tally(int number) {
            this.number = number;
        }
    }

    private Discovery(Set<String> ignore) {
        Set<String> known = new java.util.HashSet<>();
        for (Detector detector : DETECTORS) {
            known.add(detector.id());
        }
        for (String id : ignore) {
            if (!known.contains(id)) {
                throw new IllegalArgumentException("no detector '" + id + "' - known are "
                        + String.join(", ", ids()));
            }
        }
        this.ignored = Set.copyOf(ignore);
        this.detectors = DETECTORS.stream().filter(d -> !ignored.contains(d.id())).toList();
        List<Pattern> patterns = new ArrayList<>();
        Map<Character, List<Hook>> byFirst = new java.util.HashMap<>();
        for (int i = 0; i < detectors.size(); i++) {
            patterns.add(detectors.get(i).pattern());
            Anchor anchor = ANCHORS.get(detectors.get(i).id());
            for (String literal : anchor.literals()) {
                Hook hook = new Hook(literal, anchor.ignoreCase(), anchor.lookback(), i);
                char first = literal.charAt(0);
                byFirst.computeIfAbsent(first, c -> new ArrayList<>()).add(hook);
                if (anchor.ignoreCase() && Character.toUpperCase(first) != first) {
                    byFirst.computeIfAbsent(Character.toUpperCase(first),
                            c -> new ArrayList<>()).add(hook);
                }
            }
        }
        for (Map.Entry<Character, List<Hook>> entry : byFirst.entrySet()) {
            hooks[entry.getKey()] = entry.getValue().toArray(Hook[]::new);
        }
        this.own = patterns;
    }

    /**
     * Told of every occurrence as it is found - every one, where a
     * {@link Result} keeps the first {@value #POSITIONS_KEPT} per value. For
     * redacting, which has to reach all of them.
     */
    @FunctionalInterface
    public interface Sink {
        void found(Detector detector, Occurrence occurrence);
    }

    private Sink sink;

    /** The detector ids, in order. */
    public static List<String> ids() {
        return DETECTORS.stream().map(Detector::id).toList();
    }

    /** Searches a dump file. */
    public static Result scan(Path dump, Set<String> ignore) throws IOException {
        return scan(dump, ignore, null);
    }

    /** The same, telling {@code sink} of every occurrence. */
    public static Result scan(Path dump, Set<String> ignore, Sink sink) throws IOException {
        Discovery discovery = new Discovery(ignore);
        discovery.sink = sink;
        try (FileChannel channel = FileChannel.open(dump, StandardOpenOption.READ)) {
            discovery.scan(channel, CHUNK);
        }
        return discovery.result();
    }

    /** Searches bytes in memory - for the tests of what builds on this. */
    public static Result scan(byte[] data, Set<String> ignore) {
        return scan(data, ignore, CHUNK);
    }

    /** Searches bytes in memory, in windows of {@code chunk} - for the tests. */
    static Result scan(byte[] data, Set<String> ignore, int chunk) {
        Discovery discovery = new Discovery(ignore);
        discovery.scan(new Source() {
            @Override
            public long size() {
                return data.length;
            }

            @Override
            public int read(byte[] into, long from, int length) {
                int n = (int) Math.min(length, data.length - from);
                System.arraycopy(data, (int) from, into, 0, n);
                return n;
            }
        }, chunk);
        return discovery.result();
    }

    private void scan(FileChannel channel, int chunk) throws IOException {
        try {
            scan(new Source() {
                @Override
                public long size() throws IOException {
                    return channel.size();
                }

                @Override
                public int read(byte[] into, long from, int length) throws IOException {
                    ByteBuffer buffer = ByteBuffer.wrap(into, 0, length);
                    int total = 0;
                    while (buffer.hasRemaining()) {
                        int n = channel.read(buffer, from + total);
                        if (n < 0) {
                            break;
                        }
                        total += n;
                    }
                    return total;
                }
            }, chunk);
        } catch (java.io.UncheckedIOException e) {
            throw e.getCause();
        }
    }

    /** Where windows come from: a file, or bytes in a test. */
    private interface Source {
        long size() throws IOException;

        int read(byte[] into, long from, int length) throws IOException;
    }

    private void scan(Source source, int chunk) {
        if (chunk <= 2 * OVERLAP && chunk < Integer.MAX_VALUE) {
            // A test's small windows: the same rule, with a smaller margin.
            scanWindows(source, chunk, Math.max(1, chunk / 4));
        } else {
            scanWindows(source, chunk, OVERLAP);
        }
    }

    private void scanWindows(Source source, int chunk, int overlap) {
        try {
            long size = source.size();
            byte[] window = new byte[(int) Math.min(chunk, Math.max(size, 1))];
            long start = 0;
            while (start < size) {
                int length = source.read(window, start, (int) Math.min(window.length,
                        size - start));
                long end = start + length;
                boolean first = start == 0;
                boolean last = end >= size;
                // Accepted here: matches that begin at least `overlap` from
                // either edge, or at the file's own edges. The next window
                // starts 2 * overlap before this one ends, so the accepted
                // ranges meet without a gap and without a seam.
                long acceptFrom = first ? 0 : start + overlap;
                long acceptTo = last ? end : end - overlap;
                scanWindow(window, length, start, acceptFrom, acceptTo);
                if (last) {
                    break;
                }
                start = end - 2L * overlap;
            }
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    /** The runs of printable text in one window, in each of the encodings. */
    private void scanWindow(byte[] data, int length, long base, long acceptFrom, long acceptTo) {
        // Single bytes.
        int run = -1;
        for (int i = 0; i <= length; i++) {
            boolean text = i < length && printable(data[i] & 0xff);
            if (text && run < 0) {
                run = i;
            } else if (!text && run >= 0) {
                if (i - run >= MIN_RUN) {
                    match(new Ascii(data, run, i), "ASCII", base + run, 1, acceptFrom,
                            acceptTo);
                }
                run = -1;
            }
        }
        // Two bytes a character, both orders, both alignments.
        List<Utf16> runs = new ArrayList<>();
        for (boolean bigEndian : new boolean[] {true, false}) {
            for (int align = 0; align < 2; align++) {
                run = -1;
                for (int i = align; i <= length; i += 2) {
                    boolean text = i + 1 < length && utf16(data, i, bigEndian);
                    if (text && run < 0) {
                        run = i;
                    } else if (!text && run >= 0) {
                        if ((i - run) / 2 >= MIN_RUN) {
                            runs.add(new Utf16(data, run, i, bigEndian));
                        }
                        run = -1;
                    }
                }
            }
        }
        // Text in one byte order reads, one byte further on, as text in the
        // other - one character shorter at each end. That shadow lies wholly
        // inside the real run; without dropping it, every match would be
        // counted twice and the second one would be cut short.
        Map<Integer, Utf16> bigEndianAt = new java.util.HashMap<>();
        Map<Integer, Utf16> littleEndianAt = new java.util.HashMap<>();
        for (Utf16 candidate : runs) {
            (candidate.bigEndian() ? bigEndianAt : littleEndianAt).put(candidate.from(),
                    candidate);
        }
        for (Utf16 candidate : runs) {
            Utf16 real = (candidate.bigEndian() ? littleEndianAt : bigEndianAt)
                    .get(candidate.from() - 1);
            boolean shadow = real != null && candidate.to() < real.to();
            if (!shadow) {
                match(candidate, candidate.bigEndian() ? "UTF-16BE" : "UTF-16LE",
                        base + candidate.from(), 2, acceptFrom, acceptTo);
            }
        }
    }

    private static boolean printable(int b) {
        return (b >= 0x20 && b < 0x7f) || b == '\t' || b == '\n' || b == '\r';
    }

    private static boolean utf16(byte[] data, int i, boolean bigEndian) {
        int high = data[bigEndian ? i : i + 1] & 0xff;
        int low = data[bigEndian ? i + 1 : i] & 0xff;
        return high == 0 && printable(low);
    }

    private void match(CharSequence text, String encoding, long offset, int width,
            long acceptFrom, long acceptTo) {
        int length = text.length();
        current = text;
        // A match is taken once, however many of its anchors lead to it.
        Set<Long> taken = null;
        for (int i = 0; i < length; i++) {
            char c = text.charAt(i);
            Hook[] candidates = c < 128 ? hooks[c] : null;
            if (candidates == null) {
                continue;
            }
            for (Hook hook : candidates) {
                if (!startsWith(text, i, hook.literal(), hook.ignoreCase())) {
                    continue;
                }
                Matcher matcher = own.get(hook.detector()).matcher(text);
                // Transparent: the patterns look at what is before and after
                // a token to see that it is not part of a longer word.
                matcher.useTransparentBounds(true).useAnchoringBounds(false)
                        .region(Math.max(0, i - hook.lookback()),
                                (int) Math.min(length, (long) i + hook.literal().length()
                                        + MAX_MATCH));
                while (matcher.find() && matcher.start() <= i) {
                    if (matcher.end() <= i) {
                        continue;                  // ends before this anchor: not its match
                    }
                    long key = ((long) hook.detector() << 40) | matcher.start();
                    if (taken == null) {
                        taken = new java.util.HashSet<>();
                    }
                    if (taken.add(key)) {
                        take(matcher, hook.detector(), encoding, offset, width, acceptFrom,
                                acceptTo);
                    }
                    break;
                }
            }
        }
    }

    private void take(Matcher matcher, int d, String encoding, long offset, int width,
            long acceptFrom, long acceptTo) {
        long position = offset + (long) matcher.start() * width;
        if (position < acceptFrom || position >= acceptTo) {
            return;                                 // the window next door takes it
        }
        boolean group = matcher.groupCount() >= 1 && matcher.group(1) != null;
        String value = group ? matcher.group(1) : matcher.group();
        Detector detector = detectors.get(d);
        if (CHOSEN.contains(detector.id()) && PLACEHOLDER.matcher(value).matches()) {
            return;
        }
        int valueStart = group ? matcher.start(1) : matcher.start();
        int valueEnd = group ? matcher.end(1) : matcher.end();
        if (detector.id().equals("private-key")) {
            valueEnd = pemEnd(current, matcher.end());
        }
        Occurrence occurrence = new Occurrence(encoding, position,
                (matcher.end() - matcher.start()) * width,
                offset + (long) valueStart * width, (valueEnd - valueStart) * width);
        record(detector, value, occurrence);
        if (sink != null) {
            sink.found(detector, occurrence);
        }
    }

    /** The run of text being matched - a Matcher does not hand its input out. */
    private CharSequence current;

    /**
     * Where a PEM block that starts in a match ends: after its
     * {@code -----END ...-----} line, or with the run of text if that is not
     * in it. The detector matches the header and the first line of the key;
     * the key is all of it.
     */
    private static int pemEnd(CharSequence text, int from) {
        int end = indexOf(text, "-----END ", from);
        if (end < 0) {
            return text.length();
        }
        int close = indexOf(text, "-----", end + "-----END ".length());
        return close < 0 ? text.length() : close + "-----".length();
    }

    private static int indexOf(CharSequence text, String needle, int from) {
        outer:
        for (int i = Math.max(0, from); i + needle.length() <= text.length(); i++) {
            for (int j = 0; j < needle.length(); j++) {
                if (text.charAt(i + j) != needle.charAt(j)) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static boolean startsWith(CharSequence text, int at, String literal,
            boolean ignoreCase) {
        if (at + literal.length() > text.length()) {
            return false;
        }
        for (int j = 0; j < literal.length(); j++) {
            char a = text.charAt(at + j);
            char b = literal.charAt(j);
            if (a != b && !(ignoreCase && Character.toLowerCase(a) == b)) {
                return false;
            }
        }
        return true;
    }

    private void record(Detector detector, String value, Occurrence occurrence) {
        Map<String, Tally> values = tallies.computeIfAbsent(detector.id(),
                id -> new LinkedHashMap<>());
        Tally tally = values.get(value);
        if (tally == null) {
            if (values.size() >= VALUES_KEPT) {
                uncounted.merge(detector.id(), 1L, Long::sum);
                return;
            }
            tally = new Tally(values.size() + 1);
            values.put(value, tally);
        }
        tally.count++;
        if (tally.kept.size() < POSITIONS_KEPT) {
            tally.kept.add(occurrence);
        }
    }

    private Result result() {
        List<Found> found = new ArrayList<>();
        for (Detector detector : detectors) {
            Map<String, Tally> values = tallies.get(detector.id());
            if (values == null) {
                continue;
            }
            Collection<Tally> each = values.values();
            for (Tally tally : each) {
                List<Occurrence> sorted = new ArrayList<>(tally.kept);
                sorted.sort(java.util.Comparator.comparingLong(Occurrence::position));
                found.add(new Found(detector, tally.number, tally.count, List.copyOf(sorted)));
            }
        }
        // The values are dropped with this object; what leaves is numbers and places.
        tallies.clear();
        return new Result(List.copyOf(found), ignored, Map.copyOf(uncounted));
    }

    /** A run of single bytes as characters, without copying it. */
    private record Ascii(byte[] data, int from, int to) implements CharSequence {

        @Override
        public int length() {
            return to - from;
        }

        @Override
        public char charAt(int index) {
            return (char) (data[from + index] & 0xff);
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new Ascii(data, from + start, from + end);
        }

        @Override
        public String toString() {
            // seclume-allow: the searcher holds what it found to tell values apart; it never reports them
            return new String(data, from, to - from, java.nio.charset.StandardCharsets.ISO_8859_1);
        }
    }

    /** A run of two-byte characters, every one of them printable ASCII. */
    private record Utf16(byte[] data, int from, int to, boolean bigEndian) implements CharSequence {

        @Override
        public int length() {
            return (to - from) / 2;
        }

        @Override
        public char charAt(int index) {
            int at = from + 2 * index;
            return (char) (data[bigEndian ? at + 1 : at] & 0xff);
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new Utf16(data, from + 2 * start, from + 2 * end, bigEndian);
        }

        @Override
        public String toString() {
            StringBuilder text = new StringBuilder(length());
            for (int i = 0; i < length(); i++) {
                text.append(charAt(i));
            }
            return text.toString();
        }
    }

    /** One line per detector, for {@code --list-detectors}. */
    public static String describe() {
        StringBuilder out = new StringBuilder();
        for (Detector detector : DETECTORS) {
            out.append(String.format(Locale.ROOT, "%-24s %s%n", detector.id(), detector.name()));
        }
        return out.toString();
    }
}
