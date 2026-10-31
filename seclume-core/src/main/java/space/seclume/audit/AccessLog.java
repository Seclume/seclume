package space.seclume.audit;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.PrivateSigningKey;
import space.seclume.secret.SecretProvider;

/**
 * Who read which secret, when - in a log whose entries are chained by hash and
 * whose head is signed at intervals, so that an entry changed, removed or
 * slipped in afterwards is found ({@link AccessLogVerifier}).
 *
 * <h2>What is recorded</h2>
 *
 * <p>Every secret a provider is asked for ({@code secret.read}: the kind of
 * provider, its own description - a path, a Vault URL - the thread, the
 * outcome and, when it failed, the exception's type), every field encryption
 * key ring that is built ({@code data-key.ring}) and every private key opened
 * ({@code private-key.opened}). <b>Facts, never values</b> - not the secret,
 * not its length, not a hash of it: the log is meant to be read by more
 * people than the secrets are.
 *
 * <h2>The format</h2>
 *
 * <p>One JSON object per line, ASCII only, the fields in a fixed order:
 *
 * <pre>
 *   {"seq":7,"time":"2026-10-31T09:14:03.120Z","event":"secret.read","provider":"vault",
 *    "source":"VaultSecretProvider[https://vault:8200/v1/database/creds/app]",
 *    "thread":"pool-1","outcome":"ok","prev":"&lt;hash of entry 6&gt;","hash":"&lt;this entry's&gt;"}
 * </pre>
 *
 * <p>{@code hash} is SHA-256 over the line as it would read without its
 * {@code hash} field; {@code prev} is the previous entry's, 64 zeros for the
 * first. A {@code checkpoint} entry carries {@code head}, the hash of the entry
 * before it, and a signature over {@code "seclume-access-log-1" || seq || head}
 * with the log's signing key - a key the application holds in OpenSSL, CNG or
 * a KMS, so that whoever can write the file cannot sign for it. Checkpoints are
 * written every {@code checkpointEvery}, and when the log is closed.
 *
 * <h2>What it proves, and what not</h2>
 *
 * <p>An entry changed or removed in the middle breaks the chain; a forged
 * chain breaks at the next signature. Entries removed from the end - with the
 * checkpoints after them - leave a shorter, valid log: that is noticed only
 * against a checkpoint kept somewhere else, which is what a {@link #addSink
 * sink} is for - OpenTelemetry, syslog, a SIEM receive every entry as it is
 * written. And it records what seclume was asked for: code that reads a secret
 * past seclume is not in it.
 */
public final class AccessLog implements AutoCloseable {

    /** What a signature covers, before the sequence number and the head. */
    static final String DOMAIN = "seclume-access-log-1";
    static final String ZERO = "0".repeat(64);

    /** One entry as written. */
    public record Entry(long seq, Instant time, String event, Map<String, String> fields,
            String prev, String hash, String line) {
    }

    private static final AtomicReference<AccessLog> INSTALLED = new AtomicReference<>();

    private final Path file;
    private final FileChannel channel;
    private final FileLock lock;
    private final PrivateSigningKey signer;
    private final String signerAlgorithm;
    private final String signerKey;
    private final List<Consumer<Entry>> sinks = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService timer;
    private long seq;
    private String head;
    private long sinceCheckpoint;
    private boolean closed;

    private AccessLog(Path file, PrivateSigningKey signer, Duration checkpointEvery)
            throws IOException {
        this.file = file;
        this.signer = signer;
        this.signerAlgorithm = signer == null ? null : algorithmOf(signer);
        this.signerKey = signer == null ? null : fingerprint(signer.publicKey());
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        String[] last = lastEntry(file);
        this.seq = last == null ? 0 : Long.parseLong(last[0]);
        this.head = last == null ? ZERO : last[1];
        this.channel = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.APPEND);
        FileLock taken;
        try {
            taken = channel.tryLock();
        } catch (java.nio.channels.OverlappingFileLockException e) {
            channel.close();
            throw new IOException(file + " is already open for writing in this process - one log, "
                    + "one writer", e);
        } catch (IOException | RuntimeException e) {
            channel.close();
            throw e;
        }
        if (taken == null) {
            channel.close();
            throw new IOException(file + " is being written by another process - one log, one writer");
        }
        this.lock = taken;
        Map<String, String> opened = new LinkedHashMap<>();
        opened.put("pid", Long.toString(ProcessHandle.current().pid()));
        opened.put("signing", signer == null ? "none" : signerAlgorithm + " " + signerKey);
        append("log.opened", opened);
        if (signer != null && checkpointEvery != null && !checkpointEvery.isZero()
                && !checkpointEvery.isNegative()) {
            timer = Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread thread = new Thread(runnable, "seclume-access-log-checkpoint");
                thread.setDaemon(true);
                return thread;
            });
            long millis = Math.max(1, checkpointEvery.toMillis());
            timer.scheduleAtFixedRate(this::checkpointQuietly, millis, millis, TimeUnit.MILLISECONDS);
        } else {
            timer = null;
        }
    }

    /**
     * Opens {@code file} for appending, continuing its chain if it has one.
     *
     * @param signer          signs the checkpoints, or {@code null} for a chain without
     *                        signatures - which proves far less, see the class comment
     * @param checkpointEvery how often a checkpoint is signed; {@code null} or zero for
     *                        only on {@link #checkpoint()} and {@link #close()}
     */
    public static AccessLog open(Path file, PrivateSigningKey signer, Duration checkpointEvery)
            throws IOException {
        return new AccessLog(file, signer, checkpointEvery);
    }

    /** Makes {@code log} the one the library's own hooks write to; returns the one before. */
    public static AccessLog install(AccessLog log) {
        return INSTALLED.getAndSet(log);
    }

    /** The installed log, or {@code null}. */
    public static AccessLog installed() {
        return INSTALLED.get();
    }

    /** Every entry, as it is written, to {@code sink} as well - an exporter, a SIEM. */
    public void addSink(Consumer<Entry> sink) {
        sinks.add(sink);
    }

    /** The file. */
    public Path file() {
        return file;
    }

    // ------------------------------------------------------------- the hooks

    /**
     * A secret was asked of {@code provider}; {@code failure} when that failed.
     * Called by {@code SecretScope}; never throws an exception.
     */
    public static void secretRead(SecretProvider provider, Throwable failure) {
        AccessLog log = INSTALLED.get();
        if (log == null || provider == null) {
            return;
        }
        try {
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("provider", space.seclume.inventory.CryptoInventory.kindOf(provider));
            fields.put("source", describe(provider));
            fields.put("thread", Thread.currentThread().getName());
            fields.put("outcome", failure == null ? "ok" : "failed");
            if (failure != null) {
                fields.put("error", failure.getClass().getName());
            }
            log.append("secret.read", fields);
        } catch (IOException | RuntimeException ignored) {
            // the log never stands in the way of a login
        }
    }

    /** Anything else worth recording - a key ring built, a private key opened. Never throws. */
    public static void event(String event, Map<String, String> fields) {
        AccessLog log = INSTALLED.get();
        if (log == null) {
            return;
        }
        try {
            Map<String, String> all = new LinkedHashMap<>(fields);
            all.putIfAbsent("thread", Thread.currentThread().getName());
            log.append(event, all);
        } catch (IOException | RuntimeException ignored) {
            // best effort
        }
    }

    // ------------------------------------------------------------- writing

    /** Writes one entry; returns it. */
    synchronized Entry append(String event, Map<String, String> fields) throws IOException {
        if (closed) {
            throw new IOException("the access log is closed");
        }
        long next = seq + 1;
        String prev = head;
        Instant time = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        StringBuilder body = new StringBuilder(256).append("{\"seq\":").append(next)
                .append(",\"time\":").append(string(time.toString()))
                .append(",\"event\":").append(string(event));
        for (Map.Entry<String, String> field : fields.entrySet()) {
            body.append(',').append(string(field.getKey())).append(':')
                    .append(string(field.getValue() == null ? "" : field.getValue()));
        }
        body.append(",\"prev\":").append(string(prev));
        String hash = sha256(body + "}");
        String line = body + ",\"hash\":" + string(hash) + "}\n";
        write(line);
        seq = next;
        head = hash;
        sinceCheckpoint++;
        Entry entry = new Entry(next, time, event, Map.copyOf(fields), prev, hash,
                line.substring(0, line.length() - 1));
        for (Consumer<Entry> sink : sinks) {
            try {
                sink.accept(entry);
            } catch (RuntimeException ignored) {
                // a sink that fails does not stop the log
            }
        }
        return entry;
    }

    /**
     * Signs the head now - nothing when nothing was written since the last
     * checkpoint, or when the log has no signing key.
     */
    public synchronized void checkpoint() throws IOException {
        if (signer == null || sinceCheckpoint == 0 || closed) {
            return;
        }
        long next = seq + 1;
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("head", head);
        fields.put("algorithm", signerAlgorithm);
        fields.put("key", signerKey);
        fields.put("signature", sign(next, head));
        append("checkpoint", fields);
        sinceCheckpoint = 0;
        channel.force(false);
    }

    private void checkpointQuietly() {
        try {
            checkpoint();
        } catch (IOException | RuntimeException ignored) {
            // the next one will try again
        }
    }

    /** A last checkpoint, and the file closed. Uninstalls the log if it is the installed one. */
    @Override
    public synchronized void close() throws IOException {
        if (closed) {
            return;
        }
        INSTALLED.compareAndSet(this, null);
        if (timer != null) {
            timer.shutdownNow();
        }
        try {
            checkpoint();
        } finally {
            closed = true;
            try {
                lock.release();
            } finally {
                channel.close();
            }
        }
    }

    private void write(String line) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment bytes = ascii(arena, line);
            ByteBuffer view = bytes.asByteBuffer();
            while (view.hasRemaining()) {
                channel.write(view);
            }
        }
    }

    private String sign(long checkpointSeq, String headHex) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment message = signedMessage(arena, checkpointSeq, headHex);
            MemorySegment signature = arena.allocate(PrivateSigningKey.MAX_SIGNATURE);
            String digest = signerAlgorithm.equals("Ed25519") ? null : "SHA256";
            int n = signer.sign(digest, false, message, message.byteSize(), signature);
            return hex(signature, n);
        }
    }

    /** {@code DOMAIN || seq (8 bytes, big-endian) || head (32 bytes)}. */
    static MemorySegment signedMessage(Arena arena, long checkpointSeq, String headHex) {
        MemorySegment message = arena.allocate(DOMAIN.length() + 8L + 32);
        for (int i = 0; i < DOMAIN.length(); i++) {
            message.set(ValueLayout.JAVA_BYTE, i, (byte) DOMAIN.charAt(i));
        }
        message.set(ValueLayout.JAVA_LONG_UNALIGNED.withOrder(java.nio.ByteOrder.BIG_ENDIAN),
                DOMAIN.length(), checkpointSeq);
        for (int i = 0; i < 32; i++) {
            int b = Character.digit(headHex.charAt(2 * i), 16) << 4
                    | Character.digit(headHex.charAt(2 * i + 1), 16);
            message.set(ValueLayout.JAVA_BYTE, DOMAIN.length() + 8L + i, (byte) b);
        }
        return message;
    }

    private static String algorithmOf(PrivateSigningKey key) {
        if (key.is("EC")) {
            return "SHA256withECDSA";
        }
        if (key.is("ED25519")) {
            return "Ed25519";
        }
        if (key.is("RSA") && !key.is("RSA-PSS")) {
            return "SHA256withRSA";
        }
        throw new IllegalArgumentException("the access log signs with an EC, Ed25519 or RSA key");
    }

    /** SHA-256 of a public key's DER, hex - how a checkpoint names its key. */
    static String fingerprint(byte[] publicKey) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment der = arena.allocate(Math.max(1, publicKey.length));
            MemorySegment.copy(publicKey, 0, der, ValueLayout.JAVA_BYTE, 0, publicKey.length);
            MemorySegment out = arena.allocate(32);
            HashAlgorithm.SHA_256.hash(der, 0, publicKey.length, out, 0);
            return hex(out, 32);
        }
    }

    /** SHA-256 of an ASCII line, hex. */
    static String sha256(String ascii) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment bytes = ascii(arena, ascii);
            MemorySegment out = arena.allocate(32);
            HashAlgorithm.SHA_256.hash(bytes, 0, bytes.byteSize(), out, 0);
            return hex(out, 32);
        }
    }

    private static MemorySegment ascii(Arena arena, String text) {
        MemorySegment bytes = arena.allocate(Math.max(1, text.length()));
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c > 0x7e) {
                throw new IllegalArgumentException("an access log line is ASCII");
            }
            bytes.set(ValueLayout.JAVA_BYTE, i, (byte) c);
        }
        return bytes.asSlice(0, text.length());
    }

    static String hex(MemorySegment bytes, int length) {
        StringBuilder out = new StringBuilder(2 * length);
        for (int i = 0; i < length; i++) {
            int b = bytes.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            out.append(Character.forDigit(b >>> 4, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }

    /** A JSON string in ASCII: everything outside printable ASCII as {@code \}{@code uXXXX}. */
    static String string(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20 || c > 0x7e) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private static String describe(SecretProvider provider) {
        String said;
        try {
            said = provider.toString();
        } catch (RuntimeException e) {
            said = null;
        }
        String kind = space.seclume.inventory.CryptoInventory.kindOf(provider);
        if (said == null || said.startsWith(provider.getClass().getName() + "@")) {
            return kind;
        }
        return said.length() > 200 ? said.substring(0, 200) + "..." : said;
    }

    /** The last complete entry's {@code seq} and {@code hash}, or {@code null} for an empty file. */
    private static String[] lastEntry(Path file) throws IOException {
        if (!Files.exists(file) || Files.size(file) == 0) {
            return null;
        }
        long size = Files.size(file);
        int window = (int) Math.min(size, 1 << 16);
        try (FileChannel in = FileChannel.open(file, StandardOpenOption.READ);
             Arena arena = Arena.ofConfined()) {
            MemorySegment tail = arena.allocate(window);
            ByteBuffer view = tail.asByteBuffer();
            in.position(size - window);
            while (view.hasRemaining() && in.read(view) >= 0) {
                // read the window
            }
            StringBuilder text = new StringBuilder(window);
            for (int i = 0; i < window; i++) {
                text.append((char) (tail.get(ValueLayout.JAVA_BYTE, i) & 0xff));
            }
            List<String> lines = new ArrayList<>(List.of(text.toString().split("\n")));
            if (!text.toString().endsWith("\n")) {
                throw new IOException(file + " ends in a torn line - it was cut off while being "
                        + "written; check it with AccessLogVerifier before writing on");
            }
            String last = lines.get(lines.size() - 1);
            Map<String, String> fields = AccessLogVerifier.fields(last);
            if (fields == null || fields.get("seq") == null || fields.get("hash") == null) {
                throw new IOException(file + " does not end in an access log entry");
            }
            return new String[] {fields.get("seq"), fields.get("hash")};
        }
    }
}
