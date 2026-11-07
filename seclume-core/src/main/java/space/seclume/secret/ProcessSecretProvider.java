package space.seclume.secret;

import java.io.File;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import space.seclume.internal.OffHeapIo;
import space.seclume.internal.Platform;

/**
 * A helper program delivers the secret - {@code aws secretsmanager},
 * {@code pass}, {@code gcloud secrets}, or a script of your own.
 *
 * <p>The obvious route via {@link Process#getInputStream()} is
 * <b>inadmissible</b> here: its {@code read} fills a {@code byte[]}, and the
 * secret would sit on the heap before the library ever sees it. Instead the
 * helper writes into a FIFO which is read with a direct buffer.
 *
 * <p>If the command contains the placeholder {@code {fifo}}, it is replaced by
 * the path (for commands that redirect themselves). Otherwise the helper's
 * standard output is attached to the FIFO.
 *
 * <p><b>Unix only.</b> Windows has no FIFO in the file system, and a named pipe
 * would be a different, larger mechanism. There {@link DpapiSecretProvider} and
 * {@link CredentialManagerSecretProvider} are the intended way; this class
 * throws rather than quietly falling back to something unsafe.
 */
public final class ProcessSecretProvider implements SecretProvider {

    private static final String FIFO_PLACEHOLDER = "{fifo}";

    private final List<String> command;
    private final int maxLength;
    private final long timeoutSeconds;

    public ProcessSecretProvider(List<String> command, int maxLength) {
        this(command, maxLength, 30);
    }

    public ProcessSecretProvider(List<String> command, int maxLength, long timeoutSeconds) {
        if (command.isEmpty()) {
            throw new IllegalArgumentException("command must not be empty");
        }
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        this.command = List.copyOf(command);
        this.maxLength = maxLength;
        this.timeoutSeconds = timeoutSeconds;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        OffHeapIo.requireNative(target);
        if (Platform.isWindows()) {
            throw new SecretUnavailableException(
                    "ProcessSecretProvider needs a FIFO and is therefore Unix only; "
                    + "use the DPAPI or the Credential Manager provider on Windows");
        }
        Path directory = null;
        Path fifo = null;
        try {
            directory = Files.createTempDirectory("seclume-");
            fifo = directory.resolve("secret.fifo");
            makeFifo(fifo);

            List<String> effective = new ArrayList<>(command.size());
            boolean placeholder = false;
            for (String argument : command) {
                if (argument.contains(FIFO_PLACEHOLDER)) {
                    placeholder = true;
                    effective.add(argument.replace(FIFO_PLACEHOLDER, fifo.toString()));
                } else {
                    effective.add(argument);
                }
            }

            ProcessBuilder builder = new ProcessBuilder(effective);
            builder.redirectErrorStream(false);
            builder.redirectError(ProcessBuilder.Redirect.DISCARD);
            if (!placeholder) {
                builder.redirectOutput(ProcessBuilder.Redirect.to(new File(fifo.toString())));
            }
            // The read end is opened first, on a thread of its own. Opening a
            // FIFO waits for its other end, and with the helper's standard
            // output on the FIFO it is this JVM that opens the write end, in
            // builder.start(): opened in the other order, each waited for the
            // other, for ever - the standard-output form never worked.
            java.util.concurrent.CompletableFuture<FileChannel> opening =
                    new java.util.concurrent.CompletableFuture<>();
            Path pipe = fifo;
            Thread.ofVirtual().name("seclume-helper-fifo").start(() -> {
                try {
                    opening.complete(FileChannel.open(pipe, StandardOpenOption.READ));
                } catch (IOException | RuntimeException e) {
                    opening.completeExceptionally(e);
                }
            });
            Process process;
            try {
                process = builder.start();
            } catch (IOException | RuntimeException e) {
                release(pipe);
                opening.thenAccept(ProcessSecretProvider::closeQuietly);
                throw e;
            }

            // Opening the FIFO blocks until the helper has opened it for
            // writing, and reading it until the helper closes it - neither
            // with a timeout of its own. A helper that fails before it opens
            // the path it was given, or that never finishes, held this thread
            // for ever: a connection pool that never got its first
            // connection. The watchdog ends the helper at the timeout and, once
            // it is gone, releases the read by opening the FIFO itself.
            java.util.concurrent.atomic.AtomicBoolean reading =
                    new java.util.concurrent.atomic.AtomicBoolean(true);
            java.util.concurrent.atomic.AtomicBoolean timedOut =
                    new java.util.concurrent.atomic.AtomicBoolean();
            java.util.concurrent.atomic.AtomicReference<FileChannel> open =
                    new java.util.concurrent.atomic.AtomicReference<>();
            Thread watchdog = Thread.ofVirtual().name("seclume-helper-watchdog").start(() ->
                    watch(process, pipe, reading, timedOut, open));
            int read;
            FileChannel opened;
            try {
                opened = opening.get();                   // the watchdog releases it, if need be
            } catch (java.util.concurrent.ExecutionException e) {
                reading.set(false);
                throw new IOException("the FIFO could not be opened", e.getCause());
            }
            try (FileChannel channel = opened) {
                open.set(channel);
                read = OffHeapIo.readFully(channel, target);
                if (read == target.byteSize() && OffHeapIo.hasMore(channel)) {
                    throw new SecretUnavailableException(
                            "the helper produced more than the configured " + maxLength + " bytes");
                }
            } catch (IOException e) {
                if (timedOut.get()) {
                    target.fill((byte) 0);
                    throw new SecretUnavailableException("the helper " + command.get(0)
                            + " did not finish within " + timeoutSeconds + " seconds", e);
                }
                throw e;
            } finally {
                reading.set(false);
            }
            if (timedOut.get() || !process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new SecretUnavailableException(
                        "the helper " + command.get(0) + " did not finish within "
                        + timeoutSeconds + " seconds");
            }
            watchdog.join(TimeUnit.SECONDS.toMillis(5));
            if (process.exitValue() != 0) {
                throw new SecretUnavailableException(
                        "the helper " + command.get(0) + " failed with exit code "
                        + process.exitValue());
            }

            int length = OffHeapIo.trimLineBreak(target, read);
            if (length == 0) {
                throw new SecretUnavailableException(
                        "the helper " + command.get(0) + " produced nothing");
            }
            return length;
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot run " + command.get(0), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SecretUnavailableException("interrupted while waiting for " + command.get(0), e);
        } finally {
            deleteQuietly(fifo);
            deleteQuietly(directory);
        }
    }

    /**
     * Waits for the helper, ends it at the timeout, and then - while the read
     * is still waiting on the FIFO - opens the FIFO for reading and writing,
     * which never blocks: a reader waiting for a writer gets one, and when it
     * is closed again, the end of the stream.
     */
    private void watch(Process process, Path fifo,
            java.util.concurrent.atomic.AtomicBoolean reading,
            java.util.concurrent.atomic.AtomicBoolean timedOut,
            java.util.concurrent.atomic.AtomicReference<FileChannel> open) {
        try {
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                timedOut.set(true);
                process.destroyForcibly();
                process.waitFor(5, TimeUnit.SECONDS);
            }
            // The helper is gone. A read still waiting for it is released:
            // an open() waiting for a writer by one that comes and goes, a
            // read() at the timeout by closing its channel - a grandchild of
            // the helper may still hold the FIFO's other end.
            for (int round = 0; round < 50 && reading.get(); round++) {
                FileChannel reader = open.get();
                if (reader == null) {
                    if (!release(fifo)) {
                        return;                     // the FIFO is gone, so is the read
                    }
                } else if (timedOut.get()) {
                    try {
                        reader.close();
                    } catch (IOException ignored) {
                        // Closed is closed.
                    }
                }
                Thread.sleep(100);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Opens the FIFO for reading and writing and closes it again - which never
     * blocks, and lets an open() waiting for a writer return.
     *
     * @return false when the FIFO is not there any more
     */
    private static boolean release(Path fifo) {
        try {
            FileChannel.open(fifo, StandardOpenOption.READ, StandardOpenOption.WRITE).close();
            return true;
        } catch (IOException gone) {
            return false;
        }
    }

    private static void closeQuietly(FileChannel channel) {
        try {
            channel.close();
        } catch (IOException ignored) {
            // Closed is closed.
        }
    }

    /**
     * mkfifo by its absolute path where it is found: the pipe the secret
     * travels through is not made by whatever a PATH entry calls mkfifo.
     */
    private static String mkfifoExecutable() throws IOException {
        for (String executable : List.of("/usr/bin/mkfifo", "/bin/mkfifo")) {
            if (Files.isExecutable(Path.of(executable))) {
                return executable;
            }
        }
        throw new IOException("mkfifo is unavailable in /usr/bin and /bin");
    }

    private static void makeFifo(Path fifo) throws IOException, InterruptedException {
        Process mkfifo = new ProcessBuilder(mkfifoExecutable(), "-m", "600", fifo.toString())
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .start();
        if (!mkfifo.waitFor(10, TimeUnit.SECONDS) || mkfifo.exitValue() != 0) {
            throw new SecretUnavailableException("cannot create the FIFO " + fifo);
        }
    }

    private static void deleteQuietly(Path path) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // A left-over FIFO is empty - it carries no secret.
        }
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public String toString() {
        return "ProcessSecretProvider[command=" + command.get(0) + "]";
    }
}
