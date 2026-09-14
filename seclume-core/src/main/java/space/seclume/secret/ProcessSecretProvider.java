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
            Process process = builder.start();

            // Opening the FIFO blocks until the helper has opened it for
            // writing - that is the synchronisation, nothing more is needed.
            int read;
            try (FileChannel channel = FileChannel.open(fifo, StandardOpenOption.READ)) {
                read = OffHeapIo.readFully(channel, target);
                if (read == target.byteSize() && OffHeapIo.hasMore(channel)) {
                    throw new SecretUnavailableException(
                            "the helper produced more than the configured " + maxLength + " bytes");
                }
            }

            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new SecretUnavailableException(
                        "the helper " + command.get(0) + " did not finish within "
                        + timeoutSeconds + " seconds");
            }
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

    private static void makeFifo(Path fifo) throws IOException, InterruptedException {
        Process mkfifo = new ProcessBuilder("mkfifo", "-m", "600", fifo.toString())
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
