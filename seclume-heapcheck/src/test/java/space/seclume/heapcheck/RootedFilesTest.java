package space.seclume.heapcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * The process's files, opened by the kernel inside its root. Here the process
 * is this one, whose root is this file system, so a link cannot be shown to
 * leave it (seclume-heapcheck/proof/run-rooted.sh does that with a container);
 * what can be shown is everything else a hostile process could plant: a FIFO
 * that would block the check, a magic link out of the root, and a link the
 * deletion must remove rather than follow. Linux 5.6 or later.
 */
@Timeout(30)
class RootedFilesTest {

    private static final String SELF = Long.toString(ProcessHandle.current().pid());

    @BeforeEach
    void linuxOnly() {
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.isDirectory(Path.of("/proc/self/root")),
                "openat2 through /proc/<pid>/root is Linux's");
    }

    @Test
    void aFileIsReadByItsDescriptor(@TempDir Path directory) throws IOException {
        Path file = Files.writeString(directory.resolve("dump.hprof"), "contents");
        try (RootedFiles rooted = RootedFiles.of(SELF)) {
            Path opened = rooted.open(file);
            assertTrue(opened.toString().startsWith("/proc/self/fd/"), opened.toString());
            Files.delete(file);                      // gone by name, still read by descriptor
            assertEquals("contents", Files.readString(opened));
        }
    }

    @Test
    void whatIsNotThereIsNull(@TempDir Path directory) throws IOException {
        try (RootedFiles rooted = RootedFiles.of(SELF)) {
            assertNull(rooted.open(directory.resolve("missing")));
            assertNull(rooted.open(directory.resolve("no/such/dir")));
            assertFalse(rooted.delete(directory.resolve("missing")));
            assertFalse(rooted.exists(directory.resolve("missing")));
        }
    }

    @Test
    void aFifoIsRefusedWithoutBlocking(@TempDir Path directory) throws Exception {
        Path fifo = directory.resolve("fifo");
        assertEquals(0, new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor());
        try (RootedFiles rooted = RootedFiles.of(SELF)) {
            IOException refused = assertThrows(IOException.class, () -> rooted.open(fifo));
            assertTrue(refused.getMessage().contains("not a regular file"), refused.getMessage());
        }
    }

    @Test
    void aMagicLinkIsRefused(@TempDir Path directory) throws IOException {
        Path magic = Files.createSymbolicLink(directory.resolve("magic"), Path.of("/proc/1/root"));
        try (RootedFiles rooted = RootedFiles.of(SELF)) {
            assertThrows(IOException.class, () -> rooted.open(magic.resolve("etc/hostname")));
        }
    }

    @Test
    void deletingALinkRemovesTheLinkNotItsTarget(@TempDir Path directory) throws IOException {
        Path target = Files.writeString(directory.resolve("precious"), "keep me");
        Path link = Files.createSymbolicLink(directory.resolve("dump.hprof"), target);
        try (RootedFiles rooted = RootedFiles.of(SELF)) {
            assertTrue(rooted.exists(link));
            assertTrue(rooted.delete(link));
        }
        assertFalse(Files.exists(link, java.nio.file.LinkOption.NOFOLLOW_LINKS));
        assertEquals("keep me", Files.readString(target));
    }

    @Test
    void aProcessIdIsNumbers() {
        assertThrows(IOException.class, () -> RootedFiles.of("1/../../etc"));
    }
}
