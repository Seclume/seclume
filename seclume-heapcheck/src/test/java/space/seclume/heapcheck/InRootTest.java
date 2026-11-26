package space.seclume.heapcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Read through {@code /proc/<pid>/root}, a link the examined process placed
 * was followed in this file system: {@code /tmp/d.hprof -> /etc/shadow}
 * read, and deleted, the host's file. Links are resolved inside the
 * process's root now - an absolute target from that root, {@code ..} never
 * above it - while a Kubernetes secret's relative {@code ..data} links still
 * lead where they should.
 */
class InRootTest {

    @TempDir
    Path directory;

    private Path root;

    @BeforeEach
    void aRoot() throws Exception {
        root = Files.createDirectories(directory.resolve("root"));
        Assumptions.assumeTrue(Files.getFileStore(root).supportsFileAttributeView("posix"),
                "links need privileges on Windows");
    }

    @Test
    void anAbsoluteLinkStaysInsideTheRoot() throws Exception {
        Files.createDirectories(root.resolve("tmp"));
        Files.createDirectories(root.resolve("etc"));
        Files.createSymbolicLink(root.resolve("tmp/d.hprof"), Path.of("/etc/shadow"));
        assertEquals(root.resolve("etc").resolve("shadow"),
                HeapCheck.inRoot(root, Path.of("tmp/d.hprof")));
    }

    @Test
    void dotDotDoesNotClimbAboveTheRoot() throws Exception {
        Files.createDirectories(root.resolve("tmp"));
        Files.createSymbolicLink(root.resolve("tmp/up"), Path.of("../../../../outside"));
        assertEquals(root.resolve("outside"), HeapCheck.inRoot(root, Path.of("tmp/up")));
    }

    @Test
    void aSecretVolumesRelativeLinksLeadWhereTheyShould() throws Exception {
        Path volume = Files.createDirectories(root.resolve("etc/secrets"));
        Path data = Files.createDirectories(volume.resolve("..2026_11_26"));
        Files.writeString(data.resolve("password"), "x");
        Files.createSymbolicLink(volume.resolve("..data"), Path.of("..2026_11_26"));
        Files.createSymbolicLink(volume.resolve("password"), Path.of("..data/password"));
        assertEquals(data.resolve("password"),
                HeapCheck.inRoot(root, Path.of("etc/secrets/password")));
    }

    @Test
    void aFileNotWrittenYetIsTakenAsItStands() {
        assertEquals(root.resolve("tmp").resolve("later.hprof"),
                HeapCheck.inRoot(root, Path.of("tmp/later.hprof")));
    }

    @Test
    void aLoopOfLinksEnds() throws Exception {
        Files.createSymbolicLink(root.resolve("a"), Path.of("b"));
        Files.createSymbolicLink(root.resolve("b"), Path.of("a"));
        assertThrows(IllegalArgumentException.class, () -> HeapCheck.inRoot(root, Path.of("a")));
    }
}
