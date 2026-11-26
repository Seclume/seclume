package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The sidecar took a link named {@code *.hprof} for a dump: it read the file
 * the link pointed to - anywhere the process could reach - and redacted and
 * deleted it as one. A link is no dump now.
 */
class DumpFolderLinkTest {

    @TempDir
    Path directory;

    @Test
    void aLinkNamedLikeADumpIsNoCandidate() throws Exception {
        Path folder = Files.createDirectories(directory.resolve("dumps"));
        Assumptions.assumeTrue(Files.getFileStore(folder).supportsFileAttributeView("posix"),
                "links need privileges on Windows");
        Path elsewhere = Files.writeString(directory.resolve("elsewhere.txt"), "not a dump");
        Files.createSymbolicLink(folder.resolve("java_pid1.hprof"), elsewhere);
        Path real = Files.write(folder.resolve("java_pid2.hprof"), new byte[] {1, 2, 3});

        assertEquals(List.of(real), DumpFolder.candidates(folder));
        assertTrue(Files.exists(elsewhere), "what the link pointed to is untouched");
    }
}
