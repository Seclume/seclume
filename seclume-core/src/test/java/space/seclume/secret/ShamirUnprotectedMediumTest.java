package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * On a file system with neither POSIX permissions nor ACLs - FAT32, exFAT, a
 * network share; here a zip file system, which has neither - a share was
 * written with the medium's defaults and nothing said so. It is refused now.
 */
class ShamirUnprotectedMediumTest {

    @Test
    void aShareIsNotWrittenWhereNobodyCanBeKeptFromReadingIt(@TempDir Path directory)
            throws Exception {
        Path zip = directory.resolve("medium.zip");
        try (FileSystem medium = FileSystems.newFileSystem(
                URI.create("jar:" + zip.toUri()), Map.of("create", "true"))) {
            assertFalse(medium.supportedFileAttributeViews().contains("posix"));
            assertFalse(medium.supportedFileAttributeViews().contains("acl"));
            Path share = medium.getPath("/share-1-of-3.txt");
            Method write = ShamirShares.class.getDeclaredMethod("write", Path.class,
                    MemorySegment.class, int.class);
            write.setAccessible(true);
            MemorySegment text = MemorySegment.ofArray("decoy-share".getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII));
            InvocationTargetException failed = assertThrows(InvocationTargetException.class,
                    () -> write.invoke(null, share, text, 11));
            assertInstanceOf(IOException.class, failed.getCause());
            assertTrue(failed.getCause().getMessage().contains("allowUnprotected"),
                    failed.getCause().getMessage());
            assertFalse(Files.exists(share), "a refused share is not left behind");
        }
    }
}
