package space.seclume.heapcheck;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;

/**
 * --dump-dir names a directory the check and the process share. One that is
 * not shared left the dump in the process's file system, and the check said
 * "could not check process ... - <the missing file>", nothing of where the
 * dump went or what to do. It names both now; the dump is deleted there and
 * that is said as well.
 */
class DumpDirNotSharedTest {

    @Test
    void theMessageSaysWhereTheDumpWentAndWhatToDo() {
        String said = HeapCheck.notSharedMessage("4711", Path.of("/dumps/x.hprof"),
                Path.of("/dumps/x.hprof"));
        assertTrue(said.contains("process 4711 wrote its dump to"), said);
        assertTrue(said.contains("share"), said);
        assertTrue(said.contains("--in-target"), said);
        assertTrue(said.contains("/proc/4711/root"), said);
        assertTrue(said.endsWith("Nothing was checked"), said);
    }
}
