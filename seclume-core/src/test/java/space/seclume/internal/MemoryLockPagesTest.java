package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import org.junit.jupiter.api.Test;

/**
 * Two secrets on one page: releasing the first must leave the page locked and
 * out of dumps for the second. munlock and madvise work on whole pages and
 * count nothing, so MemoryLock counts for them.
 */
class MemoryLockPagesTest {

    @Test
    void aPageIsReleasedOnlyWithTheLastSecretOnIt() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment page = arena.allocate(4096, 4096);
            MemorySegment first = page.asSlice(0, 64);
            MemorySegment second = page.asSlice(1024, 64);
            int before = MemoryLock.pagesInUse();

            MemoryLock.lock(first);
            MemoryLock.lock(second);
            assertEquals(before + 1, MemoryLock.pagesInUse(), "one page, counted once");

            MemoryLock.unlock(first);
            assertEquals(before + 1, MemoryLock.pagesInUse(),
                    "the page was released while the second secret still lives on it");

            MemoryLock.unlock(second);
            assertEquals(before, MemoryLock.pagesInUse());
        }
    }

    @Test
    void aSecretAcrossTwoPagesHoldsBoth() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pages = arena.allocate(8192, 4096);
            MemorySegment straddling = pages.asSlice(4000, 200);
            MemorySegment onTheSecond = pages.asSlice(6000, 16);
            int before = MemoryLock.pagesInUse();

            MemoryLock.lock(straddling);
            MemoryLock.lock(onTheSecond);
            assertEquals(before + 2, MemoryLock.pagesInUse());

            MemoryLock.unlock(straddling);
            assertEquals(before + 1, MemoryLock.pagesInUse(), "only the first page is free");

            MemoryLock.unlock(onTheSecond);
            assertEquals(before, MemoryLock.pagesInUse());
        }
    }
}
