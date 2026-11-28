package space.seclume.internal;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/**
 * Secret pages the kernel keeps even from itself: {@code memfd_secret(2)},
 * Linux 5.14 on (by default from 6.5). Its pages are removed from the
 * kernel's direct map: they are locked in RAM, are in no core dump, and
 * {@code ptrace}, {@code /proc/<pid>/mem} and {@code process_vm_readv} cannot
 * read them - not for another process of the same user, and not for root
 * without a kernel exploit. What {@code mlock} and {@code MADV_DONTDUMP} do
 * for a page is part of it; what they leave open - another process with the
 * right to read this one's memory - is closed.
 *
 * <p>A secret is small and short-lived, a page is neither: secret pages are
 * mapped in chunks and handed out in blocks of powers of two, a block wiped
 * and taken back when the arena its segment belongs to closes. Before a
 * checkpoint the chunks with nothing in them are given back to the kernel.
 *
 * <p>{@code seclume.secretmem}: {@code true} (the default) uses it where the
 * kernel offers it and says once, loudly, where it does not - the secret then
 * goes into pages {@link MemoryLock} pins as before; {@code required} refuses
 * a secret it cannot put there; {@code false} does without, and is named among
 * the weakened settings.
 */
public final class SecretMemory {

    private static final Logger LOG = System.getLogger(SecretMemory.class.getName());

    /** How {@code seclume.secretmem} is set. */
    enum Mode { ON, OFF, REQUIRED }

    static final Mode MODE = mode(System.getProperty("seclume.secretmem"));

    /** memfd_secret's number in the generic syscall table, which x86-64 and arm64 share. */
    private static final long SYS_MEMFD_SECRET = 447;
    private static final int PROT_READ_WRITE = 0x1 | 0x2;
    private static final int MAP_SHARED = 0x01;
    /** A chunk of secret pages: sixteen of them. */
    static final long CHUNK = 64 * 1024;
    private static final int SMALLEST = 16;
    /** Not an errno: the call itself failed. */
    private static final long UNCALLABLE = 100_000;

    private static final MethodHandle SYSCALL;
    private static final MethodHandle FTRUNCATE;
    private static final MethodHandle MMAP;
    private static final MethodHandle MUNMAP;
    private static final MethodHandle MADVISE;
    /** Faults every page of a range in for writing, or fails with an errno: Linux 5.14 on. */
    private static final int MADV_POPULATE_WRITE = 23;
    private static final MethodHandle CLOSE;
    private static final VarHandle ERRNO;
    private static final long ERRNO_SIZE;

    /** Why it is not used, or null while it is; decided once, at the first secret. */
    private static volatile String unavailable;
    private static volatile boolean decided;
    private static volatile boolean warned;

    /** Free blocks by size class: index i holds blocks of {@code SMALLEST << i} bytes. */
    private static final List<ArrayDeque<Long>> FREE = new ArrayList<>();
    /** Every chunk mapped, by base address, with how many of its blocks are lent out. */
    private static final java.util.TreeMap<Long, int[]> CHUNKS = new java.util.TreeMap<>();
    /** Mappings of their own, for a secret larger than a chunk: base address to length. */
    private static final java.util.Map<Long, Long> LARGE = new java.util.HashMap<>();
    private static final Object LOCK = new Object();

    static {
        MethodHandle syscall = null;
        MethodHandle ftruncate = null;
        MethodHandle mmap = null;
        MethodHandle munmap = null;
        MethodHandle madvise = null;
        MethodHandle close = null;
        VarHandle errno = null;
        long errnoSize = 0;
        if (Platform.isLinux() && MODE != Mode.OFF && knownArchitecture()) {
            try {
                Linker linker = Linker.nativeLinker();
                SymbolLookup libc = linker.defaultLookup();
                var state = Linker.Option.captureStateLayout();
                errno = state.varHandle(java.lang.foreign.MemoryLayout.PathElement.groupElement("errno"));
                errnoSize = state.byteSize();
                // long syscall(long number, ...);
                syscall = linker.downcallHandle(libc.find("syscall").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                                ValueLayout.JAVA_INT),
                        Linker.Option.firstVariadicArg(1), Linker.Option.captureCallState("errno"));
                // int ftruncate(int fd, off_t length);
                ftruncate = linker.downcallHandle(libc.find("ftruncate").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                                ValueLayout.JAVA_LONG), Linker.Option.captureCallState("errno"));
                // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
                mmap = linker.downcallHandle(libc.find("mmap").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                                ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG),
                        Linker.Option.captureCallState("errno"));
                // int munmap(void *addr, size_t length);
                munmap = linker.downcallHandle(libc.find("munmap").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                                ValueLayout.JAVA_LONG));
                // int madvise(void *addr, size_t length, int advice);
                madvise = linker.downcallHandle(libc.find("madvise").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                                ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT),
                        Linker.Option.captureCallState("errno"));
                // int close(int fd);
                close = linker.downcallHandle(libc.find("close").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
            } catch (RuntimeException e) {
                LOG.log(Level.DEBUG, "memfd_secret cannot be called on this platform", e);
                syscall = null;
            }
        }
        SYSCALL = syscall;
        FTRUNCATE = ftruncate;
        MMAP = mmap;
        MUNMAP = munmap;
        MADVISE = madvise;
        CLOSE = close;
        ERRNO = errno;
        ERRNO_SIZE = errnoSize;
        for (long size = SMALLEST; size <= CHUNK; size <<= 1) {
            FREE.add(new ArrayDeque<>());
        }
        // Before a checkpoint the chunks nothing is lent from go back to the
        // kernel: a secret mapping may not be one CRIU can write, and an empty
        // chunk is of no use in the image anyway.
        Checkpoint.register(LOCK, ignored -> releaseIdle());
    }

    private SecretMemory() {
    }

    static Mode mode(String setting) {
        if (setting == null || setting.isBlank() || setting.equalsIgnoreCase("true")) {
            return Mode.ON;
        }
        if (setting.equalsIgnoreCase("false")) {
            return Mode.OFF;
        }
        if (setting.equalsIgnoreCase("required")) {
            return Mode.REQUIRED;
        }
        throw new IllegalStateException("seclume.secretmem is true, false or required, not '"
                + setting + "'");
    }

    private static boolean knownArchitecture() {
        String arch = System.getProperty("os.arch", "");
        return arch.equals("amd64") || arch.equals("x86_64") || arch.equals("aarch64");
    }

    /** Whether secrets go into secret pages in this process. */
    public static boolean inUse() {
        decide();
        return unavailable == null;
    }

    /** Why they do not, or null when they do. */
    public static String unavailableBecause() {
        decide(); // mutation-equivalent: decided once per process: a call left out after the first finds it decided
        return unavailable;
    }

    /** Whether the setting is the opt-out - for the weakened settings. */
    public static boolean optedOut() {
        return MODE == Mode.OFF;
    }

    private static void decide() {
        if (decided) {
            return;
        }
        synchronized (LOCK) {
            if (decided) {
                return;
            }
            String why = null;
            if (MODE == Mode.OFF) {
                why = "seclume.secretmem=false";
            } else if (!Platform.isLinux()) {
                why = "memfd_secret is Linux's, and this is " + System.getProperty("os.name");
            } else if (SYSCALL == null) {
                why = "memfd_secret cannot be called on " + System.getProperty("os.arch");
            } else {
                // One chunk now: whether the kernel has it at all is seen at once.
                long base = map(CHUNK);
                if (base < 0) { // mutation-equivalent: no mapping is at address 0
                    why = reason(-base);
                } else {
                    addChunk(base);
                }
            }
            unavailable = why;
            decided = true;
        }
    }

    static String reason(long errno) {
        return switch ((int) errno) {
            case 38 -> "this kernel has no memfd_secret (ENOSYS: before Linux 6.5 it needs "
                    + "secretmem.enable=1 on the kernel command line)";
            case 12, 11 -> "the memlock limit leaves no room for secret pages (raise "
                    + "RLIMIT_MEMLOCK, ulimit -l)";
            case 1 -> "secret pages are not allowed here (EPERM - a seccomp profile?)";
            case (int) UNCALLABLE -> "memfd_secret could not be called";
            default -> "memfd_secret failed with errno " + errno;
        };
    }

    /**
     * {@code capacity} bytes of secret pages, belonging to {@code arena}: when
     * it closes, the block is wiped and taken back. Null where secret pages
     * are not used - the caller then allocates as before - unless
     * {@code seclume.secretmem=required}, where that is refused.
     */
    public static MemorySegment allocate(long capacity, Arena arena) {
        decide(); // mutation-equivalent: decided once per process: a call left out after the first finds it decided
        if (unavailable != null) {
            if (MODE == Mode.REQUIRED) {
                throw new IllegalStateException("seclume.secretmem=required, and " + unavailable);
            }
            // Only where a newer kernel or a boot parameter would give them:
            // Windows and macOS have nothing like it, and a warning nobody can
            // act on is noise.
            if (MODE == Mode.ON && !warned && Platform.isLinux()) { // mutation-equivalent: it decides a warning only, and the secret goes where it goes either way
                warned = true;
                LOG.log(Level.WARNING, "seclume: secrets go into locked pages, not into secret "
                        + "pages, because " + unavailable + ". Root and processes allowed to read "
                        + "this one's memory can read them there; -Dseclume.secretmem=false "
                        + "silences this, -Dseclume.secretmem=required refuses instead.");
            }
            return null;
        }
        long base;
        long size;
        synchronized (LOCK) {
            if (capacity > CHUNK) {
                size = (capacity + CHUNK - 1) / CHUNK * CHUNK;
                base = map(size);
                if (base < 0) { // mutation-equivalent: no mapping is at address 0
                    return refusedOrNull(-base); // mutation-equivalent: null either way where not required; with required, a refusal either way - the errno is in its words only
                }
                LARGE.put(base, size);
            } else {
                int index = sizeClass(capacity);
                size = (long) SMALLEST << index;
                Long block = FREE.get(index).poll();
                if (block == null) {
                    if (!split(index)) {
                        long chunk = map(CHUNK);
                        if (chunk < 0) { // mutation-equivalent: no mapping is at address 0
                            return refusedOrNull(-chunk); // mutation-equivalent: null either way where not required; with required, a refusal either way - the errno is in its words only
                        }
                        // A new chunk is one block of the largest class: split
                        // down to the one asked for (found in CI - a null block).
                        addChunk(chunk);
                        split(index);
                    }
                    block = FREE.get(index).poll();
                }
                base = block;
                CHUNKS.get(chunkOf(base))[0]++;
            }
        }
        long taken = base;
        long length = size;
        MemorySegment block = MemorySegment.ofAddress(taken).reinterpret(length);
        block.fill((byte) 0);
        return MemorySegment.ofAddress(taken).reinterpret(capacity, arena, ignored -> giveBack(taken, length));
    }

    /** A chunk could not be mapped now, though the kernel has secret pages - the memlock limit. */
    private static MemorySegment refusedOrNull(long errno) {
        if (MODE == Mode.REQUIRED) {
            throw new IllegalStateException("seclume.secretmem=required, and " + reason(errno));
        }
        if (!warnedFull) { // mutation-equivalent: it decides a warning only
            warnedFull = true;
            LOG.log(Level.WARNING, "seclume: secrets go into locked pages, not into secret pages, " // mutation-equivalent: a warning only
                    + "while " + reason(errno) + " - said once");
        }
        return null;
    }

    private static volatile boolean warnedFull;

    private static int sizeClass(long capacity) {
        long size = SMALLEST;
        int index = 0;
        while (size < capacity) {
            size <<= 1;
            index++;
        }
        return index;
    }

    /** Splits a larger free block into two of the class below, down to {@code index}. */
    private static boolean split(int index) {
        int larger = index + 1;
        while (larger < FREE.size() && FREE.get(larger).isEmpty()) {
            larger++;
        }
        if (larger >= FREE.size()) {
            return false;
        }
        while (larger > index) {
            long block = FREE.get(larger).poll();
            long half = (long) SMALLEST << (larger - 1);
            FREE.get(larger - 1).add(block);
            FREE.get(larger - 1).add(block + half);
            larger--;
        }
        return true;
    }

    private static void addChunk(long base) {
        CHUNKS.put(base, new int[1]);
        FREE.get(FREE.size() - 1).add(base);
    }

    /** The chunk {@code address} lies in: the one that starts at or below it. */
    private static long chunkOf(long address) {
        Long base = CHUNKS.floorKey(address);
        if (base == null) {
            throw new IllegalStateException("a secret block outside every chunk");
        }
        return base;
    }

    /** Wipes a block and takes it back - run when the arena of its segment closes. */
    private static void giveBack(long base, long size) {
        MemorySegment.ofAddress(base).reinterpret(size).fill((byte) 0);
        synchronized (LOCK) {
            Long large = LARGE.remove(base);
            if (large != null) {
                unmap(base, large);
                return;
            }
            FREE.get(sizeClass(size)).addFirst(base);   // used again first: fewer chunks half-used
            CHUNKS.get(chunkOf(base))[0]--;
        }
    }

    /** Gives every chunk nothing is lent from back to the kernel. */
    static int releaseIdle() {
        synchronized (LOCK) {
            int released = 0;
            for (var chunk : new ArrayList<>(CHUNKS.entrySet())) {
                if (chunk.getValue()[0] != 0) {
                    continue;
                }
                long base = chunk.getKey();
                for (ArrayDeque<Long> free : FREE) {
                    free.removeIf(block -> chunkOf(block) == base);
                }
                CHUNKS.remove(base);
                unmap(base, CHUNK);
                released++;
            }
            return released;
        }
    }

    /** Blocks lent out now - for tests and diagnostics. */
    static int lent() {
        synchronized (LOCK) {
            int lent = LARGE.size();
            for (int[] count : CHUNKS.values()) {
                lent += count[0];
            }
            return lent;
        }
    }

    /** Chunks mapped now - for tests. */
    static int chunks() {
        synchronized (LOCK) {
            return CHUNKS.size();
        }
    }

    /**
     * Tests only: pages from somewhere else - ordinary memory - so that the
     * pool's handing out and taking back is tested where the kernel has no
     * secret pages. {@link #useForTests} sets it.
     */
    private static volatile java.util.function.LongUnaryOperator mapForTests;

    /** What {@link #useForTests} set aside, to put back: the process's own pool. */
    private static Object[] saved;

    /**
     * Tests only: an empty pool, its pages from {@code mapper}; null puts the
     * process's own pool back as it was - where the kernel's secret pages are
     * in use, blocks lent from them outside the test come back to it later.
     */
    @SuppressWarnings("unchecked")
    static void useForTests(java.util.function.LongUnaryOperator mapper) {
        synchronized (LOCK) {
            if (mapper != null && saved == null) { // mutation-equivalent: the test seam itself
                List<ArrayDeque<Long>> free = new ArrayList<>();
                for (ArrayDeque<Long> one : FREE) {
                    free.add(new ArrayDeque<>(one));
                }
                saved = new Object[] {free, new java.util.HashMap<>(CHUNKS),
                    new java.util.HashMap<>(LARGE), decided, unavailable, warnedFull};
            }
            for (ArrayDeque<Long> free : FREE) {
                free.clear();
            }
            CHUNKS.clear();
            LARGE.clear(); // mutation-equivalent: the test seam itself
            mapForTests = mapper;
            warnedFull = false;
            if (mapper != null) { // mutation-equivalent: the test seam itself
                decided = true;
                unavailable = null;
            } else if (saved != null) { // mutation-equivalent: the test seam itself
                List<ArrayDeque<Long>> free = (List<ArrayDeque<Long>>) saved[0];
                for (int i = 0; i < FREE.size(); i++) { // mutation-equivalent: the test seam itself
                    FREE.get(i).addAll(free.get(i));
                }
                CHUNKS.putAll((java.util.Map<Long, int[]>) saved[1]); // mutation-equivalent: the test seam itself
                LARGE.putAll((java.util.Map<Long, Long>) saved[2]); // mutation-equivalent: the test seam itself
                decided = (Boolean) saved[3];
                unavailable = (String) saved[4];
                warnedFull = (Boolean) saved[5];
                saved = null;
            }
        }
    }

    /** Maps {@code length} bytes of secret pages: the address, or minus errno. */
    private static long map(long length) {
        java.util.function.LongUnaryOperator test = mapForTests;
        if (test != null) {
            return test.applyAsLong(length);
        }
        try (Arena call = Arena.ofConfined()) {
            MemorySegment state = call.allocate(ERRNO_SIZE);
            long fd = (long) SYSCALL.invokeExact(state, SYS_MEMFD_SECRET, 0);
            if (fd < 0) {
                return -errno(state);
            }
            try {
                if ((int) FTRUNCATE.invokeExact(state, (int) fd, length) != 0) {
                    return -errno(state);
                }
                MemorySegment mapped = (MemorySegment) MMAP.invokeExact(state, MemorySegment.NULL,
                        length, PROT_READ_WRITE, MAP_SHARED, (int) fd, 0L);
                if (mapped.address() == -1L) {
                    return -errno(state);
                }
                // Secret pages are charged to the memlock limit when first
                // touched, not when mapped: past the limit that first write
                // was a SIGBUS - a JVM InternalError. Faulted in here, the
                // limit is an errno, and the secret goes to locked pages instead.
                if ((int) MADVISE.invokeExact(state, mapped, length, MADV_POPULATE_WRITE) != 0) {
                    long errno = errno(state);
                    unmap(mapped.address(), length);
                    return -(errno == 14 ? 12 : errno);   // EFAULT: a page could not be had - no room
                }
                return mapped.address();
            } finally {
                int ignored = (int) CLOSE.invokeExact((int) fd);
            }
        } catch (Throwable t) {
            LOG.log(Level.DEBUG, "memfd_secret failed", t);
            return -UNCALLABLE;
        }
    }

    private static long errno(MemorySegment state) {
        return (int) ERRNO.get(state, 0L);
    }

    private static void unmap(long base, long length) {
        if (mapForTests != null) { // mutation-equivalent: the test seam itself
            return;                                   // ordinary memory, the test's to keep
        }
        try {
            int ignored = (int) MUNMAP.invokeExact(MemorySegment.ofAddress(base), length);
        } catch (Throwable t) {
            LOG.log(Level.DEBUG, "munmap of secret pages failed", t);
        }
    }
}
