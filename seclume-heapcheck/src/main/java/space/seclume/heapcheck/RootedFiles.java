package space.seclume.heapcheck;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Files of another process's file system, opened through
 * {@code /proc/<pid>/root} by the kernel in one step:
 * {@code openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)}.
 *
 * <p>The process under examination may be hostile, and this check commonly
 * runs as root ({@code kubectl debug --target}). A path walked here and opened
 * afterwards leaves a moment in which the process can swap a directory on
 * the way for a link to {@code /etc}: through {@code /proc/<pid>/root} the
 * kernel follows an absolute link from this file system's root, and the check
 * would read - or delete - a file of the host. Resolved by the kernel inside
 * the root, every link stays in the process's file system, whenever it is
 * placed. What is opened is then used through its descriptor,
 * {@code /proc/self/fd/<n>}, which the kernel does not resolve again.
 *
 * <p>Linux 5.6 or later. Without {@code openat2} nothing is opened, rather
 * than falling back to the walk.
 */
public final class RootedFiles implements AutoCloseable {

    private static final long SYS_OPENAT2 = 437;        // the same on x86-64 and AArch64
    private static final int AT_FDCWD = -100;
    private static final long O_PATH = 0x200000;         // the same on x86-64 and AArch64
    private static final long O_CLOEXEC = 0x80000;
    private static final long RESOLVE_NO_MAGICLINKS = 0x02;
    private static final long RESOLVE_IN_ROOT = 0x10;
    private static final int ENOENT = 2;
    private static final int ENOSYS = 38;

    private static final StructLayout OPEN_HOW = MemoryLayout.structLayout(
            ValueLayout.JAVA_LONG.withName("flags"),
            ValueLayout.JAVA_LONG.withName("mode"),
            ValueLayout.JAVA_LONG.withName("resolve"));
    private static final StructLayout CALL_STATE = Linker.Option.captureStateLayout();
    private static final VarHandle ERRNO = CALL_STATE.varHandle(
            MemoryLayout.PathElement.groupElement("errno"));

    private static final MethodHandle SYSCALL;
    private static final MethodHandle UNLINKAT;
    private static final MethodHandle CLOSE;

    static {
        Linker linker = Linker.nativeLinker();
        Linker.Option errno = Linker.Option.captureCallState("errno");
        // long syscall(long number, ...): openat2(int dirfd, const char *path,
        // struct open_how *how, size_t size)
        SYSCALL = linker.downcallHandle(linker.defaultLookup().find("syscall").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG),
                errno, Linker.Option.firstVariadicArg(1));
        UNLINKAT = linker.downcallHandle(linker.defaultLookup().find("unlinkat").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT), errno);
        CLOSE = linker.downcallHandle(linker.defaultLookup().find("close").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
    }

    private final String pid;
    private final int root;
    private final List<Integer> open = new ArrayList<>();

    private RootedFiles(String pid, int root) {
        this.pid = pid;
        this.root = root;
    }

    /**
     * The file system of process {@code pid}.
     *
     * @throws IOException if it cannot be opened, or the kernel has no openat2
     */
    public static RootedFiles of(String pid) throws IOException {
        if (!pid.matches("[0-9]{1,10}")) {
            throw new IOException("not a process id: " + pid);
        }
        return new RootedFiles(pid, openat2(AT_FDCWD, "/proc/" + pid + "/root", 0, "the root of "
                + "process " + pid));
    }

    /**
     * {@code inside} - a path as the process sees it - opened, and the file to
     * read it by from here: {@code /proc/self/fd/<n>}, the file itself, valid
     * until {@link #close()}.
     *
     * @return null if there is no such file in the process's file system
     * @throws IOException if it is there but not a regular file - a FIFO
     *         would block the check, a device would be read without end
     */
    public Path open(Path inside) throws IOException {
        int fd = openOrMissing(relative(inside), O_PATH | O_CLOEXEC, inside);
        if (fd < 0) {
            return null;
        }
        Path pinned = Path.of("/proc/self/fd/" + fd);
        if (!Files.isRegularFile(pinned)) {
            close(fd);
            throw new IOException(inside + " in the file system of process " + pid
                    + " is not a regular file - nothing was read");
        }
        open.add(fd);
        return pinned;
    }

    /** Whether {@code inside} names anything in the process's file system - a link too. */
    public boolean exists(Path inside) throws IOException {
        // The parent resolved inside the root, the last name looked at there.
        Path relative = relative(inside);
        Path parent = relative.getParent();
        int dir = parent == null ? -1 : openOrMissing(parent, O_PATH | O_CLOEXEC, inside);
        if (parent != null && dir < 0) {
            return false;
        }
        try {
            Path at = Path.of("/proc/self/fd/" + (parent == null ? root : dir));
            return Files.exists(at.resolve(relative.getFileName().toString()),
                    java.nio.file.LinkOption.NOFOLLOW_LINKS);
        } finally {
            if (parent != null) {
                close(dir);
            }
        }
    }

    /**
     * Deletes {@code inside} from the process's file system: its directory
     * resolved inside the root, the name removed there - a link is removed,
     * never what it points to.
     *
     * @return false if it was not there
     */
    public boolean delete(Path inside) throws IOException {
        Path relative = relative(inside);
        Path parent = relative.getParent();
        int dir = parent == null ? root : openOrMissing(parent, O_PATH | O_CLOEXEC, inside);
        if (dir < 0) {
            return false;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(CALL_STATE);
            int result = (int) UNLINKAT.invokeExact(state, dir,
                    arena.allocateFrom(relative.getFileName().toString()), 0);
            if (result == 0) {
                return true;
            }
            int error = (int) ERRNO.get(state, 0L);
            if (error == ENOENT) {
                return false;
            }
            throw new IOException("cannot delete " + inside + " in the file system of process "
                    + pid + " (errno " + error + ")");
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("cannot delete " + inside, t);
        } finally {
            if (dir != root) {
                close(dir);
            }
        }
    }

    @Override
    public void close() {
        for (int fd : open) {
            close(fd);
        }
        open.clear();
        close(root);
    }

    /** The path from the root, without its leading slash; "." for the root itself. */
    private static Path relative(Path inside) {
        Path absolute = inside.isAbsolute() ? inside : Path.of("/").resolve(inside);
        Path relative = absolute.getRoot().relativize(absolute.normalize());
        return relative.toString().isEmpty() ? Path.of(".") : relative;
    }

    private int openOrMissing(Path relative, long flags, Path inside) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment how = arena.allocate(OPEN_HOW);
            how.set(ValueLayout.JAVA_LONG, 0, flags);
            how.set(ValueLayout.JAVA_LONG, 16, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS);
            MemorySegment state = arena.allocate(CALL_STATE);
            long fd = (long) SYSCALL.invokeExact(state, SYS_OPENAT2, root,
                    arena.allocateFrom(relative.toString().replace('\\', '/')), how,
                    OPEN_HOW.byteSize());
            if (fd >= 0) {
                return (int) fd;
            }
            int error = (int) ERRNO.get(state, 0L);
            if (error == ENOENT) {
                return -1;
            }
            throw new IOException("cannot open " + inside + " in the file system of process "
                    + pid + " (errno " + error + ")");
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("cannot open " + inside, t);
        }
    }

    private static int openat2(int dir, String path, long resolve, String what) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment how = arena.allocate(OPEN_HOW);
            how.set(ValueLayout.JAVA_LONG, 0, O_PATH | O_CLOEXEC);
            how.set(ValueLayout.JAVA_LONG, 16, resolve);
            MemorySegment state = arena.allocate(CALL_STATE);
            long fd = (long) SYSCALL.invokeExact(state, SYS_OPENAT2, dir,
                    arena.allocateFrom(path), how, OPEN_HOW.byteSize());
            if (fd >= 0) {
                return (int) fd;
            }
            int error = (int) ERRNO.get(state, 0L);
            if (error == ENOSYS) {
                throw new IOException("this kernel has no openat2 (Linux 5.6 or later): the "
                        + "process's file system cannot be read safely through /proc, and is not "
                        + "read at all");
            }
            throw new IOException("cannot open " + what + " (errno " + error + ")");
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("cannot open " + what, t);
        }
    }

    private static void close(int fd) {
        try {
            int ignored = (int) CLOSE.invokeExact(fd);
        } catch (Throwable ignored) {
            // nothing left to do with it
        }
    }
}
