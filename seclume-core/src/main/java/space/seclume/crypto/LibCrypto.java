package space.seclume.crypto;

import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * OpenSSL 3's libcrypto, looked for once, for every OpenSSL backend in this
 * package.
 *
 * <p>On 64-bit Linux it is {@code libcrypto.so.3}, found where the dynamic
 * loader finds it. macOS has no OpenSSL 3 of its own: the files looked for are
 * those of Homebrew's {@code openssl@3} (Apple silicon, then Intel) and of
 * MacPorts. The unversioned {@code /usr/lib/libcrypto.dylib} is never loaded -
 * it is Apple's LibreSSL stub, which aborts the process that loads it.
 *
 * <p>{@value #PROPERTY} names another file - an absolute path, on either
 * system - for an OpenSSL 3 that is somewhere else. Whatever is loaded must say
 * that it is OpenSSL 3 or later ({@code OpenSSL_version_num}), or it is not
 * used.
 *
 * <p>Where none of this finds a libcrypto, {@link #available()} is false and
 * each backend says what it needs; Windows uses CNG and never comes here.
 */
final class LibCrypto {

    /** The system property naming the libcrypto to load instead. */
    static final String PROPERTY = "seclume.crypto.libcrypto";

    /** What the OpenSSL backends need, for the messages that say they are not there. */
    static final String REQUIRES = "Windows, or 64-bit Linux or macOS with OpenSSL 3 "
            + "(libcrypto.so.3; on macOS Homebrew's or MacPorts' openssl@3, or -D"
            + PROPERTY + "=<path>)";

    /** OpenSSL 3.0.0, in {@code OpenSSL_version_num}'s 0xMNN00PP0L form. */
    private static final long OPENSSL_3 = 0x3000_0000L;

    private static final List<String> MAC = List.of(
            "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
            "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
            "/opt/local/lib/libcrypto.3.dylib");

    private LibCrypto() {
    }

    /** Whether there is an OpenSSL 3 libcrypto here. */
    static boolean available() {
        return Found.LOOKUP != null;
    }

    /** The libcrypto's symbols; {@link UnsupportedOperationException} where there is none. */
    static SymbolLookup lookup() {
        if (Found.LOOKUP == null) {
            throw new UnsupportedOperationException(missing());
        }
        return Found.LOOKUP;
    }

    /** The file that was loaded, or null. */
    static String file() {
        return Found.FILE;
    }

    /** Why there is no libcrypto, or null when there is one. */
    static String missing() {
        return Found.LOOKUP == null ? Found.WHY : null;
    }

    /**
     * The files to try, in order, on this system ({@code os.name}), with this
     * pointer size and this value of {@value #PROPERTY} (or null).
     *
     * @throws IllegalArgumentException if the property is not an absolute path,
     *         or names Apple's LibreSSL stub
     */
    static List<String> candidates(String osName, long pointerSize, String property) {
        String os = osName == null ? "" : osName.toLowerCase(Locale.ROOT);
        boolean linux = os.contains("linux");
        boolean mac = os.contains("mac");
        if (pointerSize != 8 || !(linux || mac)) {
            return List.of();
        }
        if (property != null && !property.isBlank()) {
            Path path = Path.of(property.strip());
            if (!path.isAbsolute()) {
                throw new IllegalArgumentException(PROPERTY + " is a file, as an absolute path, "
                        + "not " + property.strip());
            }
            if (mac && path.normalize().startsWith("/usr/lib")) {
                throw new IllegalArgumentException(PROPERTY + " names " + path + ": the libcrypto "
                        + "in /usr/lib is Apple's LibreSSL stub, which ends the process that "
                        + "loads it");
            }
            return List.of(path.toString());
        }
        return linux ? List.of("libcrypto.so.3") : MAC;
    }

    /** The search, on first use. */
    private static final class Found {

        static final SymbolLookup LOOKUP;
        static final String FILE;
        static final String WHY;

        static {
            SymbolLookup lookup = null;
            String file = null;
            String why;
            List<String> tried = new ArrayList<>();
            try {
                List<String> candidates = candidates(System.getProperty("os.name"),
                        ValueLayout.ADDRESS.byteSize(), System.getProperty(PROPERTY));
                why = candidates.isEmpty() ? "OpenSSL needs 64-bit Linux or macOS, and this is "
                        + System.getProperty("os.name") + " with "
                        + ValueLayout.ADDRESS.byteSize() * 8 + "-bit pointers"
                        : "no OpenSSL 3 libcrypto here";
                for (String candidate : candidates) {
                    if (candidate.startsWith("/") && !Files.isRegularFile(Path.of(candidate))) {
                        tried.add(candidate + " (not there)");
                        continue;
                    }
                    try {
                        SymbolLookup found = SymbolLookup.libraryLookup(candidate, Arena.global());
                        long version = version(found);
                        if (version < OPENSSL_3) {
                            tried.add(candidate + String.format(" (version 0x%x, not 3)", version));
                            continue;
                        }
                        lookup = found;
                        file = candidate;
                        break;
                    } catch (RuntimeException notLoaded) {
                        tried.add(candidate + " (" + notLoaded.getMessage() + ")");
                    }
                }
            } catch (IllegalArgumentException wrongProperty) {
                why = wrongProperty.getMessage();
            }
            LOOKUP = lookup;
            FILE = file;
            WHY = lookup != null ? null
                    : tried.isEmpty() ? why : why + "; tried " + String.join(", ", tried);
        }

        private static long version(SymbolLookup lookup) {
            var function = lookup.find("OpenSSL_version_num").orElseThrow(
                    () -> new IllegalArgumentException("no OpenSSL_version_num, not OpenSSL"));
            try {
                return (long) Linker.nativeLinker()
                        .downcallHandle(function, FunctionDescriptor.of(JAVA_LONG))
                        .invokeExact();
            } catch (RuntimeException | Error e) {
                throw e;
            } catch (Throwable e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
