package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.internal.Platform;

/**
 * Where seclume looks for OpenSSL 3 on each system, what it refuses to load,
 * and - in a JVM of its own, since the search happens once per process - what
 * {@code -Dseclume.crypto.libcrypto} does to it.
 */
class LibCryptoTest {

    private static final String LINUX = "Linux";
    private static final String MAC = "Mac OS X";

    @TempDir
    Path temporary;

    @Test
    void linuxAsksTheLoaderForTheVersionedName() {
        assertEquals(List.of("libcrypto.so.3"), LibCrypto.candidates(LINUX, 8, null));
    }

    @Test
    void macOsTriesHomebrewOnBothArchitecturesThenMacPorts() {
        assertEquals(List.of("/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
                        "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
                        "/opt/local/lib/libcrypto.3.dylib"),
                LibCrypto.candidates(MAC, 8, null));
    }

    @Test
    void macOsNeverLoadsTheSystemsLibreSslStub() {
        for (String candidate : LibCrypto.candidates(MAC, 8, null)) {
            assertTrue(Path.of(candidate).isAbsolute(), candidate);
            assertFalse(Path.of(candidate).normalize().startsWith("/usr/lib"), candidate);
            assertTrue(candidate.endsWith("/libcrypto.3.dylib"), candidate);
        }
        for (String stub : List.of("/usr/lib/libcrypto.dylib", "/usr/lib/libcrypto.46.dylib",
                "/usr/local/../lib/libcrypto.dylib", "/usr/lib/./libcrypto.3.dylib")) {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> LibCrypto.candidates(MAC, 8, stub));
            assertTrue(refused.getMessage().contains("LibreSSL stub"), refused.getMessage());
            assertTrue(refused.getMessage().contains(LibCrypto.PROPERTY), refused.getMessage());
        }
    }

    @Test
    void thePropertyNamesTheOneFileToLoadOnEitherSystem() {
        String file = "/opt/openssl-3.5/lib64/libcrypto.so.3";
        assertEquals(List.of(file), LibCrypto.candidates(LINUX, 8, file));
        assertEquals(List.of(file), LibCrypto.candidates(LINUX, 8, "  " + file + "\n"));
        assertEquals(List.of("/opt/ssl/libcrypto.3.dylib"),
                LibCrypto.candidates(MAC, 8, "/opt/ssl/libcrypto.3.dylib"));
        // On Linux /usr/lib is where the system's OpenSSL 3 is - nothing to refuse there.
        assertEquals(List.of("/usr/lib/x86_64-linux-gnu/libcrypto.so.3"),
                LibCrypto.candidates(LINUX, 8, "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"));
    }

    @Test
    void aBlankPropertyIsNoProperty() {
        assertEquals(List.of("libcrypto.so.3"), LibCrypto.candidates(LINUX, 8, ""));
        assertEquals(List.of("libcrypto.so.3"), LibCrypto.candidates(LINUX, 8, " \t"));
        assertEquals(LibCrypto.candidates(MAC, 8, null), LibCrypto.candidates(MAC, 8, " "));
    }

    @Test
    void aRelativeNameIsNotLeftToTheLoadersSearch() {
        for (String relative : List.of("libcrypto.so.3", "lib/libcrypto.so.3", "./libcrypto.so.3")) {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> LibCrypto.candidates(LINUX, 8, relative));
            assertTrue(refused.getMessage().contains("absolute path"), refused.getMessage());
            assertTrue(refused.getMessage().contains(relative), refused.getMessage());
        }
    }

    @Test
    void elsewhereThereIsNothingToLookFor() {
        assertEquals(List.of(), LibCrypto.candidates("Windows 11", 8, null));
        assertEquals(List.of(), LibCrypto.candidates("FreeBSD", 8, null));
        assertEquals(List.of(), LibCrypto.candidates(null, 8, null));
        assertEquals(List.of(), LibCrypto.candidates(LINUX, 4, null));
        assertEquals(List.of(), LibCrypto.candidates(MAC, 4, null));
        // The property does not make a 32-bit or a Windows process look for OpenSSL.
        assertEquals(List.of(), LibCrypto.candidates("Windows 11", 8, "C:/ssl/libcrypto-3.dll"));
        assertEquals(List.of(), LibCrypto.candidates(LINUX, 4, "/opt/ssl/libcrypto.so.3"));
    }

    @Test
    void theSystemsAreToldApartRegardlessOfCase() {
        assertEquals(List.of("libcrypto.so.3"), LibCrypto.candidates("LINUX", 8, null));
        assertEquals(LibCrypto.candidates(MAC, 8, null), LibCrypto.candidates("mac os x", 8, null));
    }

    @Test
    void whatThisProcessFoundIsConsistent() {
        if (LibCrypto.available()) {
            assertNull(LibCrypto.missing());
            assertTrue(LibCrypto.file() != null && !LibCrypto.file().isBlank());
            assertTrue(LibCrypto.lookup().find("OpenSSL_version_num").isPresent());
            assertTrue(LibCrypto.lookup().find("EVP_PKEY_CTX_new_from_name").isPresent());
        } else {
            assertNull(LibCrypto.file());
            UnsupportedOperationException none = assertThrows(UnsupportedOperationException.class,
                    LibCrypto::lookup);
            assertEquals(LibCrypto.missing(), none.getMessage());
        }
    }

    @Test
    void sixtyFourBitLinuxAndMacOsHaveIt() {
        // The CI runners have OpenSSL 3 (Ubuntu's, Homebrew's on macOS). Where it is
        // expected and missing, the native tests would all be skipped or fail
        // further away; this says why, here.
        Assumptions.assumeTrue(System.getenv("CI") != null, "only where OpenSSL 3 is known to be");
        if (Platform.isLinux() || Platform.isMac()) {
            assertTrue(LibCrypto.available(), LibCrypto.missing());
        } else {
            assertFalse(LibCrypto.available());
        }
    }

    @Test
    @Timeout(120)
    void aFileThatIsNotThereIsReportedAndNothingElseIsTried() throws Exception {
        Assumptions.assumeTrue(Platform.isLinux() || Platform.isMac(), "OpenSSL is not used here");
        String absent = temporary.resolve("no-such-libcrypto.so.3").toString();
        String report = child(absent);
        assertTrue(report.contains("MISSING"), report);
        assertTrue(report.contains(absent + " (not there)"), report);
        // What has no Java fallback says what it needs, and why it is not there.
        assertTrue(report.contains("P256 refused: native P-256 requires " + LibCrypto.REQUIRES
                + ": no OpenSSL 3 libcrypto here; tried " + absent + " (not there)"), report);
        assertTrue(report.contains("AES-GCM java"), report);
    }

    @Test
    @Timeout(120)
    void aFileThatIsNotALibcryptoIsNotUsed() throws Exception {
        Assumptions.assumeTrue(Platform.isLinux() || Platform.isMac(), "OpenSSL is not used here");
        Path notALibrary = temporary.resolve("libcrypto.so.3");
        Files.writeString(notALibrary, "not a shared object\n");
        String report = child(notALibrary.toString());
        assertTrue(report.contains("MISSING"), report);
        assertTrue(report.contains(notALibrary + " ("), report);
        assertTrue(report.contains("AES-GCM java"), report);
    }

    @Test
    @Timeout(120)
    void aRelativePropertyIsRefusedAndSaid() throws Exception {
        Assumptions.assumeTrue(Platform.isLinux() || Platform.isMac(), "OpenSSL is not used here");
        String report = child("libcrypto.so.3");
        assertTrue(report.contains("MISSING " + LibCrypto.PROPERTY + " is a file, as an absolute "
                + "path, not libcrypto.so.3"), report);
    }

    @Test
    @Timeout(120)
    void theRealFileNamedByThePropertyIsUsed() throws Exception {
        Assumptions.assumeTrue(LibCrypto.available(), "no OpenSSL 3 here");
        String real = realFile();
        Assumptions.assumeTrue(real != null, "where the loader found libcrypto is not known");
        String report = child(real);
        assertTrue(report.contains("AVAILABLE " + real), report);
        assertTrue(report.contains("P256 generated"), report);
        assertTrue(report.contains("AES-GCM openssl"), report);
    }

    /** The absolute path of the libcrypto this process loaded. */
    private static String realFile() throws Exception {
        if (LibCrypto.file().startsWith("/")) {
            return LibCrypto.file();
        }
        if (!Platform.isLinux()) {
            return null;
        }
        for (String line : Files.readAllLines(Path.of("/proc/self/maps"))) {
            int slash = line.indexOf('/');
            if (slash >= 0 && line.substring(slash).contains("/libcrypto.so.3")) {
                return line.substring(slash).strip();
            }
        }
        return null;
    }

    private String child(String property) throws Exception {
        Path output = Files.createTempFile(temporary, "child", ".log");
        String classpath = System.getProperty("surefire.test.class.path",
                System.getProperty("java.class.path"));
        Process child = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED", "-D" + LibCrypto.PROPERTY + "=" + property,
                "-Dseclume.mlock=false", "-cp", classpath, LibCryptoTest.class.getName())
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        try {
            assertTrue(child.waitFor(90, TimeUnit.SECONDS), "child timed out");
            String report = Files.readString(output);
            assertEquals(0, child.exitValue(), report);
            return report;
        } finally {
            if (child.isAlive()) {
                child.destroyForcibly();
                child.waitFor(10, TimeUnit.SECONDS);
            }
        }
    }

    /** The child: what it found, and what the backends make of it. */
    public static void main(String[] args) {
        System.out.println(LibCrypto.available() ? "AVAILABLE " + LibCrypto.file()
                : "MISSING " + LibCrypto.missing());
        try {
            NativeP256.generate().close();
            System.out.println("P256 generated");
        } catch (UnsupportedOperationException refused) {
            System.out.println("P256 refused: " + refused.getMessage());
        }
        try (Arena arena = Arena.ofConfined();
             AesGcmCipher cipher = AesGcmCipher.of(arena.allocate(16), 0, 16)) {
            System.out.println("AES-GCM " + cipher.implementation());
        }
    }
}
