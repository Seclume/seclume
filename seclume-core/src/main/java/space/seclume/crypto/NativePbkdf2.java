package space.seclume.crypto;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

import space.seclume.internal.Platform;

/**
 * PBKDF2-HMAC in the operating system's crypto library: OpenSSL's
 * {@code PKCS5_PBKDF2_HMAC} on Linux, CNG's {@code BCryptDeriveKeyPBKDF2} on
 * Windows - the libraries the TLS stack already uses for its key exchange
 * and AES-GCM.
 *
 * <p><b>Why.</b> A login pays for PBKDF2 once per connection: SCRAM-SHA-256
 * with 4096 rounds for PostgreSQL, PBKDF2-SHA512 for Oracle's 12c verifier,
 * and for Oracle once per return to a pool too, where a new session is made
 * on the same connection. The libraries run SHA-256 on the CPU's SHA
 * instructions and SHA-512 vectorised; the Java digests here do neither, and
 * were four times slower for SHA-256 (Pbkdf2Benchmark).
 *
 * <p>The password and the salt go from native memory into the library, and
 * the result comes back into native memory - never on the heap. The
 * libraries wipe their HMAC state when they free it. Where neither library
 * is there, or it refuses (OpenSSL's FIPS provider turns down short salts),
 * {@link Pbkdf2} falls back to its own code.
 */
final class NativePbkdf2 {

    private NativePbkdf2() {
    }

    /**
     * Derives into {@code out}, or returns false when no library does it here
     * - and then nothing was written.
     */
    static boolean derive(HashAlgorithm algorithm, MemorySegment password, MemorySegment salt,
                          int iterations, MemorySegment out) {
        if ("java".equals(System.getProperty("seclume.crypto.pbkdf2"))
                || ValueLayout.ADDRESS.byteSize() != 8
                || password.byteSize() > Integer.MAX_VALUE || salt.byteSize() > Integer.MAX_VALUE
                || out.byteSize() > Integer.MAX_VALUE) {
            return false;
        }
        try {
            if (Platform.isLinux()) {
                return OpenSsl.derive(algorithm, password, salt, iterations, out);
            }
            if (Platform.isWindows()) {
                return Cng.derive(algorithm, password, salt, iterations, out);
            }
        } catch (LinkageError | RuntimeException unavailable) {
            // No usable library: the Java code does it.
        }
        return false;
    }

    /** OpenSSL 3, loaded on first use. */
    private static final class OpenSsl {

        private static final SymbolLookup LIB =
                SymbolLookup.libraryLookup("libcrypto.so.3", Arena.global());
        private static final MethodHandle PBKDF2 = bind("PKCS5_PBKDF2_HMAC", JAVA_INT,
                ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS);
        private static final MethodHandle SHA1 = bind("EVP_sha1", ADDRESS);
        private static final MethodHandle SHA256 = bind("EVP_sha256", ADDRESS);
        private static final MethodHandle SHA384 = bind("EVP_sha384", ADDRESS);
        private static final MethodHandle SHA512 = bind("EVP_sha512", ADDRESS);

        static boolean derive(HashAlgorithm algorithm, MemorySegment password,
                              MemorySegment salt, int iterations, MemorySegment out) {
            MethodHandle which = switch (algorithm) {
                case SHA_1 -> SHA1;
                case SHA_256 -> SHA256;
                case SHA_384 -> SHA384;
                case SHA_512 -> SHA512;
                default -> null;
            };
            if (which == null) {
                return false;
            }
            try {
                MemorySegment digest = (MemorySegment) which.invokeExact();
                if (digest.equals(MemorySegment.NULL)) {
                    return false;
                }
                int done = (int) PBKDF2.invokeExact(password, (int) password.byteSize(),
                        salt, (int) salt.byteSize(), iterations, digest,
                        (int) out.byteSize(), out);
                if (done != 1) {
                    out.fill((byte) 0);
                    return false;
                }
                return true;
            } catch (RuntimeException | Error e) {
                out.fill((byte) 0);
                throw e;
            } catch (Throwable e) {
                out.fill((byte) 0);
                throw new IllegalStateException("OpenSSL PBKDF2 downcall failed", e);
            }
        }

        private static MethodHandle bind(String name, ValueLayout result,
                                         ValueLayout... arguments) {
            return Linker.nativeLinker().downcallHandle(LIB.find(name).orElseThrow(),
                    FunctionDescriptor.of(result, arguments));
        }
    }

    /** CNG, loaded on first use; one HMAC provider per hash, opened once. */
    private static final class Cng {

        private static final SymbolLookup LIB =
                SymbolLookup.libraryLookup("bcrypt.dll", Arena.global());
        private static final MethodHandle OPEN = bind("BCryptOpenAlgorithmProvider", JAVA_INT,
                ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
        private static final MethodHandle PBKDF2 = bind("BCryptDeriveKeyPBKDF2", JAVA_INT,
                ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, JAVA_LONG, ADDRESS, JAVA_INT,
                JAVA_INT);
        /** BCRYPT_ALG_HANDLE_HMAC_FLAG: the provider as the PRF, keyed by the password. */
        private static final int HMAC_FLAG = 0x8;

        private static final MemorySegment SHA1 = open("SHA1");
        private static final MemorySegment SHA256 = open("SHA256");

        static boolean derive(HashAlgorithm algorithm, MemorySegment password,
                              MemorySegment salt, int iterations, MemorySegment out) {
            // Not SHA-384 and SHA-512: CNG's were slower than the Java code
            // here (3.6 against 3.4 ms for 4096 rounds, Pbkdf2Benchmark on
            // Windows 11) - it has SHA instructions to use only for SHA-256.
            MemorySegment provider = switch (algorithm) {
                case SHA_1 -> SHA1;
                case SHA_256 -> SHA256;
                default -> MemorySegment.NULL;
            };
            if (provider.equals(MemorySegment.NULL)) {
                return false;
            }
            try {
                int status = (int) PBKDF2.invokeExact(provider, password,
                        (int) password.byteSize(), salt, (int) salt.byteSize(),
                        (long) iterations, out, (int) out.byteSize(), 0);
                if (status != 0) {
                    out.fill((byte) 0);
                    return false;
                }
                return true;
            } catch (RuntimeException | Error e) {
                out.fill((byte) 0);
                throw e;
            } catch (Throwable e) {
                out.fill((byte) 0);
                throw new IllegalStateException("CNG PBKDF2 downcall failed", e);
            }
        }

        private static MemorySegment open(String name) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment handle = arena.allocate(ADDRESS);
                MemorySegment wide = arena.allocate((name.length() + 1L) * 2, 2);
                for (int i = 0; i < name.length(); i++) {
                    wide.set(ValueLayout.JAVA_CHAR, 2L * i, name.charAt(i));
                }
                int status = (int) OPEN.invokeExact(handle, wide, MemorySegment.NULL, HMAC_FLAG);
                return status == 0 ? handle.get(ADDRESS, 0) : MemorySegment.NULL;
            } catch (Throwable e) {
                return MemorySegment.NULL;
            }
        }

        private static MethodHandle bind(String name, ValueLayout result,
                                         ValueLayout... arguments) {
            return Linker.nativeLinker().downcallHandle(LIB.find(name).orElseThrow(),
                    FunctionDescriptor.of(result, arguments));
        }
    }
}
