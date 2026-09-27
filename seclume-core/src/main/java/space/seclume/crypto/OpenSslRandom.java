package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

import space.seclume.internal.Platform;

/**
 * Fresh entropy for OpenSSL's random generator after a restore.
 *
 * <p>seclume's own randomness ({@code Entropy}) asks the operating system on
 * every call and keeps no state, so a restored process gets new bytes from
 * the first call on. OpenSSL is different: its DRBG - which makes the
 * ephemeral P-256 and ML-KEM keys of every TLS handshake - keeps its state in
 * process memory, and a checkpoint image carries that state. Every instance
 * started from one image begins with the same DRBG and, until OpenSSL decides
 * to reseed on its own, would draw the same "random" key shares.
 *
 * <p>{@link #reseed()} reseeds the primary DRBG with prediction resistance,
 * which fetches entropy from the operating system; the per-thread DRBGs below
 * it notice the parent's new reseed count and reseed themselves before their
 * next output. The calling thread's two are reseeded directly as well.
 */
public final class OpenSslRandom {

    private static final MethodHandle PRIMARY;
    private static final MethodHandle PUBLIC;
    private static final MethodHandle PRIVATE;
    private static final MethodHandle RESEED;

    static {
        MethodHandle primary = null;
        MethodHandle publicDrbg = null;
        MethodHandle privateDrbg = null;
        MethodHandle reseed = null;
        if (Platform.isLinux() && ValueLayout.ADDRESS.byteSize() == 8) {
            try {
                SymbolLookup lib = SymbolLookup.libraryLookup("libcrypto.so.3", Arena.global());
                Linker linker = Linker.nativeLinker();
                // EVP_RAND_CTX *RAND_get0_primary(OSSL_LIB_CTX *ctx); likewise _public, _private
                FunctionDescriptor get = FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS);
                primary = linker.downcallHandle(lib.find("RAND_get0_primary").orElseThrow(), get);
                publicDrbg = linker.downcallHandle(lib.find("RAND_get0_public").orElseThrow(), get);
                privateDrbg = linker.downcallHandle(lib.find("RAND_get0_private").orElseThrow(), get);
                // int EVP_RAND_reseed(EVP_RAND_CTX *ctx, int prediction_resistance,
                //     const unsigned char *ent, size_t ent_len,
                //     const unsigned char *addin, size_t addin_len);
                reseed = linker.downcallHandle(lib.find("EVP_RAND_reseed").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                                ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
            } catch (RuntimeException noOpenSsl) {
                primary = null;
            }
        }
        PRIMARY = primary;
        PUBLIC = publicDrbg;
        PRIVATE = privateDrbg;
        RESEED = reseed;
    }

    private OpenSslRandom() {
    }

    /** Whether there is an OpenSSL here whose generator can be reseeded. */
    public static boolean available() {
        return PRIMARY != null;
    }

    /**
     * Reseeds OpenSSL's generators from the operating system.
     *
     * @return true if OpenSSL is present and the primary generator took the
     *         new seed; false if there is no OpenSSL to reseed
     * @throws IllegalStateException if OpenSSL is present and refused
     */
    public static boolean reseed() {
        if (!available()) {
            return false;
        }
        try {
            reseed((MemorySegment) PRIMARY.invokeExact(MemorySegment.NULL), "primary");
            reseed((MemorySegment) PUBLIC.invokeExact(MemorySegment.NULL), "public");
            reseed((MemorySegment) PRIVATE.invokeExact(MemorySegment.NULL), "private");
            return true;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("reseeding OpenSSL's random generator failed", t);
        }
    }

    private static void reseed(MemorySegment drbg, String which) throws Throwable {
        if (drbg.equals(MemorySegment.NULL)) {
            throw new IllegalStateException("OpenSSL has no " + which + " random generator");
        }
        int ok = (int) RESEED.invokeExact(drbg, 1, MemorySegment.NULL, 0L,
                MemorySegment.NULL, 0L);
        if (ok != 1) {
            throw new IllegalStateException("OpenSSL refused to reseed its " + which
                    + " random generator");
        }
    }
}
