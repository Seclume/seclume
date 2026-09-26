package space.seclume.crypto;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * AES-GCM through OpenSSL's EVP interface (libcrypto 3): AES-NI where the CPU
 * has it, OpenSSL's constant-time code where it does not. One context per
 * direction, keyed once; each message only sets the nonce. OpenSSL wipes the
 * key schedule when a context is freed.
 */
final class OpenSslAesGcm implements AesGcmCipher {

    private static final SymbolLookup LIB = SymbolLookup.libraryLookup("libcrypto.so.3", Arena.global());
    private static final MethodHandle CTX_NEW = bind("EVP_CIPHER_CTX_new", ADDRESS);
    private static final MethodHandle CTX_FREE = bind("EVP_CIPHER_CTX_free", null, ADDRESS);
    private static final MethodHandle AES_128_GCM = bind("EVP_aes_128_gcm", ADDRESS);
    private static final MethodHandle AES_256_GCM = bind("EVP_aes_256_gcm", ADDRESS);
    private static final MethodHandle INIT = bind("EVP_CipherInit_ex", JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
    private static final MethodHandle UPDATE = bind("EVP_CipherUpdate", JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
    private static final MethodHandle FINAL = bind("EVP_CipherFinal_ex", JAVA_INT, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle CTRL = bind("EVP_CIPHER_CTX_ctrl", JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS);

    private static final int GET_TAG = 0x10;
    private static final int SET_TAG = 0x11;

    /** Where OpenSSL reports how much it wrote - once per context, not per record. */
    private final Arena arena = Arena.ofShared();
    private final MemorySegment encryptWritten = arena.allocate(JAVA_INT);
    private final MemorySegment decryptWritten = arena.allocate(JAVA_INT);
    private MemorySegment encrypting = MemorySegment.NULL;
    private MemorySegment decrypting = MemorySegment.NULL;

    OpenSslAesGcm(MemorySegment key, long offset, int length) {
        try {
            MemorySegment cipher = length == 16 ? newCipher(AES_128_GCM) : newCipher(AES_256_GCM);
            encrypting = context(cipher, key.asSlice(offset, length), 1);
            decrypting = context(cipher, key.asSlice(offset, length), 0);
        } catch (RuntimeException | Error failure) {
            close();
            throw failure;
        }
    }

    private static MemorySegment context(MemorySegment cipher, MemorySegment key, int encrypt) {
        MemorySegment context = newContext();
        if (context.equals(MemorySegment.NULL)) {
            throw new IllegalStateException("EVP_CIPHER_CTX_new returned no context");
        }
        try {
            check(init(context, cipher, key, MemorySegment.NULL, encrypt), "EVP_CipherInit_ex");
            return context;
        } catch (RuntimeException | Error failure) {
            free(context);
            throw failure;
        }
    }

    @Override
    public void encrypt(MemorySegment nonce, long nonceOffset, MemorySegment aad, long aadOffset,
                        long aadLength, MemorySegment in, long inOffset, long length,
                        MemorySegment out, long outOffset) {
        run(encrypting, nonce, nonceOffset, aad, aadOffset, aadLength, in, inOffset, length,
                out, outOffset, encryptWritten);
        check(finish(encrypting, out.asSlice(outOffset + length), encryptWritten),
                "EVP_CipherFinal_ex");
        check(ctrl(encrypting, GET_TAG, out.asSlice(outOffset + length, AesGcm.TAG)),
                "reading the GCM tag");
    }

    @Override
    public boolean decrypt(MemorySegment nonce, long nonceOffset, MemorySegment aad,
                           long aadOffset, long aadLength, MemorySegment in, long inOffset,
                           long length, MemorySegment out, long outOffset) {
        run(decrypting, nonce, nonceOffset, aad, aadOffset, aadLength, in, inOffset, length,
                out, outOffset, decryptWritten);
        check(ctrl(decrypting, SET_TAG, in.asSlice(inOffset + length, AesGcm.TAG)),
                "setting the GCM tag");
        if (finish(decrypting, out.asSlice(outOffset + length), decryptWritten) <= 0) {
            if (length > 0) {
                out.asSlice(outOffset, length).fill((byte) 0);
            }
            return false;
        }
        return true;
    }

    private static void run(MemorySegment context, MemorySegment nonce, long nonceOffset,
                            MemorySegment aad, long aadOffset, long aadLength,
                            MemorySegment in, long inOffset, long length,
                            MemorySegment out, long outOffset, MemorySegment written) {
        check(init(context, MemorySegment.NULL, MemorySegment.NULL,
                nonce.asSlice(nonceOffset, AesGcm.NONCE), -1), "EVP_CipherInit_ex with the nonce");
        if (aadLength > 0) {
            check(update(context, MemorySegment.NULL, written, aad.asSlice(aadOffset, aadLength),
                    (int) aadLength), "EVP_CipherUpdate with the additional data");
        }
        if (length > 0) {
            check(update(context, out.asSlice(outOffset, length), written,
                    in.asSlice(inOffset, length), (int) length), "EVP_CipherUpdate");
        }
    }

    @Override
    public String implementation() {
        return "openssl";
    }

    @Override
    public void close() {
        if (!encrypting.equals(MemorySegment.NULL)) {
            MemorySegment old = encrypting;
            encrypting = MemorySegment.NULL;
            free(old);
        }
        if (!decrypting.equals(MemorySegment.NULL)) {
            MemorySegment old = decrypting;
            decrypting = MemorySegment.NULL;
            free(old);
        }
        if (arena.scope().isAlive()) {
            arena.close();
        }
    }

    private static void check(int result, String what) {
        if (result <= 0) {
            throw new IllegalStateException("OpenSSL AES-GCM failed in " + what);
        }
    }

    // ---- the downcalls, each with its exact type ---------------------------
    //
    // invokeExact rather than invokeWithArguments: the latter boxes every
    // argument into an Object[] and goes through a generic adapter, which cost
    // more than the AES-GCM of a short record itself (RecordBenchmark).

    private static MemorySegment newCipher(MethodHandle which) {
        try {
            return (MemorySegment) which.invokeExact();
        } catch (Throwable e) {
            throw failed(e);
        }
    }

    private static MemorySegment newContext() {
        try {
            return (MemorySegment) CTX_NEW.invokeExact();
        } catch (Throwable e) {
            throw failed(e);
        }
    }

    private static void free(MemorySegment context) {
        try {
            CTX_FREE.invokeExact(context);
        } catch (Throwable e) {
            throw failed(e);
        }
    }

    /** EVP_CipherInit_ex without an engine; {@code cipher} and {@code key} may be NULL. */
    private static int init(MemorySegment context, MemorySegment cipher, MemorySegment key,
                            MemorySegment iv, int encrypt) {
        try {
            return (int) INIT.invokeExact(context, cipher, MemorySegment.NULL, key, iv, encrypt);
        } catch (Throwable e) {
            throw failed(e);
        }
    }

    private static int update(MemorySegment context, MemorySegment out, MemorySegment written,
                              MemorySegment in, int length) {
        try {
            return (int) UPDATE.invokeExact(context, out, written, in, length);
        } catch (Throwable e) {
            throw failed(e);
        }
    }

    private static int finish(MemorySegment context, MemorySegment out, MemorySegment written) {
        try {
            return (int) FINAL.invokeExact(context, out, written);
        } catch (Throwable e) {
            throw failed(e);
        }
    }

    private static int ctrl(MemorySegment context, int type, MemorySegment tag) {
        try {
            return (int) CTRL.invokeExact(context, type, AesGcm.TAG, tag);
        } catch (Throwable e) {
            throw failed(e);
        }
    }

    private static RuntimeException failed(Throwable e) {
        if (e instanceof RuntimeException runtime) {
            return runtime;
        }
        if (e instanceof Error error) {
            throw error;
        }
        return new IllegalStateException("OpenSSL AES-GCM downcall failed", e);
    }

    private static MethodHandle bind(String name, ValueLayout result, ValueLayout... arguments) {
        return Linker.nativeLinker().downcallHandle(LIB.find(name).orElseThrow(),
                descriptor(result, arguments));
    }

    private static FunctionDescriptor descriptor(ValueLayout result, ValueLayout... arguments) {
        return result == null ? FunctionDescriptor.ofVoid(arguments)
                : FunctionDescriptor.of(result, arguments);
    }
}
