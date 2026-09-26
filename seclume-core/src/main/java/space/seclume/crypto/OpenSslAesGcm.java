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

    private MemorySegment encrypting = MemorySegment.NULL;
    private MemorySegment decrypting = MemorySegment.NULL;

    OpenSslAesGcm(MemorySegment key, long offset, int length) {
        MemorySegment cipher = (MemorySegment) call(length == 16 ? AES_128_GCM : AES_256_GCM);
        try {
            encrypting = context(cipher, key.asSlice(offset, length), 1);
            decrypting = context(cipher, key.asSlice(offset, length), 0);
        } catch (RuntimeException | Error failure) {
            close();
            throw failure;
        }
    }

    private static MemorySegment context(MemorySegment cipher, MemorySegment key, int encrypt) {
        MemorySegment context = (MemorySegment) call(CTX_NEW);
        if (context.equals(MemorySegment.NULL)) {
            throw new IllegalStateException("EVP_CIPHER_CTX_new returned no context");
        }
        try {
            check((int) call(INIT, context, cipher, MemorySegment.NULL, key, MemorySegment.NULL,
                    encrypt), "EVP_CipherInit_ex");
            return context;
        } catch (RuntimeException | Error failure) {
            call(CTX_FREE, context);
            throw failure;
        }
    }

    @Override
    public void encrypt(MemorySegment nonce, long nonceOffset, MemorySegment aad, long aadOffset,
                        long aadLength, MemorySegment in, long inOffset, long length,
                        MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment written = arena.allocate(JAVA_INT);
            run(encrypting, nonce, nonceOffset, aad, aadOffset, aadLength, in, inOffset, length,
                    out, outOffset, written);
            check((int) call(FINAL, encrypting, out.asSlice(outOffset + length), written),
                    "EVP_CipherFinal_ex");
            check((int) call(CTRL, encrypting, GET_TAG, AesGcm.TAG,
                    out.asSlice(outOffset + length, AesGcm.TAG)), "reading the GCM tag");
        }
    }

    @Override
    public boolean decrypt(MemorySegment nonce, long nonceOffset, MemorySegment aad,
                           long aadOffset, long aadLength, MemorySegment in, long inOffset,
                           long length, MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment written = arena.allocate(JAVA_INT);
            run(decrypting, nonce, nonceOffset, aad, aadOffset, aadLength, in, inOffset, length,
                    out, outOffset, written);
            check((int) call(CTRL, decrypting, SET_TAG, AesGcm.TAG,
                    in.asSlice(inOffset + length, AesGcm.TAG)), "setting the GCM tag");
            if ((int) call(FINAL, decrypting, out.asSlice(outOffset + length), written) <= 0) {
                if (length > 0) {
                    out.asSlice(outOffset, length).fill((byte) 0);
                }
                return false;
            }
            return true;
        }
    }

    /** Nonce, additional data, then the message itself. */
    private static void run(MemorySegment context, MemorySegment nonce, long nonceOffset,
                            MemorySegment aad, long aadOffset, long aadLength,
                            MemorySegment in, long inOffset, long length,
                            MemorySegment out, long outOffset, MemorySegment written) {
        check((int) call(INIT, context, MemorySegment.NULL, MemorySegment.NULL,
                MemorySegment.NULL, nonce.asSlice(nonceOffset, AesGcm.NONCE), -1),
                "EVP_CipherInit_ex with the nonce");
        if (aadLength > 0) {
            check((int) call(UPDATE, context, MemorySegment.NULL, written,
                    aad.asSlice(aadOffset, aadLength), (int) aadLength),
                    "EVP_CipherUpdate with the additional data");
        }
        if (length > 0) {
            check((int) call(UPDATE, context, out.asSlice(outOffset, length), written,
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
            call(CTX_FREE, old);
        }
        if (!decrypting.equals(MemorySegment.NULL)) {
            MemorySegment old = decrypting;
            decrypting = MemorySegment.NULL;
            call(CTX_FREE, old);
        }
    }

    private static void check(int result, String what) {
        if (result <= 0) {
            throw new IllegalStateException("OpenSSL AES-GCM failed in " + what);
        }
    }

    private static MethodHandle bind(String name, ValueLayout result, ValueLayout... arguments) {
        FunctionDescriptor descriptor = result == null ? FunctionDescriptor.ofVoid(arguments)
                : FunctionDescriptor.of(result, arguments);
        return Linker.nativeLinker().downcallHandle(LIB.find(name).orElseThrow(), descriptor);
    }

    private static Object call(MethodHandle function, Object... arguments) {
        try {
            return function.invokeWithArguments(arguments);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("OpenSSL AES-GCM downcall failed", e);
        }
    }
}
