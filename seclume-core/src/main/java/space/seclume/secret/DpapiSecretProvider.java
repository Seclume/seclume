package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import space.seclume.internal.OffHeapIo;
import space.seclume.internal.Platform;
import space.seclume.internal.Utf;

/**
 * Windows built-in: a DPAPI blob in a file.
 *
 * <p>For target environments without vault infrastructure this is the built-in
 * key store. Provisioning uses what is present on every Windows:
 *
 * {@snippet lang = "powershell":
 * Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File -Encoding ascii C:\ProgramData\app\db.dpapi
 * }
 *
 * <p>That produces exactly the blob this class expects - DPAPI in the user
 * context, hex encoded. For a service this has to run <b>as the service
 * account</b>, otherwise the service cannot decrypt the blob later. An
 * application salt as a second factor is optional ({@code entropy}).
 *
 * <p>The plaintext buffer {@code CryptUnprotectData} returns is allocated with
 * {@code LocalAlloc}. It is therefore <b>zeroed first and released after</b>: an
 * unzeroed buffer in the OS heap defeats the core property just as much as a
 * Java {@code byte[]} would.
 *
 * <p>The plaintext is UTF-16LE - that is how {@code SecureString} stored it. It
 * is converted to UTF-8 off-heap; whoever needs the raw bytes turns that off
 * with {@link #raw()}.
 */
public final class DpapiSecretProvider implements SecretProvider {

    private static final MethodHandle CRYPT_UNPROTECT_DATA;
    private static final MethodHandle LOCAL_FREE;

    /** DATA_BLOB { DWORD cbData; BYTE *pbData; } - the layout computes the offsets. */
    private static final MemoryLayout DATA_BLOB = MemoryLayout.structLayout(
            ValueLayout.JAVA_INT.withName("cbData"),
            MemoryLayout.paddingLayout(4),
            ValueLayout.ADDRESS.withName("pbData"));
    private static final VarHandle BLOB_SIZE =
            DATA_BLOB.varHandle(MemoryLayout.PathElement.groupElement("cbData"));
    private static final VarHandle BLOB_DATA =
            DATA_BLOB.varHandle(MemoryLayout.PathElement.groupElement("pbData"));

    static {
        MethodHandle unprotect = null;
        MethodHandle free = null;
        if (Platform.isWindows()) {
            try {
                Linker linker = Linker.nativeLinker();
                SymbolLookup crypt32 = SymbolLookup.libraryLookup("crypt32.dll", Arena.global());
                SymbolLookup kernel32 = SymbolLookup.libraryLookup("kernel32.dll", Arena.global());
                // BOOL CryptUnprotectData(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID,
                //                         CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*)
                unprotect = linker.downcallHandle(
                        crypt32.find("CryptUnprotectData").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS));
                free = linker.downcallHandle(kernel32.find("LocalFree").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
            } catch (RuntimeException e) {
                unprotect = null;
                free = null;
            }
        }
        CRYPT_UNPROTECT_DATA = unprotect;
        LOCAL_FREE = free;
    }

    private final Path path;
    private final byte[] entropy;
    private final int maxLength;
    private final boolean convertToUtf8;

    public DpapiSecretProvider(Path path, int maxLength) {
        this(path, null, maxLength, true);
    }

    /**
     * @param entropy optional second factor; it has to have been the same when
     *        the blob was encrypted
     */
    public DpapiSecretProvider(Path path, String entropy, int maxLength) {
        this(path, entropy, maxLength, true);
    }

    private DpapiSecretProvider(Path path, String entropy, int maxLength, boolean convertToUtf8) {
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        this.path = path;
        // seclume-allow: the entropy is an application salt from the configuration, not the secret
        this.entropy = entropy == null ? null : entropy.getBytes(StandardCharsets.UTF_16LE);
        this.maxLength = maxLength;
        this.convertToUtf8 = convertToUtf8;
    }

    /** Returns the decrypted raw bytes instead of the UTF-8 form. */
    public DpapiSecretProvider raw() {
        return new DpapiSecretProvider(path, null, maxLength, false);
    }

    @Override
    public int writeSecret(MemorySegment target) {
        OffHeapIo.requireNative(target);
        if (CRYPT_UNPROTECT_DATA == null) {
            throw new SecretUnavailableException(
                    "DPAPI is only available on Windows; use a file, a unix socket "
                    + "or your own SecretProvider on this platform");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment blob = readHexBlob(arena);
            MemorySegment in = arena.allocate(DATA_BLOB);
            MemorySegment out = arena.allocate(DATA_BLOB);
            MemorySegment entropyBlob = entropy == null ? MemorySegment.NULL : arena.allocate(DATA_BLOB);
            MemorySegment entropyBytes = null;
            try {
                BLOB_SIZE.set(in, 0L, (int) blob.byteSize());
                BLOB_DATA.set(in, 0L, blob);
                if (entropy != null) {
                    entropyBytes = arena.allocate(entropy.length);
                    MemorySegment.copy(MemorySegment.ofArray(entropy), 0, entropyBytes, 0,
                            entropy.length);
                    BLOB_SIZE.set(entropyBlob, 0L, entropy.length);
                    BLOB_DATA.set(entropyBlob, 0L, entropyBytes);
                }

                int ok = (int) CRYPT_UNPROTECT_DATA.invokeExact(
                        in, MemorySegment.NULL, entropyBlob, MemorySegment.NULL,
                        MemorySegment.NULL, 0, out);
                if (ok == 0) {
                    throw new SecretUnavailableException(
                            "CryptUnprotectData failed for " + path
                            + " - was the blob created by this user"
                            + (entropy != null ? " and with this entropy?" : "?"));
                }
                return copyOut(out, target, arena);
            } catch (SecretUnavailableException e) {
                throw e;
            } catch (Throwable t) {
                throw new SecretUnavailableException("DPAPI call failed for " + path, t);
            } finally {
                blob.fill((byte) 0);
                if (entropyBytes != null) {
                    entropyBytes.fill((byte) 0);
                }
            }
        }
    }

    /** Copies the plaintext out and cleans up the native buffer. */
    private int copyOut(MemorySegment out, MemorySegment target, Arena arena) throws Throwable {
        int size = (int) BLOB_SIZE.get(out, 0L);
        MemorySegment plain = ((MemorySegment) BLOB_DATA.get(out, 0L)).reinterpret(size);
        try {
            if (!convertToUtf8) {
                requireFits(size, target);
                MemorySegment.copy(plain, 0, target, 0, size);
                return size;
            }
            // First into an intermediate buffer that is certainly large
            // enough - otherwise one would have to guess the UTF-8 length and
            // would either reject a legitimate password or write past the
            // target.
            MemorySegment converted = arena.allocate(Utf.utf8UpperBound(size) + 1);
            try {
                int length = Utf.utf16LeToUtf8(plain, 0, size, converted, 0);
                requireFits(length, target);
                MemorySegment.copy(converted, 0, target, 0, length);
                return length;
            } finally {
                converted.fill((byte) 0);
            }
        } finally {
            // Zero first, release second - in that order. Afterwards it is
            // verified that this actually took effect: the buffer belongs to
            // the OS heap, and a silent failure here would be exactly the leak
            // this library exists to prevent.
            plain.fill((byte) 0);
            lastBufferWasZeroed = isAllZero(plain);
            MemorySegment ignored = (MemorySegment) LOCAL_FREE.invokeExact(plain);
        }
    }

    /** Result of the last zeroing check; the platform test reads this. */
    static volatile boolean lastBufferWasZeroed;

    private static boolean isAllZero(MemorySegment segment) {
        for (long i = 0; i < segment.byteSize(); i++) {
            if (segment.get(ValueLayout.JAVA_BYTE, i) != 0) {
                return false;
            }
        }
        return true;
    }

    private void requireFits(int length, MemorySegment target) {
        if (length > target.byteSize()) {
            throw new SecretUnavailableException(
                    "the secret in " + path + " is longer than the configured "
                    + maxLength + " bytes");
        }
    }

    /** Reads the hex file and decodes it off-heap; {@code HexFormat} is ruled out. */
    private MemorySegment readHexBlob(Arena arena) {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            long size = channel.size();
            if (size < 2 || size > (1 << 20)) {
                throw new SecretUnavailableException(path + " does not look like a DPAPI blob");
            }
            MemorySegment text = arena.allocate(size);
            try {
                int read = OffHeapIo.readFully(channel, text);
                int digits = 0;
                for (int i = 0; i < read; i++) {
                    if (isHexDigit(text.get(ValueLayout.JAVA_BYTE, i))) {
                        digits++;
                    }
                }
                if (digits == 0 || (digits & 1) != 0) {
                    throw new SecretUnavailableException(
                            path + " does not contain an even number of hex digits");
                }
                MemorySegment blob = arena.allocate(digits / 2);
                int nibble = 0;
                int value = 0;
                int position = 0;
                for (int i = 0; i < read; i++) {
                    byte c = text.get(ValueLayout.JAVA_BYTE, i);
                    if (!isHexDigit(c)) {
                        continue;
                    }
                    value = (value << 4) | hexValue(c);
                    if (++nibble == 2) {
                        blob.set(ValueLayout.JAVA_BYTE, position++, (byte) value);
                        nibble = 0;
                        value = 0;
                    }
                }
                return blob;
            } finally {
                text.fill((byte) 0);
            }
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot read " + path, e);
        }
    }

    private static boolean isHexDigit(byte c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /** A checked hex digit's value, without a branch: '0'-'9' are 0x3_, letters 0x4_/0x6_. */
    private static int hexValue(byte c) {
        return (c & 0xf) + 9 * ((c >> 6) & 1);
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public String toString() {
        return "DpapiSecretProvider[path=" + path + ", entropy=" + (entropy != null) + "]";
    }
}
