package space.seclume.secret;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;

import space.seclume.internal.OffHeapIo;
import space.seclume.internal.Platform;
import space.seclume.internal.Utf;

/**
 * Windows Credential Manager, generische Anmeldeinformation.
 *
 * <p>It is stored with the built-in tools:
 *
 * {@snippet lang = "powershell":
 * cmdkey /generic:seclume/reporting /user:app /pass
 * }
 *
 * <p>or through the Credential Manager window in the control panel. Reading
 * goes through {@code advapi32!CredReadW}; the result belongs to the caller and
 * is released with {@code CredFree} - zeroed first, because the blob holds the
 * password in the clear.
 *
 * <p>The field offsets of {@code CREDENTIALW} come from a {@link MemoryLayout}
 * with named fields. Hard-coded offsets would be particularly risky here: the
 * structure contains pointers whose size and alignment depend on the
 * architecture.
 *
 * <p>The blob is whatever was written into it - {@code cmdkey} and the UI store
 * UTF-16LE. It is therefore converted to UTF-8 off-heap, as with DPAPI;
 * {@link #raw()} returns the raw bytes.
 */
public final class CredentialManagerSecretProvider implements SecretProvider {

    /** CRED_TYPE_GENERIC */
    private static final int CRED_TYPE_GENERIC = 1;

    private static final MemoryLayout CREDENTIALW = MemoryLayout.structLayout(
            ValueLayout.JAVA_INT.withName("Flags"),
            ValueLayout.JAVA_INT.withName("Type"),
            ValueLayout.ADDRESS.withName("TargetName"),
            ValueLayout.ADDRESS.withName("Comment"),
            ValueLayout.JAVA_LONG.withName("LastWritten"),
            ValueLayout.JAVA_INT.withName("CredentialBlobSize"),
            MemoryLayout.paddingLayout(4),
            ValueLayout.ADDRESS.withName("CredentialBlob"),
            ValueLayout.JAVA_INT.withName("Persist"),
            ValueLayout.JAVA_INT.withName("AttributeCount"),
            ValueLayout.ADDRESS.withName("Attributes"),
            ValueLayout.ADDRESS.withName("TargetAlias"),
            ValueLayout.ADDRESS.withName("UserName"));

    private static final VarHandle BLOB_SIZE =
            CREDENTIALW.varHandle(MemoryLayout.PathElement.groupElement("CredentialBlobSize"));
    private static final VarHandle BLOB =
            CREDENTIALW.varHandle(MemoryLayout.PathElement.groupElement("CredentialBlob"));

    private static final MethodHandle CRED_READ;
    private static final MethodHandle CRED_FREE;

    static {
        MethodHandle read = null;
        MethodHandle free = null;
        if (Platform.isWindows()) {
            try {
                Linker linker = Linker.nativeLinker();
                SymbolLookup advapi32 = SymbolLookup.libraryLookup("advapi32.dll", Arena.global());
                // BOOL CredReadW(LPCWSTR TargetName, DWORD Type, DWORD Flags, PCREDENTIALW *Credential)
                read = linker.downcallHandle(advapi32.find("CredReadW").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                                ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
                // void CredFree(PVOID Buffer)
                free = linker.downcallHandle(advapi32.find("CredFree").orElseThrow(),
                        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
            } catch (RuntimeException e) {
                read = null;
                free = null;
            }
        }
        CRED_READ = read;
        CRED_FREE = free;
    }

    private final String targetName;
    private final int maxLength;
    private final boolean convertToUtf8;

    public CredentialManagerSecretProvider(String targetName, int maxLength) {
        this(targetName, maxLength, true);
    }

    private CredentialManagerSecretProvider(String targetName, int maxLength, boolean convertToUtf8) {
        if (targetName.isBlank()) {
            throw new IllegalArgumentException("targetName must not be blank");
        }
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        this.targetName = targetName;
        this.maxLength = maxLength;
        this.convertToUtf8 = convertToUtf8;
    }

    /** Returns the blob unchanged instead of the UTF-8 form. */
    public CredentialManagerSecretProvider raw() {
        return new CredentialManagerSecretProvider(targetName, maxLength, false);
    }

    @Override
    public int writeSecret(MemorySegment target) {
        OffHeapIo.requireNative(target);
        if (CRED_READ == null) {
            throw new SecretUnavailableException(
                    "the Windows Credential Manager is not available on this platform");
        }
        try (Arena arena = Arena.ofConfined()) {
            // The target name is not a secret; it may arrive as a String.
            byte[] nameBytes = targetName.getBytes(StandardCharsets.UTF_16LE); // seclume-allow: the target name is configuration, not a secret
            MemorySegment name = arena.allocate(nameBytes.length + 2L);
            MemorySegment.copy(MemorySegment.ofArray(nameBytes), 0, name, 0, nameBytes.length);
            MemorySegment pointer = arena.allocate(ValueLayout.ADDRESS);

            int ok = (int) CRED_READ.invokeExact(name, CRED_TYPE_GENERIC, 0, pointer);
            if (ok == 0) {
                throw new SecretUnavailableException(
                        "no generic credential named " + targetName
                        + " for this user - store one with cmdkey /generic:" + targetName);
            }
            MemorySegment credential = pointer.get(ValueLayout.ADDRESS, 0)
                    .reinterpret(CREDENTIALW.byteSize());
            try {
                int size = (int) BLOB_SIZE.get(credential, 0L);
                MemorySegment blob = ((MemorySegment) BLOB.get(credential, 0L)).reinterpret(size);
                try {
                    return copyOut(blob, size, target, arena);
                } finally {
                    blob.fill((byte) 0);
                }
            } finally {
                CRED_FREE.invokeExact(credential);
            }
        } catch (SecretUnavailableException e) {
            throw e;
        } catch (Throwable t) {
            throw new SecretUnavailableException("CredReadW failed for " + targetName, t);
        }
    }

    private int copyOut(MemorySegment blob, int size, MemorySegment target, Arena arena) {
        if (size == 0) {
            throw new SecretUnavailableException(
                    "the credential " + targetName + " has an empty blob");
        }
        if (!convertToUtf8) {
            requireFits(size, target);
            MemorySegment.copy(blob, 0, target, 0, size);
            return size;
        }
        MemorySegment converted = arena.allocate(Utf.utf8UpperBound(size) + 1);
        try {
            int length = Utf.utf16LeToUtf8(blob, 0, size, converted, 0);
            requireFits(length, target);
            MemorySegment.copy(converted, 0, target, 0, length);
            return length;
        } finally {
            converted.fill((byte) 0);
        }
    }

    private void requireFits(int length, MemorySegment target) {
        if (length > target.byteSize()) {
            throw new SecretUnavailableException(
                    "the credential " + targetName + " is longer than the configured "
                    + maxLength + " bytes");
        }
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public String toString() {
        return "CredentialManagerSecretProvider[target=" + targetName + "]";
    }
}
