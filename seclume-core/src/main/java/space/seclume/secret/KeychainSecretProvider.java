package space.seclume.secret;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

import space.seclume.internal.OffHeapIo;
import space.seclume.internal.Platform;

/**
 * The macOS Keychain: a generic password, found by service and account, as
 * the {@code security} tool stores it:
 *
 * {@snippet lang = "shell":
 * security add-generic-password -s orders-db -a app -w
 * }
 *
 * <pre>
 * provider=keychain&amp;service=orders-db&amp;account=app
 * </pre>
 *
 * <p>Read with {@code SecItemCopyMatching} from Security.framework, which
 * answers a {@code CFData} in the process's native memory; its bytes are
 * copied into the target and the data released. The service and account are
 * not secrets. A keychain that asks the user for permission does so the first
 * time, as for any application.
 *
 * <p><b>Not tested on a Mac yet</b> - written against Apple's documented C
 * API, it is the one provider seclume's CI does not run. Anywhere but macOS it
 * says it is not available.
 */
public final class KeychainSecretProvider implements SecretProvider {

    private static final int ERR_SEC_SUCCESS = 0;
    private static final int ERR_SEC_ITEM_NOT_FOUND = -25300;
    private static final int UTF8 = 0x08000100;                  // kCFStringEncodingUTF8

    private static final MethodHandle COPY_MATCHING;
    private static final MethodHandle DICTIONARY_CREATE;
    private static final MethodHandle DICTIONARY_SET;
    private static final MethodHandle STRING_CREATE;
    private static final MethodHandle DATA_LENGTH;
    private static final MethodHandle DATA_BYTES;
    private static final MethodHandle RELEASE;
    private static final Constants CONSTANTS;

    /** The CoreFoundation and Security constants a query is made of: pointers in global variables. */
    private record Constants(MemorySegment keyCallbacks, MemorySegment valueCallbacks,
                             MemorySegment secClass, MemorySegment genericPassword,
                             MemorySegment service, MemorySegment account,
                             MemorySegment returnData, MemorySegment matchLimit,
                             MemorySegment matchLimitOne, MemorySegment booleanTrue) {
    }

    static {
        MethodHandle copyMatching = null;
        MethodHandle dictionaryCreate = null;
        MethodHandle dictionarySet = null;
        MethodHandle stringCreate = null;
        MethodHandle dataLength = null;
        MethodHandle dataBytes = null;
        MethodHandle release = null;
        Constants constants = null;
        if (Platform.isMac()) {
            try {
                Linker linker = Linker.nativeLinker();
                SymbolLookup security = SymbolLookup.libraryLookup(
                        "/System/Library/Frameworks/Security.framework/Security", Arena.global());
                SymbolLookup cf = SymbolLookup.libraryLookup(
                        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                        Arena.global());
                // OSStatus SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result)
                copyMatching = linker.downcallHandle(security.find("SecItemCopyMatching")
                        .orElseThrow(), FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS));
                dictionaryCreate = linker.downcallHandle(cf.find("CFDictionaryCreateMutable")
                        .orElseThrow(), FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS));
                dictionarySet = linker.downcallHandle(cf.find("CFDictionarySetValue").orElseThrow(),
                        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS));
                stringCreate = linker.downcallHandle(cf.find("CFStringCreateWithCString")
                        .orElseThrow(), FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
                dataLength = linker.downcallHandle(cf.find("CFDataGetLength").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
                dataBytes = linker.downcallHandle(cf.find("CFDataGetBytePtr").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
                release = linker.downcallHandle(cf.find("CFRelease").orElseThrow(),
                        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
                constants = new Constants(
                        cf.find("kCFTypeDictionaryKeyCallBacks").orElseThrow(),
                        cf.find("kCFTypeDictionaryValueCallBacks").orElseThrow(),
                        pointer(security, "kSecClass"), pointer(security, "kSecClassGenericPassword"),
                        pointer(security, "kSecAttrService"), pointer(security, "kSecAttrAccount"),
                        pointer(security, "kSecReturnData"), pointer(security, "kSecMatchLimit"),
                        pointer(security, "kSecMatchLimitOne"), pointer(cf, "kCFBooleanTrue"));
            } catch (RuntimeException absent) {
                copyMatching = null;
            }
        }
        COPY_MATCHING = copyMatching;
        DICTIONARY_CREATE = dictionaryCreate;
        DICTIONARY_SET = dictionarySet;
        STRING_CREATE = stringCreate;
        DATA_LENGTH = dataLength;
        DATA_BYTES = dataBytes;
        RELEASE = release;
        CONSTANTS = constants;
    }

    /** The value of a global {@code CFStringRef} variable: the variable holds the pointer. */
    private static MemorySegment pointer(SymbolLookup library, String name) {
        return library.find(name).orElseThrow().reinterpret(ValueLayout.ADDRESS.byteSize())
                .get(ValueLayout.ADDRESS, 0);
    }

    private final String service;
    private final String account;
    private final int maxLength;

    /** @param account the account, or {@code null} for any under the service */
    public KeychainSecretProvider(String service, String account, int maxLength) {
        if (service == null || service.isBlank()) {
            throw new IllegalArgumentException("keychain needs 'service' - the -s of "
                    + "security add-generic-password");
        }
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        this.service = service;
        this.account = account == null || account.isBlank() ? null : account;
        this.maxLength = maxLength;
    }

    /** Whether Security.framework could be loaded here: macOS. */
    public static boolean available() {
        return COPY_MATCHING != null;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        OffHeapIo.requireNative(target);
        if (COPY_MATCHING == null) {
            throw new SecretUnavailableException("the macOS Keychain is not available on this "
                    + "platform");
        }
        MemorySegment query = MemorySegment.NULL;
        MemorySegment serviceName = MemorySegment.NULL;
        MemorySegment accountName = MemorySegment.NULL;
        try (Arena arena = Arena.ofConfined()) {
            query = (MemorySegment) DICTIONARY_CREATE.invokeExact(MemorySegment.NULL, 0L,
                    CONSTANTS.keyCallbacks(), CONSTANTS.valueCallbacks());
            serviceName = (MemorySegment) STRING_CREATE.invokeExact(MemorySegment.NULL,
                    arena.allocateFrom(service), UTF8);
            DICTIONARY_SET.invokeExact(query, CONSTANTS.secClass(), CONSTANTS.genericPassword());
            DICTIONARY_SET.invokeExact(query, CONSTANTS.service(), serviceName);
            if (account != null) {
                accountName = (MemorySegment) STRING_CREATE.invokeExact(MemorySegment.NULL,
                        arena.allocateFrom(account), UTF8);
                DICTIONARY_SET.invokeExact(query, CONSTANTS.account(), accountName);
            }
            DICTIONARY_SET.invokeExact(query, CONSTANTS.returnData(), CONSTANTS.booleanTrue());
            DICTIONARY_SET.invokeExact(query, CONSTANTS.matchLimit(), CONSTANTS.matchLimitOne());
            MemorySegment result = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) COPY_MATCHING.invokeExact(query, result);
            if (status == ERR_SEC_ITEM_NOT_FOUND) {
                throw new SecretUnavailableException("no generic password in the keychain for "
                        + "service " + service + (account == null ? "" : ", account " + account)
                        + " - store one with security add-generic-password -s " + service
                        + (account == null ? "" : " -a " + account) + " -w");
            }
            if (status != ERR_SEC_SUCCESS) {
                throw new SecretUnavailableException("SecItemCopyMatching answered OSStatus "
                        + status + " for service " + service);
            }
            MemorySegment data = result.get(ValueLayout.ADDRESS, 0);
            try {
                long size = (long) DATA_LENGTH.invokeExact(data);
                if (size <= 0) {
                    throw new SecretUnavailableException("the keychain item for service "
                            + service + " is empty");
                }
                if (size > target.byteSize()) {
                    throw new SecretUnavailableException("the keychain item for service "
                            + service + " is longer than the configured " + maxLength + " bytes");
                }
                MemorySegment bytes = (MemorySegment) DATA_BYTES.invokeExact(data);
                MemorySegment.copy(bytes.reinterpret(size), 0, target, 0, size);
                return (int) size;
            } finally {
                RELEASE.invokeExact(data);
            }
        } catch (SecretUnavailableException e) {
            throw e;
        } catch (Throwable t) {
            throw new SecretUnavailableException("the keychain lookup failed for service "
                    + service, t);
        } finally {
            release(accountName);
            release(serviceName);
            release(query);
        }
    }

    private static void release(MemorySegment object) {
        if (!object.equals(MemorySegment.NULL)) {
            try {
                RELEASE.invokeExact(object);
            } catch (Throwable ignored) {
                // nothing else to free it with
            }
        }
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public String toString() {
        return "KeychainSecretProvider[service=" + service
                + (account == null ? "" : ", account=" + account) + "]";
    }
}
