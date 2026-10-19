package space.seclume.secret;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.LinkedHashMap;
import java.util.Map;

import space.seclume.internal.OffHeapIo;
import space.seclume.internal.Platform;

/**
 * The Linux desktop's keyring - GNOME Keyring, KWallet or KeePassXC behind the
 * freedesktop Secret Service - through libsecret.
 *
 * <p>An item is found by its attributes, as {@code secret-tool} stores it:
 *
 * {@snippet lang = "shell":
 * secret-tool store --label='orders db' service orders-db account app
 * }
 *
 * <pre>
 * provider=libsecret&amp;attribute.service=orders-db&amp;attribute.account=app
 * </pre>
 *
 * <p>Read with {@code secret_password_lookupv_binary_sync}, which answers a
 * {@code SecretValue}: libsecret keeps it in its own non-pageable memory,
 * which it wipes when the value is released. The bytes are copied from there
 * into the target and the value released - the password never becomes a
 * {@code String}, nor a {@code gchar*} of the ordinary heap, which the
 * non-binary lookup would have returned. The attributes are not secrets.
 *
 * <p>The item may have been stored under any schema: the lookup matches the
 * attributes only ({@code SECRET_SCHEMA_DONT_MATCH_NAME}). A locked keyring
 * is unlocked the way the desktop does it, by prompting - in a headless
 * process that fails, and the message says so.
 */
public final class LibsecretSecretProvider implements SecretProvider {

    /** {@code SECRET_SCHEMA_DONT_MATCH_NAME}: an item stored under another schema is found too. */
    private static final int DONT_MATCH_NAME = 1 << 1;
    /** {@code SecretSchema}: name, flags, 32 attributes of {name, type}, then reserved fields. */
    private static final long SCHEMA_SIZE = 8 + 8 + 32 * 16 + 8 + 7 * 8;
    private static final int MAX_ATTRIBUTES = 32;

    private static final MethodHandle LOOKUP;
    private static final MethodHandle VALUE_GET;
    private static final MethodHandle VALUE_UNREF;
    private static final MethodHandle TABLE_NEW;
    private static final MethodHandle TABLE_INSERT;
    private static final MethodHandle TABLE_UNREF;
    private static final MethodHandle ERROR_FREE;
    private static final MemorySegment STR_HASH;
    private static final MemorySegment STR_EQUAL;

    static {
        MethodHandle lookup = null;
        MethodHandle valueGet = null;
        MethodHandle valueUnref = null;
        MethodHandle tableNew = null;
        MethodHandle tableInsert = null;
        MethodHandle tableUnref = null;
        MethodHandle errorFree = null;
        MemorySegment strHash = null;
        MemorySegment strEqual = null;
        if (Platform.isLinux()) {
            try {
                Linker linker = Linker.nativeLinker();
                SymbolLookup secret = SymbolLookup.libraryLookup("libsecret-1.so.0", Arena.global());
                SymbolLookup glib = SymbolLookup.libraryLookup("libglib-2.0.so.0", Arena.global());
                // SecretValue *secret_password_lookupv_binary_sync(const SecretSchema *,
                //         GHashTable *attributes, GCancellable *, GError **)
                lookup = linker.downcallHandle(
                        secret.find("secret_password_lookupv_binary_sync").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
                // const gchar *secret_value_get(SecretValue *, gsize *length)
                valueGet = linker.downcallHandle(secret.find("secret_value_get").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS));
                valueUnref = linker.downcallHandle(secret.find("secret_value_unref").orElseThrow(),
                        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
                tableNew = linker.downcallHandle(glib.find("g_hash_table_new").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS));
                tableInsert = linker.downcallHandle(glib.find("g_hash_table_insert").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS, ValueLayout.ADDRESS));
                tableUnref = linker.downcallHandle(glib.find("g_hash_table_unref").orElseThrow(),
                        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
                errorFree = linker.downcallHandle(glib.find("g_error_free").orElseThrow(),
                        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
                strHash = glib.find("g_str_hash").orElseThrow();
                strEqual = glib.find("g_str_equal").orElseThrow();
            } catch (RuntimeException absent) {
                // No libsecret (a server without a desktop): writeSecret says so.
                lookup = null;
            }
        }
        LOOKUP = lookup;
        VALUE_GET = valueGet;
        VALUE_UNREF = valueUnref;
        TABLE_NEW = tableNew;
        TABLE_INSERT = tableInsert;
        TABLE_UNREF = tableUnref;
        ERROR_FREE = errorFree;
        STR_HASH = strHash;
        STR_EQUAL = strEqual;
    }

    private final Map<String, String> attributes;
    private final int maxLength;

    /** @param attributes what the item is found by - {@code service}, {@code account}, ... */
    public LibsecretSecretProvider(Map<String, String> attributes, int maxLength) {
        if (attributes == null || attributes.isEmpty()) {
            throw new IllegalArgumentException("libsecret needs the attributes the item is "
                    + "found by: attribute.service=...&attribute.account=..., as secret-tool "
                    + "stores them");
        }
        if (attributes.size() > MAX_ATTRIBUTES) {
            throw new IllegalArgumentException("at most " + MAX_ATTRIBUTES + " attributes");
        }
        if (maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
        this.attributes = new LinkedHashMap<>(attributes);
        this.maxLength = maxLength;
    }

    /** Whether libsecret could be loaded here. */
    public static boolean available() {
        return LOOKUP != null;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        OffHeapIo.requireNative(target);
        if (LOOKUP == null) {
            throw new SecretUnavailableException("libsecret (libsecret-1.so.0) is not available "
                    + "here - it is the Linux desktop's keyring; a server takes another provider");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment schema = arena.allocate(SCHEMA_SIZE, 8);
            schema.set(ValueLayout.ADDRESS, 0, arena.allocateFrom("space.seclume.Lookup"));
            schema.set(ValueLayout.JAVA_INT, 8, DONT_MATCH_NAME);
            MemorySegment table = (MemorySegment) TABLE_NEW.invokeExact(STR_HASH, STR_EQUAL);
            MemorySegment error = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment value;
            try {
                int at = 0;
                for (Map.Entry<String, String> attribute : attributes.entrySet()) {
                    MemorySegment name = arena.allocateFrom(attribute.getKey());
                    schema.set(ValueLayout.ADDRESS, 16 + at * 16L, name);
                    schema.set(ValueLayout.JAVA_INT, 16 + at * 16L + 8, 0);   // a string
                    int _ = (int) TABLE_INSERT.invokeExact(table, name,
                            arena.allocateFrom(attribute.getValue()));
                    at++;
                }
                value = (MemorySegment) LOOKUP.invokeExact(schema, table, MemorySegment.NULL,
                        error);
            } finally {
                TABLE_UNREF.invokeExact(table);
            }
            MemorySegment failure = error.get(ValueLayout.ADDRESS, 0);
            if (!failure.equals(MemorySegment.NULL)) {
                // GError: a quark, a code, the message - which names no secret.
                MemorySegment message = failure.reinterpret(16).get(ValueLayout.ADDRESS, 8);
                String why = message.equals(MemorySegment.NULL) ? "no message"
                        : message.reinterpret(4096).getString(0);
                ERROR_FREE.invokeExact(failure);
                throw new SecretUnavailableException("the Secret Service refused the lookup of "
                        + attributes + ": " + why + " - is a keyring running and unlocked "
                        + "for this session?");
            }
            if (value.equals(MemorySegment.NULL)) {
                throw new SecretUnavailableException("no item in the keyring with " + attributes
                        + " - store one with secret-tool store --label=... " + String.join(" ",
                                attributes.entrySet().stream()
                                        .map(e -> e.getKey() + " " + e.getValue()).toList()));
            }
            try {
                MemorySegment length = arena.allocate(ValueLayout.JAVA_LONG);
                MemorySegment bytes = (MemorySegment) VALUE_GET.invokeExact(value, length);
                long size = length.get(ValueLayout.JAVA_LONG, 0);
                if (size <= 0) {
                    throw new SecretUnavailableException("the item with " + attributes
                            + " is empty");
                }
                if (size > target.byteSize()) {
                    throw new SecretUnavailableException("the item with " + attributes
                            + " is longer than the configured " + maxLength + " bytes");
                }
                MemorySegment.copy(bytes.reinterpret(size), 0, target, 0, size);
                return (int) size;
            } finally {
                VALUE_UNREF.invokeExact(value);    // libsecret wipes its secure memory
            }
        } catch (SecretUnavailableException e) {
            throw e;
        } catch (Throwable t) {
            throw new SecretUnavailableException("the libsecret lookup failed for " + attributes,
                    t);
        }
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    @Override
    public String toString() {
        return "LibsecretSecretProvider" + attributes;
    }
}
