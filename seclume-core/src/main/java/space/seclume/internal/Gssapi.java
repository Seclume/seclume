package space.seclume.internal;

import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;

/**
 * Kerberos through the system's GSSAPI (MIT {@code libgssapi_krb5}) - the
 * login with no secret in the process at all.
 *
 * <p>The credentials are the operating system's: a ticket in the credential
 * cache that {@code kinit}, a keytab or the machine's login put there. This
 * class only asks the library to turn that ticket into the tokens a server
 * wants, and hands the tokens on. The tokens themselves are protocol data -
 * a ticket encrypted for the server and an authenticator - not the key.
 *
 * <p>64-bit Linux; elsewhere {@link #available()} says no. (Windows speaks
 * Kerberos through SSPI, which is a different library and not this one.)
 */
public final class Gssapi {

    private static final int COMPLETE = 0;
    private static final int CONTINUE_NEEDED = 1;
    private static final int MUTUAL_FLAG = 2;
    private static final int GSS_CODE = 1;
    private static final int MECH_CODE = 2;
    /** gss_buffer_desc: size_t length, void* value. */
    private static final long BUFFER = 16;

    private Gssapi() {
    }

    /** Whether the system's GSSAPI library can be used here. */
    public static boolean available() {
        return Native.AVAILABLE;
    }

    /**
     * A security context for {@code service@host} - {@code postgres@db.example}
     * for PostgreSQL - to be driven by {@link Context#step}.
     */
    public static Context initiate(String service, String host) {
        if (!available()) {
            throw new IllegalStateException("Kerberos needs the GSSAPI library "
                    + "(libgssapi_krb5.so.2) on 64-bit Linux");
        }
        return new Context(service + "@" + host, Native.HOSTBASED);
    }

    /**
     * A security context for a Kerberos principal written out in full -
     * {@code mariadb/db.example@EXAMPLE.COM} - which is how MariaDB names
     * itself to the client.
     */
    public static Context initiatePrincipal(String principal) {
        if (!available()) {
            throw new IllegalStateException("Kerberos needs the GSSAPI library "
                    + "(libgssapi_krb5.so.2) on 64-bit Linux");
        }
        return new Context(principal, Native.USER_NAME);
    }

    /** One login's exchange of tokens. */
    public static final class Context implements AutoCloseable {

        private final Arena arena = Arena.ofShared();
        private final MemorySegment name;
        private final MemorySegment handle;
        private boolean complete;

        private Context(String principal, MemorySegment nameType) {
            MemorySegment minor = arena.allocate(JAVA_INT);
            MemorySegment input = arena.allocate(BUFFER);
            byte[] text = principal.getBytes(StandardCharsets.UTF_8); // seclume-allow: a service name, not a secret
            MemorySegment bytes = arena.allocate(text.length);
            MemorySegment.copy(text, 0, bytes, JAVA_BYTE, 0, text.length);
            input.set(JAVA_LONG, 0, text.length);
            input.set(ADDRESS, 8, bytes);
            MemorySegment out = arena.allocate(ADDRESS);
            check((int) Native.call(Native.IMPORT_NAME, minor, input, nameType, out), minor,
                    "the service name " + principal + " was refused");
            name = out.get(ADDRESS, 0);
            handle = arena.allocate(ADDRESS);          // GSS_C_NO_CONTEXT to begin with
        }

        /**
         * The next token for the server, from the server's last one (null for
         * the first step). Empty when there is nothing more to send.
         */
        public byte[] step(MemorySegment serverToken, long offset, int length) {
            try (Arena call = Arena.ofConfined()) {
                MemorySegment minor = call.allocate(JAVA_INT);
                MemorySegment input = NULL;
                if (serverToken != null) {
                    input = call.allocate(BUFFER);
                    input.set(JAVA_LONG, 0, length);
                    input.set(ADDRESS, 8, serverToken.asSlice(offset, length));
                }
                MemorySegment output = call.allocate(BUFFER);
                MemorySegment flags = call.allocate(JAVA_INT);
                int major = (int) Native.call(Native.INIT_SEC_CONTEXT, minor, NULL, handle, name,
                        NULL, MUTUAL_FLAG, 0, NULL, input, NULL, output, flags, NULL);
                check(major, minor, "the Kerberos exchange failed");
                complete = (major & 0xffff) == COMPLETE;
                long size = output.get(JAVA_LONG, 0);
                byte[] token = new byte[(int) size]; // seclume-allow: a GSSAPI token, protocol data and not the key
                if (size > 0) {
                    MemorySegment.copy(output.get(ADDRESS, 8).reinterpret(size), JAVA_BYTE, 0,
                            token, 0, (int) size);
                    Native.call(Native.RELEASE_BUFFER, minor, output);
                }
                return token;
            }
        }

        /** Whether the library considers the context established. */
        public boolean complete() {
            return complete;
        }

        @Override
        public void close() {
            try (Arena call = Arena.ofConfined()) {
                MemorySegment minor = call.allocate(JAVA_INT);
                if (!handle.get(ADDRESS, 0).equals(NULL)) {
                    Native.call(Native.DELETE_SEC_CONTEXT, minor, handle, NULL);
                }
                MemorySegment names = call.allocate(ADDRESS);
                names.set(ADDRESS, 0, name);
                Native.call(Native.RELEASE_NAME, minor, names);
            } finally {
                arena.close();
            }
        }

        private static void check(int major, MemorySegment minor, String what) {
            if (major == COMPLETE || major == CONTINUE_NEEDED
                    || (major & 0xffff0000) == 0 && (major & 0xffff) <= CONTINUE_NEEDED) {
                return;
            }
            throw new IllegalStateException(what + " - the GSSAPI library says: "
                    + describe(major, GSS_CODE) + ", and Kerberos: "
                    + describe(minor.get(JAVA_INT, 0), MECH_CODE));
        }
    }

    /** What the library says a status means - "No Kerberos credentials available", say. */
    private static String describe(int status, int type) {
        StringBuilder text = new StringBuilder(); // seclume-allow: a status message, no secret
        try (Arena call = Arena.ofConfined()) {
            MemorySegment minor = call.allocate(JAVA_INT);
            MemorySegment context = call.allocate(JAVA_INT);
            do {
                MemorySegment message = call.allocate(BUFFER);
                int major = (int) Native.call(Native.DISPLAY_STATUS, minor, status, type, NULL,
                        context, message);
                if (major != COMPLETE) {
                    break;
                }
                long size = message.get(JAVA_LONG, 0);
                if (!text.isEmpty()) {
                    text.append("; ");
                }
                text.append(new String(message.get(ADDRESS, 8).reinterpret(size) // seclume-allow: the library's status text, no secret
                        .toArray(JAVA_BYTE), StandardCharsets.UTF_8));
                Native.call(Native.RELEASE_BUFFER, minor, message);
            } while (context.get(JAVA_INT, 0) != 0);
        }
        return text.isEmpty() ? "status " + Integer.toHexString(status) : text.toString();
    }

    /** The GSSAPI downcalls, loaded only where the library is. */
    private static final class Native {

        static final boolean AVAILABLE;
        static final MethodHandle IMPORT_NAME;
        static final MethodHandle INIT_SEC_CONTEXT;
        static final MethodHandle RELEASE_BUFFER;
        static final MethodHandle DELETE_SEC_CONTEXT;
        static final MethodHandle RELEASE_NAME;
        static final MethodHandle DISPLAY_STATUS;
        static final MemorySegment HOSTBASED;
        static final MemorySegment USER_NAME;

        /** Set in the static initialiser before the first bind, where the library is. */
        private static SymbolLookup lookup;

        static {
            MethodHandle[] handles = new MethodHandle[6];
            MemorySegment hostbased = NULL;
            MemorySegment userName = NULL;
            boolean available = false;
            if (Platform.isLinux() && ValueLayout.ADDRESS.byteSize() == 8) {
                try {
                    lookup = SymbolLookup.libraryLookup("libgssapi_krb5.so.2", Arena.global());
                    handles[0] = bind("gss_import_name", JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS);
                    handles[1] = bind("gss_init_sec_context", JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS);
                    handles[2] = bind("gss_release_buffer", JAVA_INT, ADDRESS, ADDRESS);
                    handles[3] = bind("gss_delete_sec_context", JAVA_INT, ADDRESS, ADDRESS, ADDRESS);
                    handles[4] = bind("gss_release_name", JAVA_INT, ADDRESS, ADDRESS);
                    handles[5] = bind("gss_display_status", JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS, ADDRESS);
                    // An exported gss_OID variable: its address, read as a pointer.
                    hostbased = lookup.find("GSS_C_NT_HOSTBASED_SERVICE").orElseThrow()
                            .reinterpret(8).get(ADDRESS, 0);
                    userName = lookup.find("GSS_C_NT_USER_NAME").orElseThrow()
                            .reinterpret(8).get(ADDRESS, 0);
                    available = true;
                } catch (Throwable absent) {
                    available = false;
                }
            }
            AVAILABLE = available;
            IMPORT_NAME = handles[0];
            INIT_SEC_CONTEXT = handles[1];
            RELEASE_BUFFER = handles[2];
            DELETE_SEC_CONTEXT = handles[3];
            RELEASE_NAME = handles[4];
            DISPLAY_STATUS = handles[5];
            HOSTBASED = hostbased;
            USER_NAME = userName;
        }

        private static MethodHandle bind(String name, ValueLayout result, ValueLayout... arguments) {
            FunctionDescriptor descriptor = result == null ? FunctionDescriptor.ofVoid(arguments)
                    : FunctionDescriptor.of(result, arguments);
            return Linker.nativeLinker().downcallHandle(lookup.find(name).orElseThrow(), descriptor);
        }

        static Object call(MethodHandle function, Object... arguments) {
            try {
                return function.invokeWithArguments(arguments);
            } catch (RuntimeException | Error e) {
                throw e;
            } catch (Throwable e) {
                throw new IllegalStateException("GSSAPI downcall failed", e);
            }
        }
    }
}
