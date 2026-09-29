package space.seclume.internal;

import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;

/**
 * Kerberos through Windows' SSPI ({@code secur32.dll}) - the same login as
 * {@link Gssapi} on Linux, with the same property: the credentials are the
 * operating system's. The ticket and its session key live in the LSA, which
 * got them from the domain logon - or, on a machine outside the domain, from
 * {@code runas /netonly} or saved credentials - and never enter this process.
 * What this class handles are the tokens: a ticket encrypted for the server,
 * an authenticator, and the server's answer to it.
 *
 * <p>The Kerberos package, not Negotiate: a server that speaks GSSAPI's
 * Kerberos mechanism (SQL Server's integrated login, PostgreSQL's
 * {@code gss}, MariaDB's {@code auth_gssapi}) gets the same tokens MIT's
 * library would send, and NTLM - a password hash the server could relay - is
 * never offered. Mutual authentication is required.
 */
final class Sspi {

    private static final int SEC_E_OK = 0;
    private static final int SEC_I_CONTINUE_NEEDED = 0x00090312;
    private static final int SECPKG_CRED_OUTBOUND = 2;
    private static final int ISC_REQ_MUTUAL_AUTH = 0x2;
    private static final int ISC_REQ_ALLOCATE_MEMORY = 0x100;
    private static final int ISC_RET_MUTUAL_AUTH = 0x2;
    private static final int SECURITY_NATIVE_DREP = 0x10;
    private static final int SECBUFFER_TOKEN = 2;
    /** CredHandle and CtxtHandle: two ULONG_PTRs. */
    private static final long HANDLE = 16;
    /** SecBuffer: ULONG cbBuffer, ULONG BufferType, void* pvBuffer. */
    private static final long SEC_BUFFER = 16;
    /** SecBufferDesc: ULONG ulVersion, ULONG cBuffers, SecBuffer* pBuffers. */
    private static final long SEC_BUFFER_DESC = 16;

    private Sspi() {
    }

    static boolean available() {
        return Native.AVAILABLE;
    }

    /** A context for {@code target}, an SPN such as {@code MSSQLSvc/db.example:1433}. */
    static Gssapi.Context initiate(String target) {
        if (!available()) {
            throw new IllegalStateException("Kerberos needs SSPI (secur32.dll) on 64-bit Windows");
        }
        return new Context(target);
    }

    private static final class Context implements Gssapi.Context {

        private final Arena arena = Arena.ofShared();
        private final String target;
        private final MemorySegment wideTarget;
        private final MemorySegment credentials;
        private final MemorySegment context;
        private boolean started;
        private boolean complete;

        private Context(String target) {
            this.target = target;
            byte[] utf16 = (target + "\0").getBytes(StandardCharsets.UTF_16LE); // seclume-allow: a service name, not a secret
            wideTarget = arena.allocate(utf16.length);
            MemorySegment.copy(utf16, 0, wideTarget, JAVA_BYTE, 0, utf16.length);
            byte[] kerberos = "Kerberos\0".getBytes(StandardCharsets.UTF_16LE); // seclume-allow: the package's name
            MemorySegment packageName = arena.allocate(kerberos.length);
            MemorySegment.copy(kerberos, 0, packageName, JAVA_BYTE, 0, kerberos.length);
            credentials = arena.allocate(HANDLE);
            context = arena.allocate(HANDLE);
            MemorySegment expiry = arena.allocate(8);
            // No principal, no auth data: the logon session's own credentials.
            int status = (int) Native.call(Native.ACQUIRE_CREDENTIALS, NULL, packageName,
                    SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, credentials, expiry);
            if (status != SEC_E_OK) {
                arena.close();
                throw new IllegalStateException("Windows has no Kerberos credentials for this "
                        + "process (" + describe(status) + ") - log on to the domain, or start "
                        + "the application with runas /netonly");
            }
        }

        @Override
        public byte[] step(MemorySegment serverToken, long offset, int length) {
            try (Arena call = Arena.ofConfined()) {
                MemorySegment input = NULL;
                if (serverToken != null) {
                    MemorySegment buffer = call.allocate(SEC_BUFFER);
                    buffer.set(JAVA_INT, 0, length);
                    buffer.set(JAVA_INT, 4, SECBUFFER_TOKEN);
                    buffer.set(ADDRESS, 8, serverToken.asSlice(offset, length));
                    input = call.allocate(SEC_BUFFER_DESC);
                    input.set(JAVA_INT, 0, 0);
                    input.set(JAVA_INT, 4, 1);
                    input.set(ADDRESS, 8, buffer);
                }
                MemorySegment outBuffer = call.allocate(SEC_BUFFER);
                outBuffer.set(JAVA_INT, 4, SECBUFFER_TOKEN);
                MemorySegment output = call.allocate(SEC_BUFFER_DESC);
                output.set(JAVA_INT, 4, 1);
                output.set(ADDRESS, 8, outBuffer);
                MemorySegment attributes = call.allocate(JAVA_INT);
                MemorySegment expiry = call.allocate(8);
                int status = (int) Native.call(Native.INITIALIZE_CONTEXT, credentials,
                        started ? context : NULL, wideTarget,
                        ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP,
                        input, 0, context, output, attributes, expiry);
                started = true;
                int size = outBuffer.get(JAVA_INT, 0);
                MemorySegment token = outBuffer.get(ADDRESS, 8);
                byte[] bytes = new byte[size]; // seclume-allow: a Kerberos token, protocol data and not the key
                try {
                    if (size > 0 && !token.equals(NULL)) {
                        MemorySegment.copy(token.reinterpret(size), JAVA_BYTE, 0, bytes, 0, size);
                    }
                } finally {
                    if (!token.equals(NULL)) {
                        Native.call(Native.FREE_CONTEXT_BUFFER, token);
                    }
                }
                if (status == SEC_E_OK) {
                    if ((attributes.get(JAVA_INT, 0) & ISC_RET_MUTUAL_AUTH) == 0) {
                        throw new IllegalStateException("the Kerberos exchange with " + target
                                + " ended without the server proving who it is");
                    }
                    complete = true;
                } else if (status != SEC_I_CONTINUE_NEEDED) {
                    throw new IllegalStateException("the Kerberos exchange with " + target
                            + " failed - SSPI says " + describe(status));
                }
                return bytes;
            }
        }

        @Override
        public boolean complete() {
            return complete;
        }

        @Override
        public void close() {
            try {
                if (started) {
                    Native.call(Native.DELETE_CONTEXT, context);
                }
                Native.call(Native.FREE_CREDENTIALS, credentials);
            } finally {
                arena.close();
            }
        }
    }

    /** The status codes a Kerberos login meets, by name - SSPI has no message call of its own. */
    static String describe(int status) {
        String name = switch (status) {
            case 0x8009030E -> "SEC_E_NO_CREDENTIALS: no Kerberos credentials in this logon session";
            case 0x80090303 -> "SEC_E_TARGET_UNKNOWN: the KDC does not know that service "
                    + "principal (SPN)";
            case 0x80090311 -> "SEC_E_NO_AUTHENTICATING_AUTHORITY: no KDC could be reached for "
                    + "the realm";
            case 0x8009030C -> "SEC_E_LOGON_DENIED: the logon was refused";
            case 0x80090322 -> "SEC_E_WRONG_PRINCIPAL: the server is not the principal asked for";
            case 0x80090324 -> "SEC_E_TIME_SKEW: the clocks of client and KDC differ too much";
            case 0x80090308 -> "SEC_E_INVALID_TOKEN: the server's token was not understood";
            case 0x8009030F -> "SEC_E_MESSAGE_ALTERED: a token was changed on the way";
            case 0x80090304 -> "SEC_E_INTERNAL_ERROR";
            case 0x80090305 -> "SEC_E_SECPKG_NOT_FOUND: no Kerberos package";
            default -> null;
        };
        String code = "0x" + Integer.toHexString(status);
        return name == null ? code : name + " (" + code + ")";
    }

    /** The SSPI downcalls, loaded only on Windows. */
    private static final class Native {

        static final boolean AVAILABLE;
        static final MethodHandle ACQUIRE_CREDENTIALS;
        static final MethodHandle INITIALIZE_CONTEXT;
        static final MethodHandle FREE_CONTEXT_BUFFER;
        static final MethodHandle DELETE_CONTEXT;
        static final MethodHandle FREE_CREDENTIALS;

        /** Set in the static initialiser before the first bind, where the library is. */
        private static SymbolLookup lookup;

        static {
            MethodHandle[] handles = new MethodHandle[5];
            boolean available = false;
            if (Platform.isWindows() && ValueLayout.ADDRESS.byteSize() == 8) {
                try {
                    lookup = SymbolLookup.libraryLookup("secur32.dll", Arena.global());
                    handles[0] = bind("AcquireCredentialsHandleW", JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS);
                    handles[1] = bind("InitializeSecurityContextW", JAVA_INT, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS);
                    handles[2] = bind("FreeContextBuffer", JAVA_INT, ADDRESS);
                    handles[3] = bind("DeleteSecurityContext", JAVA_INT, ADDRESS);
                    handles[4] = bind("FreeCredentialsHandle", JAVA_INT, ADDRESS);
                    available = true;
                } catch (Throwable absent) {
                    available = false;
                }
            }
            AVAILABLE = available;
            ACQUIRE_CREDENTIALS = handles[0];
            INITIALIZE_CONTEXT = handles[1];
            FREE_CONTEXT_BUFFER = handles[2];
            DELETE_CONTEXT = handles[3];
            FREE_CREDENTIALS = handles[4];
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
                throw new IllegalStateException("SSPI downcall failed", e);
            }
        }
    }
}
