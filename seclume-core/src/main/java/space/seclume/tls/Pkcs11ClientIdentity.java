package space.seclume.tls;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * A client identity whose key lives in a PKCS#11 token - a smart card, an HSM,
 * SoftHSM, or a TPM 2.0 through {@code tpm2-pkcs11} - on Linux and the other
 * systems whose {@code long} is 64 bits.
 *
 * <p>The same idea as {@link WindowsStoreClientIdentity}: the key is never in
 * this process. The token is asked for a signature ({@code C_Sign} with
 * {@code CKM_ECDSA} over the hash) and gives one; nothing here could ask it
 * for the key, and a key generated on the token with {@code CKA_EXTRACTABLE}
 * false would not be given anyway. The one secret this side holds is the
 * token's PIN, for the moment of {@code C_Login}: read from its provider into
 * native memory, written to the token, wiped.
 *
 * <pre>
 * clientCertPkcs11=/usr/lib64/pkcs11/libsofthsm2.so   the token's module
 * clientCertPkcs11Token=app                            the token's label (default: the first)
 * clientCertPkcs11Key=client                           the label of key and certificate
 * clientCertPin-provider=file                          where the PIN comes from, if
 * clientCertPin-path=/run/secrets/token-pin            the token wants one
 * clientCert=/etc/tls/chain.pem                        optional: the chain from a file
 *                                                      instead of the token's certificate
 * </pre>
 *
 * <p>The certificate is the token's certificate object with the key's label,
 * unless {@code clientCert} names a chain - which is also how intermediate
 * certificates get sent. P-256 and P-384 keys; RSA is refused, as everywhere
 * in this stack.
 *
 * <p><b>Windows</b> is not served here: its {@code CK_ULONG} is 32 bits and its
 * structures packed differently, and its certificate store already does this
 * - see {@link WindowsStoreClientIdentity}.
 */
public final class Pkcs11ClientIdentity implements ClientIdentity {

    private static final long CKR_OK = 0;
    private static final long CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191;
    private static final long CKR_USER_ALREADY_LOGGED_IN = 0x100;
    private static final long CKF_SERIAL_SESSION = 0x4;
    private static final long CKF_OS_LOCKING_OK = 0x2;
    private static final long CKU_USER = 1;
    private static final long CKA_CLASS = 0x0;
    private static final long CKA_LABEL = 0x3;
    private static final long CKA_VALUE = 0x11;
    private static final long CKO_CERTIFICATE = 1;
    private static final long CKO_PRIVATE_KEY = 3;
    private static final long CKM_ECDSA = 0x1041;
    /** CK_ATTRIBUTE and CK_MECHANISM: three 8-byte fields each. */
    private static final long TRIPLE = 24;

    private final Module module;
    private final long session;
    private final long key;
    private final List<byte[]> chain;
    private final int field;
    private boolean closed;

    /**
     * @param modulePath the token's PKCS#11 library
     * @param token      the token's label, or {@code null} for the first token
     * @param label      the label of the private key - and of the certificate
     * @param pin        where the PIN comes from, or {@code null} for none
     * @param chainFile  a PEM chain to send instead of the token's certificate, or null
     */
    public Pkcs11ClientIdentity(String modulePath, String token, String label,
                                SecretProvider pin, Path chainFile) {
        if (System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows")) {
            throw new IllegalArgumentException("clientCertPkcs11 is for Linux and the other "
                    + "64-bit-long systems; on Windows, name the certificate in the store "
                    + "(clientCertThumbprint or clientCertSubject) - the token's own CSP puts "
                    + "it there");
        }
        if (label == null || label.isBlank()) {
            throw new IllegalArgumentException("clientCertPkcs11Key names the key on the token "
                    + "by its label, and it is missing");
        }
        this.module = Module.of(modulePath);
        long opened = -1;
        try (Arena arena = Arena.ofConfined()) {
            long slot = slot(arena, token);
            MemorySegment handle = arena.allocate(JAVA_LONG);
            check("C_OpenSession", (long) module.openSession.invokeExact(slot,
                    CKF_SERIAL_SESSION, MemorySegment.NULL, MemorySegment.NULL, handle));
            opened = handle.get(JAVA_LONG, 0);
            if (pin != null) {
                try (SecretScope secret = SecretScope.fromProvider(pin)) {
                    long rv = (long) module.login.invokeExact(opened, CKU_USER,
                            secret.secret(), (long) secret.length());
                    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
                        throw failed("C_Login", rv);
                    }
                }
            }
            long found = find(arena, opened, CKO_PRIVATE_KEY, label);
            if (found == 0) {
                throw new IllegalArgumentException("no private key labelled '" + label
                        + "' on the token" + (pin == null ? " - it may need a PIN "
                        + "(clientCertPin-provider)" : ""));
            }
            this.key = found;
            if (chainFile != null) {
                this.chain = EcClientIdentity.parseChain(
                        java.nio.file.Files.readAllBytes(chainFile), chainFile); // seclume-allow: a certificate chain, public
            } else {
                long certificate = find(arena, opened, CKO_CERTIFICATE, label);
                if (certificate == 0) {
                    throw new IllegalArgumentException("no certificate labelled '" + label
                            + "' on the token - put it there, or name a chain with clientCert");
                }
                this.chain = List.of(value(arena, opened, certificate));
            }
            this.field = field(chain.getFirst());
            this.session = opened;
        } catch (RuntimeException | Error failure) {
            closeQuietly(opened);
            throw failure;
        } catch (java.io.IOException unreadable) {
            closeQuietly(opened);
            throw new IllegalArgumentException("the client certificate chain " + chainFile
                    + " cannot be read", unreadable);
        } catch (Throwable impossible) {
            closeQuietly(opened);
            throw new IllegalStateException(impossible);
        }
    }

    @Override
    public List<byte[]> chain() {
        return chain;
    }

    @Override
    public int signatureScheme() {
        return field == 48 ? HandshakeSignature.ECDSA_SECP384R1_SHA384
                : HandshakeSignature.ECDSA_SECP256R1_SHA256;
    }

    /**
     * The token signs the hash; {@code CKM_ECDSA} answers {@code r || s},
     * which TLS wants as DER.
     */
    @Override
    public synchronized byte[] sign(byte[] content) {
        if (closed) {
            throw new IllegalStateException("this client identity is closed");
        }
        byte[] digest = EcClientIdentity.digest(content,
                space.seclume.crypto.EcdsaSigner.Curve.ofField(field));
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment mechanism = arena.allocate(TRIPLE);
            mechanism.set(JAVA_LONG, 0, CKM_ECDSA);
            check("C_SignInit", (long) module.signInit.invokeExact(session, mechanism, key));
            MemorySegment data = arena.allocate(digest.length);
            MemorySegment.copy(digest, 0, data, JAVA_BYTE, 0, digest.length);
            MemorySegment signature = arena.allocate(2L * field);
            MemorySegment length = arena.allocate(JAVA_LONG);
            length.set(JAVA_LONG, 0, 2L * field);
            check("C_Sign", (long) module.sign.invokeExact(session, data,
                    (long) digest.length, signature, length));
            byte[] raw = signature.asSlice(0, length.get(JAVA_LONG, 0)).toArray(JAVA_BYTE);
            return space.seclume.crypto.EcdsaSigner.der(raw, field);
        } catch (RuntimeException | Error failure) {
            throw failure;
        } catch (Throwable impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        closeQuietly(session);
    }

    private void closeQuietly(long opened) {
        if (opened < 0) {
            return;
        }
        try {
            long _ = (long) module.logout.invokeExact(opened);
            long _ = (long) module.closeSession.invokeExact(opened);
        } catch (Throwable ignored) {
            // the session ends with the process at the latest
        }
    }

    // ---------------------------------------------------------------- helpers

    /** The slot of the token with that label, or of the first token. */
    private long slot(Arena arena, String token) throws Throwable {
        MemorySegment count = arena.allocate(JAVA_LONG);
        check("C_GetSlotList", (long) module.slotList.invokeExact((byte) 1, MemorySegment.NULL,
                count));
        long n = count.get(JAVA_LONG, 0);
        if (n == 0) {
            throw new IllegalArgumentException("the PKCS#11 module has no token");
        }
        MemorySegment slots = arena.allocate(JAVA_LONG, n);
        check("C_GetSlotList", (long) module.slotList.invokeExact((byte) 1, slots, count));
        StringBuilder seen = new StringBuilder();
        for (long i = 0; i < count.get(JAVA_LONG, 0); i++) {
            long slot = slots.getAtIndex(JAVA_LONG, i);
            MemorySegment info = arena.allocate(512);
            if ((long) module.tokenInfo.invokeExact(slot, info) != CKR_OK) {
                continue;
            }
            String label = new String(info.asSlice(0, 32).toArray(JAVA_BYTE),
                    StandardCharsets.UTF_8).strip();
            if (token == null || token.isBlank() || token.strip().equals(label)) {
                return slot;
            }
            seen.append(seen.isEmpty() ? "" : ", ").append('\'').append(label).append('\'');
        }
        throw new IllegalArgumentException("no token labelled '" + token + "' - the module "
                + "has " + seen);
    }

    /** The first object of {@code type} with {@code label}, or 0. */
    private long find(Arena arena, long session, long type, String label) throws Throwable {
        byte[] name = label.getBytes(StandardCharsets.UTF_8);
        MemorySegment classValue = arena.allocate(JAVA_LONG);
        classValue.set(JAVA_LONG, 0, type);
        MemorySegment labelValue = arena.allocate(Math.max(1, name.length));
        MemorySegment.copy(name, 0, labelValue, JAVA_BYTE, 0, name.length);
        MemorySegment template = arena.allocate(2 * TRIPLE);
        template.set(JAVA_LONG, 0, CKA_CLASS);
        template.set(ADDRESS, 8, classValue);
        template.set(JAVA_LONG, 16, 8);
        template.set(JAVA_LONG, TRIPLE, CKA_LABEL);
        template.set(ADDRESS, TRIPLE + 8, labelValue);
        template.set(JAVA_LONG, TRIPLE + 16, name.length);
        check("C_FindObjectsInit", (long) module.findInit.invokeExact(session, template, 2L));
        try {
            MemorySegment handle = arena.allocate(JAVA_LONG);
            MemorySegment found = arena.allocate(JAVA_LONG);
            check("C_FindObjects", (long) module.find.invokeExact(session, handle, 1L, found));
            return found.get(JAVA_LONG, 0) == 0 ? 0 : handle.get(JAVA_LONG, 0);
        } finally {
            long _ = (long) module.findFinal.invokeExact(session);
        }
    }

    /** {@code CKA_VALUE} of a certificate object - its DER. */
    private byte[] value(Arena arena, long session, long object) throws Throwable {
        MemorySegment template = arena.allocate(TRIPLE);
        template.set(JAVA_LONG, 0, CKA_VALUE);
        template.set(ADDRESS, 8, MemorySegment.NULL);
        check("C_GetAttributeValue", (long) module.attribute.invokeExact(session, object,
                template, 1L));
        long length = template.get(JAVA_LONG, 16);
        MemorySegment value = arena.allocate(Math.max(1, length));
        template.set(ADDRESS, 8, value);
        check("C_GetAttributeValue", (long) module.attribute.invokeExact(session, object,
                template, 1L));
        return value.asSlice(0, template.get(JAVA_LONG, 16)).toArray(JAVA_BYTE);
    }

    private static int field(byte[] der) {
        try (InputStream in = new java.io.ByteArrayInputStream(der)) {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
            int bits = certificate.getPublicKey() instanceof ECPublicKey ec
                    ? ec.getParams().getCurve().getField().getFieldSize() : 0;
            if (bits != 256 && bits != 384) {
                throw new IllegalArgumentException("the certificate holds a "
                        + certificate.getPublicKey().getAlgorithm() + " key; seclume signs "
                        + "client certificates with P-256 or P-384 only");
            }
            return bits / 8;
        } catch (CertificateException | java.io.IOException e) {
            throw new IllegalArgumentException("the client certificate cannot be read", e);
        }
    }

    private static void check(String call, long rv) {
        if (rv != CKR_OK) {
            throw failed(call, rv);
        }
    }

    private static IllegalStateException failed(String call, long rv) {
        String meaning = switch ((int) rv) {
            case 0xa0 -> " (CKR_PIN_INCORRECT)";
            case 0xa4 -> " (CKR_PIN_LOCKED)";
            case 0x101 -> " (CKR_USER_NOT_LOGGED_IN - the token wants a PIN)";
            case 0xe0 -> " (CKR_TOKEN_NOT_PRESENT)";
            case 0x63 -> " (CKR_KEY_TYPE_INCONSISTENT - not an EC key)";
            default -> "";
        };
        return new IllegalStateException(call + " failed: CKR 0x" + Long.toHexString(rv)
                + meaning);
    }

    /** A loaded module and its function list - once per library, initialised once. */
    private static final class Module {

        private static final Map<String, Module> LOADED = new ConcurrentHashMap<>();

        final MethodHandle slotList;
        final MethodHandle tokenInfo;
        final MethodHandle openSession;
        final MethodHandle closeSession;
        final MethodHandle login;
        final MethodHandle logout;
        final MethodHandle attribute;
        final MethodHandle findInit;
        final MethodHandle find;
        final MethodHandle findFinal;
        final MethodHandle signInit;
        final MethodHandle sign;

        static Module of(String path) {
            if (path == null || path.isBlank()) {
                throw new IllegalArgumentException("clientCertPkcs11 names the token's PKCS#11 "
                        + "module, and it is empty");
            }
            return LOADED.computeIfAbsent(Path.of(path).toAbsolutePath().normalize().toString(),
                    Module::new);
        }

        private Module(String path) {
            Linker linker = Linker.nativeLinker();
            SymbolLookup library;
            try {
                library = SymbolLookup.libraryLookup(Path.of(path), Arena.global());
            } catch (IllegalArgumentException missing) {
                throw new IllegalArgumentException("the PKCS#11 module " + path
                        + " cannot be loaded", missing);
            }
            try (Arena arena = Arena.ofConfined()) {
                MethodHandle getList = linker.downcallHandle(
                        library.find("C_GetFunctionList").orElseThrow(() ->
                                new IllegalArgumentException(path + " is no PKCS#11 module: "
                                        + "it has no C_GetFunctionList")),
                        FunctionDescriptor.of(JAVA_LONG, ADDRESS));
                MemorySegment holder = arena.allocate(ADDRESS);
                check("C_GetFunctionList", (long) getList.invokeExact(holder));
                // CK_FUNCTION_LIST: a CK_VERSION (two bytes, padded to eight),
                // then the functions in the order of the standard.
                MemorySegment list = holder.get(ADDRESS, 0).reinterpret(8 + 8 * 70);
                MethodHandle initialize = function(linker, list, 0,
                        FunctionDescriptor.of(JAVA_LONG, ADDRESS));
                slotList = function(linker, list, 4,
                        FunctionDescriptor.of(JAVA_LONG, JAVA_BYTE, ADDRESS, ADDRESS));
                tokenInfo = function(linker, list, 6,
                        FunctionDescriptor.of(JAVA_LONG, JAVA_LONG, ADDRESS));
                openSession = function(linker, list, 12, FunctionDescriptor.of(JAVA_LONG,
                        JAVA_LONG, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS));
                closeSession = function(linker, list, 13,
                        FunctionDescriptor.of(JAVA_LONG, JAVA_LONG));
                login = function(linker, list, 18, FunctionDescriptor.of(JAVA_LONG, JAVA_LONG,
                        JAVA_LONG, ADDRESS, JAVA_LONG));
                logout = function(linker, list, 19,
                        FunctionDescriptor.of(JAVA_LONG, JAVA_LONG));
                attribute = function(linker, list, 24, FunctionDescriptor.of(JAVA_LONG,
                        JAVA_LONG, JAVA_LONG, ADDRESS, JAVA_LONG));
                findInit = function(linker, list, 26, FunctionDescriptor.of(JAVA_LONG,
                        JAVA_LONG, ADDRESS, JAVA_LONG));
                find = function(linker, list, 27, FunctionDescriptor.of(JAVA_LONG, JAVA_LONG,
                        ADDRESS, JAVA_LONG, ADDRESS));
                findFinal = function(linker, list, 28,
                        FunctionDescriptor.of(JAVA_LONG, JAVA_LONG));
                signInit = function(linker, list, 42, FunctionDescriptor.of(JAVA_LONG,
                        JAVA_LONG, ADDRESS, JAVA_LONG));
                sign = function(linker, list, 43, FunctionDescriptor.of(JAVA_LONG, JAVA_LONG,
                        ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
                // CK_C_INITIALIZE_ARGS: four mutex functions (none), the flags
                // - the system's own locking - and a reserved pointer.
                MemorySegment arguments = arena.allocate(48);
                arguments.set(JAVA_LONG, 32, CKF_OS_LOCKING_OK);
                long rv = (long) initialize.invokeExact(arguments);
                if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                    throw failed("C_Initialize", rv);
                }
            } catch (RuntimeException | Error failure) {
                throw failure;
            } catch (Throwable impossible) {
                throw new IllegalStateException(impossible);
            }
        }

        private static MethodHandle function(Linker linker, MemorySegment list, int index,
                                             FunctionDescriptor descriptor) {
            MemorySegment address = list.get(ADDRESS, 8 + 8L * index);
            if (address.address() == 0) {
                throw new IllegalArgumentException("the PKCS#11 module has no function number "
                        + index);
            }
            return linker.downcallHandle(address, descriptor);
        }
    }
}
