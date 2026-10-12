package space.seclume.tls;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat; // seclume-allow: a thumbprint - the hash of a public certificate
import java.util.List;
import java.util.Locale;

/**
 * A client identity whose private key never leaves Windows - and, on a
 * machine with a TPM, never leaves the chip.
 *
 * <p>{@link P256ClientIdentity} already keeps the key off the Java heap: it is
 * read from its provider into native memory and handed to the operating
 * system's crypto. That is the best a key that lives in a <i>file</i> can
 * have, and it still means the key existed in this process for a moment. Here
 * it never does. The certificate is looked up in the Windows certificate store
 * by its thumbprint, and the key that belongs to it is used through
 * <b>NCrypt</b> by handle: this class asks for a signature and gets one, and
 * there is no call in it - and none in Windows it could make - that returns
 * the key.
 *
 * <p>Where the key lives is Windows' decision, taken when the certificate was
 * enrolled:
 *
 * <ul>
 *   <li><b>Microsoft Software Key Storage Provider</b> - protected by the
 *       account, and with an export policy of <i>non-exportable</i> it cannot
 *       be read out even by the account that owns it;</li>
 *   <li><b>Microsoft Platform Crypto Provider</b> - generated inside the TPM
 *       and never outside it. Stealing the disk, the memory or the process
 *       yields nothing that signs.</li>
 * </ul>
 *
 * <p>The code is the same for both: {@code ClientIdentity} was an interface
 * that signs rather than a key from the start, which is exactly what makes
 * this possible without touching the handshake.
 *
 * <pre>
 * clientCertThumbprint=3F2A...   the SHA-1 thumbprint, as certmgr shows it
 * clientCertStore=CurrentUser    or LocalMachine; the "My" store either way
 * </pre>
 *
 * <p><b>The chain</b> is what Windows builds for the certificate - leaf, then
 * the intermediate certificates it finds in the stores - without a
 * self-signed root at the end, which the server has to have anyway. A
 * renewed certificate has a new thumbprint: {@code clientCertSubject} names
 * it by subject instead, and the newest valid one is used and looked for
 * again every minute - see {@link #newestBySubject}.
 *
 * <p><b>Not covered:</b> RSA keys, which are refused as
 * {@link P256ClientIdentity} refuses them.
 */
public final class WindowsStoreClientIdentity implements ClientIdentity {

    private static final int X509_AND_PKCS7 = 0x0001_0001;
    private static final int CERT_STORE_PROV_SYSTEM_W = 10;
    private static final int CURRENT_USER = 0x0001_0000;
    private static final int LOCAL_MACHINE = 0x0002_0000;
    private static final int OPEN_EXISTING_READ_ONLY = 0x0000_4000 | 0x0000_8000;
    private static final int CERT_FIND_HASH = 0x0001_0000;
    private static final int ONLY_NCRYPT_SILENT = 0x0004_0000 | 0x40;
    private static final int NCRYPT_SILENT_FLAG = 0x40;

    private final List<byte[]> chain;
    /** Bytes per coordinate: 32 for P-256, 48 for P-384 - the certificate's curve. */
    private final int field;
    private final MemorySegment key;
    private final boolean freeKey;
    private boolean closed;

    /**
     * @param thumbprint the certificate's SHA-1 thumbprint, hex, spaces allowed
     * @param machine    {@code true} for the machine's store, {@code false}
     *                   for the account's
     */
    public WindowsStoreClientIdentity(String thumbprint, boolean machine) {
        if (!System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows")) {
            throw new IllegalArgumentException("clientCertThumbprint names a certificate in the "
                    + "Windows certificate store, and this is not Windows");
        }
        byte[] hash = parse(thumbprint);
        Native n = Native.get();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment store = (MemorySegment) n.openStore.invokeExact(
                    MemorySegment.ofAddress(CERT_STORE_PROV_SYSTEM_W), 0, MemorySegment.NULL,
                    (machine ? LOCAL_MACHINE : CURRENT_USER) | OPEN_EXISTING_READ_ONLY,
                    wide(arena, "MY"));
            if (store.address() == 0) {
                throw new IllegalArgumentException("the " + where(machine)
                        + " certificate store could not be opened");
            }
            try {
                MemorySegment blob = arena.allocate(16);
                MemorySegment bytes = arena.allocate(hash.length);
                MemorySegment.copy(hash, 0, bytes, JAVA_BYTE, 0, hash.length);
                blob.set(JAVA_INT, 0, hash.length);
                blob.set(ADDRESS, 8, bytes);
                MemorySegment context = (MemorySegment) n.findCertificate.invokeExact(store,
                        X509_AND_PKCS7, 0, CERT_FIND_HASH, blob, MemorySegment.NULL);
                if (context.address() == 0) {
                    throw new IllegalArgumentException("no certificate with the thumbprint "
                            + HexFormat.of().withUpperCase().formatHex(hash) + " in the " // seclume-allow: a thumbprint - the hash of a public certificate
                            + where(machine) + " store");
                }
                try {
                    MemorySegment view = context.reinterpret(40);
                    int length = view.get(JAVA_INT, 16);
                    byte[] der = view.get(ADDRESS, 8).reinterpret(length)
                            .toArray(JAVA_BYTE);
                    this.field = field(der);
                    this.chain = withIssuers(n, context, store, der, machine);

                    MemorySegment handle = arena.allocate(JAVA_LONG);
                    MemorySegment keySpec = arena.allocate(JAVA_INT);
                    MemorySegment callerFrees = arena.allocate(JAVA_INT);
                    int ok = (int) n.acquireKey.invokeExact(context, ONLY_NCRYPT_SILENT,
                            MemorySegment.NULL, handle, keySpec, callerFrees);
                    if (ok == 0) {
                        throw new IllegalArgumentException("the certificate "
                                + HexFormat.of().withUpperCase().formatHex(hash) + " has no " // seclume-allow: a thumbprint - the hash of a public certificate
                                + "private key this account may use through CNG");
                    }
                    this.key = MemorySegment.ofAddress(handle.get(JAVA_LONG, 0));
                    this.freeKey = callerFrees.get(JAVA_INT, 0) != 0;
                } finally {
                    int _ = (int) n.freeCertificate.invokeExact(context);
                }
            } finally {
                int _ = (int) n.closeStore.invokeExact(store, 0);
            }
        } catch (RuntimeException | Error failure) {
            throw failure;
        } catch (Throwable impossible) {
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
     * Asks Windows for a signature over the hash of the content.
     *
     * <p>NCrypt answers ECDSA with the raw {@code r || s}, 64 or 96 bytes, where TLS
     * wants the DER structure, so it is converted here. Nothing about this is
     * secret: a signature is meant to be seen.
     */
    @Override
    public synchronized byte[] sign(byte[] content) {
        if (closed) {
            throw new IllegalStateException("this client identity is closed");
        }
        Native n = Native.get();
        try (Arena arena = Arena.ofConfined()) {
            byte[] digest = EcClientIdentity.digest(content,
                    space.seclume.crypto.EcdsaSigner.Curve.ofField(field));
            MemorySegment hash = arena.allocate(digest.length);
            MemorySegment.copy(digest, 0, hash, JAVA_BYTE, 0, digest.length);
            MemorySegment signature = arena.allocate(2L * field);
            MemorySegment written = arena.allocate(JAVA_INT);
            int status = (int) n.signHash.invokeExact(key, MemorySegment.NULL, hash,
                    digest.length, signature, 2 * field, written, NCRYPT_SILENT_FLAG);
            if (status != 0) {
                throw new IllegalStateException("Windows refused to sign with the client "
                        + "certificate's key: NCrypt status 0x" + Integer.toHexString(status));
            }
            return space.seclume.crypto.EcdsaSigner.der(signature.toArray(JAVA_BYTE), field);
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
        if (freeKey) {
            try {
                int _ = (int) Native.get().freeObject.invokeExact(key);
            } catch (Throwable impossible) {
                throw new IllegalStateException(impossible);
            }
        }
    }

    /**
     * The certificate and the intermediate certificates Windows finds for
     * it, leaf first, without a self-signed root. Only the leaf when no chain
     * can be built - which is what was sent before.
     */
    private static List<byte[]> withIssuers(Native n, MemorySegment context, MemorySegment store,
                                            byte[] leaf, boolean machine) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            // CERT_CHAIN_PARA with no usage asked for: cbSize and zeroes.
            MemorySegment parameters = arena.allocate(32);
            parameters.set(JAVA_INT, 0, 32);
            MemorySegment built = arena.allocate(ADDRESS);
            MemorySegment engine = machine ? MemorySegment.ofAddress(1)  // HCCE_LOCAL_MACHINE
                    : MemorySegment.NULL;                                 // HCCE_CURRENT_USER
            int ok = (int) n.getChain.invokeExact(engine, context, MemorySegment.NULL, store,
                    parameters, 0, MemorySegment.NULL, built);
            if (ok == 0 || built.get(ADDRESS, 0).address() == 0) {
                return List.of(leaf);
            }
            MemorySegment chainContext = built.get(ADDRESS, 0).reinterpret(24);
            try {
                if (chainContext.get(JAVA_INT, 12) < 1) {                       // cChain
                    return List.of(leaf);
                }
                MemorySegment simple = chainContext.get(ADDRESS, 16).reinterpret(8)
                        .get(ADDRESS, 0).reinterpret(24);
                int count = simple.get(JAVA_INT, 12);                           // cElement
                MemorySegment elements = simple.get(ADDRESS, 16).reinterpret(8L * count);
                List<byte[]> ders = new ArrayList<>();
                for (int i = 0; i < count; i++) {
                    MemorySegment certificate = elements.get(ADDRESS, 8L * i).reinterpret(16)
                            .get(ADDRESS, 8).reinterpret(40);
                    int length = certificate.get(JAVA_INT, 16);
                    ders.add(certificate.get(ADDRESS, 8).reinterpret(length).toArray(JAVA_BYTE));
                }
                if (ders.isEmpty() || !Arrays.equals(ders.getFirst(), leaf)) {
                    return List.of(leaf);
                }
                if (ders.size() > 1 && selfSigned(ders.getLast())) {
                    ders.removeLast();
                }
                return List.copyOf(ders);
            } finally {
                n.freeChain.invokeExact(chainContext);
            }
        }
    }

    private static boolean selfSigned(byte[] der) {
        X509Certificate certificate = certificate(der);
        return certificate.getSubjectX500Principal().equals(
                certificate.getIssuerX500Principal());
    }

    private static X509Certificate certificate(byte[] der) {
        try (InputStream in = new java.io.ByteArrayInputStream(der)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
        } catch (CertificateException | java.io.IOException e) {
            throw new IllegalArgumentException("a certificate in the store cannot be read", e);
        }
    }

    /**
     * The thumbprint of the newest certificate in the store whose subject is
     * {@code subject} and which is valid now: the one that replaced the last
     * when a certificate was renewed.
     *
     * @param subject a whole subject ({@code CN=app1, O=Example}), or a common
     *                name alone ({@code app1}) - matched exactly, not as a part
     */
    public static String newestBySubject(String subject, boolean machine) {
        if (!System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows")) {
            throw new IllegalArgumentException("clientCertSubject names a certificate in the "
                    + "Windows certificate store, and this is not Windows");
        }
        String wanted = subject == null ? "" : subject.trim();
        if (wanted.isEmpty()) {
            throw new IllegalArgumentException("clientCertSubject is empty");
        }
        javax.security.auth.x500.X500Principal whole = wanted.contains("=")
                ? new javax.security.auth.x500.X500Principal(wanted) : null;
        Native n = Native.get();
        byte[] best = null;
        java.util.Date bestFrom = null;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment store = (MemorySegment) n.openStore.invokeExact(
                    MemorySegment.ofAddress(CERT_STORE_PROV_SYSTEM_W), 0, MemorySegment.NULL,
                    (machine ? LOCAL_MACHINE : CURRENT_USER) | OPEN_EXISTING_READ_ONLY,
                    wide(arena, "MY"));
            if (store.address() == 0) {
                throw new IllegalArgumentException("the " + where(machine)
                        + " certificate store could not be opened");
            }
            try {
                MemorySegment context = MemorySegment.NULL;
                while (true) {
                    context = (MemorySegment) n.enumCertificates.invokeExact(store, context);
                    if (context.address() == 0) {
                        break;
                    }
                    MemorySegment view = context.reinterpret(40);
                    byte[] der = view.get(ADDRESS, 8).reinterpret(view.get(JAVA_INT, 16))
                            .toArray(JAVA_BYTE);
                    X509Certificate one;
                    try {
                        one = certificate(der);
                        one.checkValidity();
                    } catch (IllegalArgumentException | CertificateException notNow) {
                        continue;
                    }
                    boolean matches = whole != null
                            ? whole.equals(one.getSubjectX500Principal())
                            : wanted.equalsIgnoreCase(commonName(one));
                    if (matches && (bestFrom == null || one.getNotBefore().after(bestFrom))) {
                        best = der;
                        bestFrom = one.getNotBefore();
                    }
                }
            } finally {
                int _ = (int) n.closeStore.invokeExact(store, 0);
            }
        } catch (RuntimeException | Error failure) {
            throw failure;
        } catch (Throwable impossible) {
            throw new IllegalStateException(impossible);
        }
        if (best == null) {
            throw new IllegalArgumentException("no certificate valid now with the subject '"
                    + wanted + "' in the " + where(machine) + " store");
        }
        // A thumbprint is what Windows calls the certificate's SHA-1: a name,
        // compared with the setting, never a protection.
        java.security.MessageDigest sha1; // seclume-allow: hashes a public certificate
        try {
            // nosemgrep: java.lang.security.audit.crypto.use-of-sha1.use-of-sha1
            sha1 = java.security.MessageDigest.getInstance("SHA-1"); // seclume-allow: a public certificate's thumbprint
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
        return HexFormat.of().withUpperCase().formatHex(sha1.digest(best)); // seclume-allow: a thumbprint - the hash of a public certificate
    }

    /** The first CN of the subject, unescaped as RFC 2253 writes it; empty when there is none. */
    static String commonName(X509Certificate certificate) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "(?:^|,)CN=((?:\\\\.|[^,])*)", java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(certificate.getSubjectX500Principal().getName(
                        javax.security.auth.x500.X500Principal.RFC2253));
        return m.find() ? m.group(1).replaceAll("\\\\(.)", "$1") : "";
    }

    // ---------------------------------------------------------------- helpers

    /** 32 or 48: the certificate's curve, P-256 or P-384; anything else refused. */
    private static int field(byte[] der) {
        try (InputStream in = new java.io.ByteArrayInputStream(der)) {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
            int bits = certificate.getPublicKey() instanceof ECPublicKey ec
                    ? ec.getParams().getCurve().getField().getFieldSize() : 0;
            if (bits != 256 && bits != 384) {
                throw new IllegalArgumentException("the certificate holds a "
                        + certificate.getPublicKey().getAlgorithm() + " key"
                        + (bits > 0 ? " on a " + bits + "-bit curve" : "")
                        + "; seclume signs client certificates with P-256 or P-384 only");
            }
            return bits / 8;
        } catch (CertificateException | java.io.IOException e) {
            throw new IllegalArgumentException("the certificate in the store cannot be read", e);
        }
    }

    private static byte[] parse(String thumbprint) {
        String hex = thumbprint == null ? "" : thumbprint.replaceAll("[\\s:\\u200e]", "");
        if (hex.length() != 40) {
            throw new IllegalArgumentException("clientCertThumbprint must be the 40 hex digits "
                    + "of a SHA-1 thumbprint, not '" + thumbprint + "'");
        }
        return HexFormat.of().parseHex(hex); // seclume-allow: a thumbprint - the hash of a public certificate
    }

    private static String where(boolean machine) {
        return machine ? "LocalMachine\\My" : "CurrentUser\\My";
    }

    private static MemorySegment wide(Arena arena, String text) {
        MemorySegment out = arena.allocate(2L * (text.length() + 1));
        for (int i = 0; i < text.length(); i++) {
            out.set(java.lang.foreign.ValueLayout.JAVA_CHAR_UNALIGNED, 2L * i, text.charAt(i));
        }
        return out;
    }

    /** The downcalls, bound on first use so that other platforms never look for them. */
    private static final class Native {

        private static Native instance;

        final MethodHandle openStore;
        final MethodHandle closeStore;
        final MethodHandle findCertificate;
        final MethodHandle freeCertificate;
        final MethodHandle acquireKey;
        final MethodHandle signHash;
        final MethodHandle freeObject;
        final MethodHandle getChain;
        final MethodHandle freeChain;
        final MethodHandle enumCertificates;

        private Native() {
            Linker linker = Linker.nativeLinker();
            SymbolLookup crypt32 = SymbolLookup.libraryLookup("crypt32.dll", Arena.global());
            SymbolLookup ncrypt = SymbolLookup.libraryLookup("ncrypt.dll", Arena.global());
            openStore = linker.downcallHandle(crypt32.find("CertOpenStore").orElseThrow(),
                    FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
            closeStore = linker.downcallHandle(crypt32.find("CertCloseStore").orElseThrow(),
                    FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
            findCertificate = linker.downcallHandle(
                    crypt32.find("CertFindCertificateInStore").orElseThrow(),
                    FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT,
                            ADDRESS, ADDRESS));
            freeCertificate = linker.downcallHandle(
                    crypt32.find("CertFreeCertificateContext").orElseThrow(),
                    FunctionDescriptor.of(JAVA_INT, ADDRESS));
            acquireKey = linker.downcallHandle(
                    crypt32.find("CryptAcquireCertificatePrivateKey").orElseThrow(),
                    FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, ADDRESS,
                            ADDRESS, ADDRESS));
            signHash = linker.downcallHandle(ncrypt.find("NCryptSignHash").orElseThrow(),
                    FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, JAVA_INT,
                            ADDRESS, JAVA_INT, ADDRESS, JAVA_INT));
            freeObject = linker.downcallHandle(ncrypt.find("NCryptFreeObject").orElseThrow(),
                    FunctionDescriptor.of(JAVA_INT, ADDRESS));
            getChain = linker.downcallHandle(
                    crypt32.find("CertGetCertificateChain").orElseThrow(),
                    FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS,
                            JAVA_INT, ADDRESS, ADDRESS));
            freeChain = linker.downcallHandle(
                    crypt32.find("CertFreeCertificateChain").orElseThrow(),
                    FunctionDescriptor.ofVoid(ADDRESS));
            enumCertificates = linker.downcallHandle(
                    crypt32.find("CertEnumCertificatesInStore").orElseThrow(),
                    FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS));
        }

        static synchronized Native get() {
            if (instance == null) {
                instance = new Native();
            }
            return instance;
        }
    }
}
