package space.seclume.tls;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
// seclume-allow: hashes the public transcript, never the key - see sign below
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
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
 * <p><b>Not covered:</b> the intermediate certificates - only the leaf is
 * sent, which is enough when the server's trust store has the issuing CA; a
 * renewed certificate has a new thumbprint and needs the setting changed; and
 * RSA keys, which are refused as {@link P256ClientIdentity} refuses them.
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
                    requireP256(der);
                    this.chain = List.of(der);

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
                    int ignored = (int) n.freeCertificate.invokeExact(context);
                }
            } finally {
                int ignored = (int) n.closeStore.invokeExact(store, 0);
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
        return HandshakeSignature.ECDSA_SECP256R1_SHA256;
    }

    /**
     * Asks Windows for a signature over the hash of the content.
     *
     * <p>NCrypt answers ECDSA with the raw {@code r || s}, 64 bytes, where TLS
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
            byte[] digest = sha256(content);
            MemorySegment hash = arena.allocate(digest.length);
            MemorySegment.copy(digest, 0, hash, JAVA_BYTE, 0, digest.length);
            MemorySegment signature = arena.allocate(64);
            MemorySegment written = arena.allocate(JAVA_INT);
            int status = (int) n.signHash.invokeExact(key, MemorySegment.NULL, hash,
                    digest.length, signature, 64, written, NCRYPT_SILENT_FLAG);
            if (status != 0) {
                throw new IllegalStateException("Windows refused to sign with the client "
                        + "certificate's key: NCrypt status 0x" + Integer.toHexString(status));
            }
            return der(signature.toArray(JAVA_BYTE));
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
                int ignored = (int) Native.get().freeObject.invokeExact(key);
            } catch (Throwable impossible) {
                throw new IllegalStateException(impossible);
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    /** {@code r || s} into {@code SEQUENCE { INTEGER r, INTEGER s }}. */
    static byte[] der(byte[] raw) {
        byte[] r = integer(raw, 0);
        byte[] s = integer(raw, 32);
        ByteArrayOutputStream out = new ByteArrayOutputStream(72);
        out.write(0x30);
        out.write(r.length + s.length);
        out.writeBytes(r);
        out.writeBytes(s);
        return out.toByteArray();
    }

    /** One 32-byte half as a DER INTEGER: leading zeros dropped, a zero added if the top bit is set. */
    private static byte[] integer(byte[] raw, int from) {
        int start = from;
        while (start < from + 31 && raw[start] == 0) {
            start++;
        }
        int length = from + 32 - start;
        boolean pad = (raw[start] & 0x80) != 0;
        byte[] out = new byte[2 + (pad ? 1 : 0) + length];
        out[0] = 0x02;
        out[1] = (byte) (length + (pad ? 1 : 0));
        System.arraycopy(raw, start, out, pad ? 3 : 2, length);
        return out;
    }

    private static void requireP256(byte[] der) {
        try (InputStream in = new java.io.ByteArrayInputStream(der)) {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
            if (!(certificate.getPublicKey() instanceof ECPublicKey ec)
                    || ec.getParams().getCurve().getField().getFieldSize() != 256) {
                throw new IllegalArgumentException("the certificate holds a "
                        + certificate.getPublicKey().getAlgorithm() + " key; seclume signs "
                        + "client certificates with P-256 only");
            }
        } catch (CertificateException | java.io.IOException e) {
            throw new IllegalArgumentException("the certificate in the store cannot be read", e);
        }
    }

    private static byte[] sha256(byte[] content) {
        try {
            // seclume-allow: public transcript data, never the key
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("a JVM without SHA-256", impossible);
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
        }

        static synchronized Native get() {
            if (instance == null) {
                instance = new Native();
            }
            return instance;
        }
    }
}
