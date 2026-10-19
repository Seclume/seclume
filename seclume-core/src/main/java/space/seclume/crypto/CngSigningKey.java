package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.math.BigInteger; // seclume-allow: a public key's numbers
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

import space.seclume.internal.Base64Off;
import space.seclume.internal.Platform;
import space.seclume.secret.SecretScope;

/**
 * A private key in CNG, the Windows counterpart of {@link OpenSslSigningKey}:
 * imported into the software key storage provider as PKCS#8 from native
 * memory, signed with there, freed with {@code NCryptFreeObject}. The key is
 * an ephemeral one - no name, not persisted - and never leaves CNG again.
 *
 * <p>The input is what OpenSSL's decoder reads: PEM or DER, PKCS#8, SEC 1 or
 * PKCS#1. The two older shapes are wrapped into PKCS#8 here, in native memory
 * that is wiped afterwards. A SEC 1 key without its public point is fine: CNG
 * computes it as it imports - what SigV4a, whose key is only a scalar, needs.
 *
 * <p>RSA (PKCS#1 v1.5 and PSS) and ECDSA on P-256, P-384 and P-521. Not
 * Ed25519: CNG has no signature for it, and the decode says so.
 */
public final class CngSigningKey implements PrivateSigningKey {

    private static final int BCRYPT_PAD_PKCS1 = 0x2;
    private static final int BCRYPT_PAD_PSS = 0x8;
    /** {@code BCRYPT_RSAKEY_BLOB}: six ULONGs, then exponent and modulus, big-endian. */
    private static final int RSA_HEADER = 24;
    /** {@code BCRYPT_ECCKEY_BLOB}: magic and the size of one coordinate. */
    private static final int ECC_HEADER = 8;

    private static final byte[] RSA_OID = hex("2a864886f70d010101");
    private static final byte[] EC_OID = hex("2a8648ce3d0201");
    private static final byte[] ED25519_OID = hex("2b6570");

    private static final MethodHandle IMPORT;
    private static final MethodHandle EXPORT;
    private static final MethodHandle SIGN;
    private static final MethodHandle FREE;
    private static final long PROVIDER;

    static {
        MethodHandle importKey = null;
        MethodHandle exportKey = null;
        MethodHandle sign = null;
        MethodHandle free = null;
        long provider = 0;
        if (Platform.isWindows()) {
            try {
                Linker linker = Linker.nativeLinker();
                SymbolLookup ncrypt = SymbolLookup.libraryLookup("ncrypt.dll", Arena.global());
                var a = ValueLayout.ADDRESS;
                var i = ValueLayout.JAVA_INT;
                var l = ValueLayout.JAVA_LONG;
                MethodHandle open = linker.downcallHandle(
                        ncrypt.find("NCryptOpenStorageProvider").orElseThrow(),
                        FunctionDescriptor.of(i, a, a, i));
                // SECURITY_STATUS NCryptImportKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE,
                //     LPCWSTR blobType, NCryptBufferDesc*, NCRYPT_KEY_HANDLE*, PBYTE, DWORD, DWORD)
                importKey = linker.downcallHandle(ncrypt.find("NCryptImportKey").orElseThrow(),
                        FunctionDescriptor.of(i, l, l, a, a, a, a, i, i));
                // NCryptExportKey(key, exportKey, blobType, params, out, cbOut, *cbResult, flags)
                exportKey = linker.downcallHandle(ncrypt.find("NCryptExportKey").orElseThrow(),
                        FunctionDescriptor.of(i, l, l, a, a, a, i, a, i));
                // NCryptSignHash(key, padding, hash, cbHash, signature, cbSignature, *cbResult, flags)
                sign = linker.downcallHandle(ncrypt.find("NCryptSignHash").orElseThrow(),
                        FunctionDescriptor.of(i, l, a, a, i, a, i, a, i));
                free = linker.downcallHandle(ncrypt.find("NCryptFreeObject").orElseThrow(),
                        FunctionDescriptor.of(i, l));
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment handle = arena.allocate(ValueLayout.JAVA_LONG);
                    int status = (int) open.invokeExact(handle,
                            wide(arena, "Microsoft Software Key Storage Provider"), 0);
                    provider = status == 0 ? handle.get(ValueLayout.JAVA_LONG, 0) : 0;
                }
            } catch (Throwable unavailable) {
                provider = 0;
            }
        }
        IMPORT = importKey;
        EXPORT = exportKey;
        SIGN = sign;
        FREE = free;
        PROVIDER = provider;
    }

    private enum Kind { RSA, EC }

    private final Kind kind;
    private long key;

    private CngSigningKey(Kind kind, long key) {
        this.kind = kind;
        this.key = key;
    }

    /** Whether CNG's software key storage provider could be opened here: Windows. */
    public static boolean available() {
        return PROVIDER != 0;
    }

    /**
     * Imports a private key from {@code length} bytes of PEM or DER at the
     * start of {@code encoded}, which stays the caller's to wipe.
     */
    public static CngSigningKey decode(MemorySegment encoded, int length) {
        if (!available()) {
            throw new IllegalStateException("CNG is not available here - it is Windows'");
        }
        try (Arena arena = Arena.ofConfined();
             SecretScope der = SecretScope.in(arena, Math.max(length, 16));
             SecretScope pkcs8 = SecretScope.in(arena, Math.max(length, 16) + 64)) {
            MemorySegment source = encoded;
            int sourceLength = length;
            if (length > 0 && encoded.get(ValueLayout.JAVA_BYTE, 0) != 0x30) {
                der.length(pem(encoded, length, der.segment()));
                source = der.segment();
                sourceLength = der.length();
            }
            Kind kind = toPkcs8(source, sourceLength, pkcs8);
            MemorySegment handle = arena.allocate(ValueLayout.JAVA_LONG);
            int status = (int) IMPORT.invokeExact(PROVIDER, 0L, wide(arena, "PKCS8_PRIVATEKEY"),
                    MemorySegment.NULL, handle, pkcs8.segment(), pkcs8.length(), 0);
            if (status != 0) {
                throw new IllegalArgumentException("CNG did not take the private key: "
                        + "SECURITY_STATUS 0x" + Integer.toHexString(status));
            }
            return new CngSigningKey(kind, handle.get(ValueLayout.JAVA_LONG, 0));
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("the CNG import failed", t);
        }
    }

    /** The base64 between {@code -----BEGIN} and {@code -----END}, decoded into {@code out}. */
    private static int pem(MemorySegment source, int length, MemorySegment out) {
        long body = -1;
        long end = -1;
        for (long i = 0; i + 5 <= length; i++) {
            if (startsWith(source, i, "-----BEGIN") && body < 0) {
                for (long j = i + 10; j < length; j++) {
                    if (source.get(ValueLayout.JAVA_BYTE, j) == '\n') {
                        body = j + 1;
                        break;
                    }
                }
            } else if (startsWith(source, i, "-----END") && body >= 0) {
                end = i;
                break;
            }
        }
        if (body < 0 || end < body) {
            throw new IllegalArgumentException("the private key could not be read - PEM or DER, "
                    + "PKCS#8, PKCS#1 or SEC 1, without a passphrase");
        }
        return Base64Off.decode(source, body, (int) (end - body), out, 0);
    }

    private static boolean startsWith(MemorySegment source, long at, String text) {
        if (at + text.length() > source.byteSize()) {
            return false;
        }
        for (int k = 0; k < text.length(); k++) {
            if (source.get(ValueLayout.JAVA_BYTE, at + k) != text.charAt(k)) {
                return false;
            }
        }
        return true;
    }

    /**
     * PKCS#8 as it is; PKCS#1 (RSA) and SEC 1 (EC) wrapped into it - told
     * apart by their first elements, as OpenSSL's decoder does.
     */
    private static Kind toPkcs8(MemorySegment der, int length, SecretScope out) {
        Der.Reader top = new Der.Reader(der, 0, length);
        Der.Range whole = top.readWhole();
        Der.Reader outer = new Der.Reader(der, 0, length).readSequence();
        int version;
        try {
            version = outer.readSmallInteger();
        } catch (IllegalArgumentException notAnInteger) {
            throw new IllegalArgumentException("unsupported private key structure - an "
                    + "encrypted key (-----BEGIN ENCRYPTED PRIVATE KEY-----) has to be decrypted "
                    + "first; the 'encrypted' secret provider does that");
        }
        if (version == 0 && outer.peekTag() == Der.SEQUENCE) {
            Der.Reader algorithm = outer.readSequence();
            Der.Range oid = algorithm.readTaggedRange(0x06);
            Kind kind;
            if (equals(der, oid, RSA_OID)) {
                kind = Kind.RSA;
            } else if (equals(der, oid, EC_OID)) {
                kind = Kind.EC;
            } else if (equals(der, oid, ED25519_OID)) {
                throw new IllegalArgumentException("an Ed25519 key cannot sign in CNG - Windows "
                        + "has no Ed25519 signature; use an EC or RSA key here");
            } else {
                throw new IllegalArgumentException("the private key is neither RSA nor EC");
            }
            MemorySegment.copy(der, whole.offset(), out.segment(), 0, whole.length());
            out.length((int) whole.length());
            return kind;
        }
        if (version == 0 && outer.peekTag() == Der.INTEGER) {
            // PKCS#1 RSAPrivateKey: the algorithm is rsaEncryption with NULL parameters.
            byte[] algorithm = concat(new byte[] {0x06, (byte) RSA_OID.length}, RSA_OID,
                    new byte[] {0x05, 0x00});
            wrap(der, whole, algorithm, out);
            return Kind.RSA;
        }
        if (version == 1) {
            // SEC 1 ECPrivateKey: the curve moves from its [0] into the algorithm.
            outer.readOctetStringRange();
            if (!outer.hasMore() || outer.peekTag() != 0xa0) {
                throw new IllegalArgumentException("the SEC 1 key names no curve");
            }
            Der.Reader parameters = outer.readTaggedAsDer(0xa0);
            Der.Range curve = parameters.readWhole();
            byte[] curveTlv = new byte[(int) curve.length()];
            MemorySegment.copy(der, ValueLayout.JAVA_BYTE, curve.offset(), curveTlv, 0,
                    curveTlv.length);
            byte[] algorithm = concat(new byte[] {0x06, (byte) EC_OID.length}, EC_OID, curveTlv);
            wrap(der, whole, algorithm, out);
            return Kind.EC;
        }
        throw new IllegalArgumentException("unsupported private key structure, version "
                + version);
    }

    /** {@code SEQUENCE { INTEGER 0, SEQUENCE { algorithm }, OCTET STRING { key } }}. */
    private static void wrap(MemorySegment der, Der.Range key, byte[] algorithm,
            SecretScope out) {
        byte[] algorithmSequence = concat(header(0x30, algorithm.length), algorithm);
        byte[] octetHeader = header(0x04, (int) key.length());
        int content = 3 + algorithmSequence.length + octetHeader.length + (int) key.length();
        byte[] outerHeader = header(0x30, content);
        MemorySegment target = out.segment();
        long at = 0;
        for (byte[] part : new byte[][] {outerHeader, {0x02, 0x01, 0x00}, algorithmSequence,
                octetHeader}) {
            MemorySegment.copy(part, 0, target, ValueLayout.JAVA_BYTE, at, part.length);
            at += part.length;
        }
        MemorySegment.copy(der, key.offset(), target, at, key.length());
        out.length((int) (at + key.length()));
    }

    /** A DER tag and length - public framing, the key's bytes go in after it. */
    private static byte[] header(int tag, int length) {
        if (length < 0x80) {
            return new byte[] {(byte) tag, (byte) length};
        }
        if (length < 0x100) {
            return new byte[] {(byte) tag, (byte) 0x81, (byte) length};
        }
        return new byte[] {(byte) tag, (byte) 0x82, (byte) (length >> 8), (byte) length};
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] all = new byte[length]; // seclume-allow: DER framing and OIDs, public
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, all, at, part.length);
            at += part.length;
        }
        return all;
    }

    private static boolean equals(MemorySegment der, Der.Range range, byte[] expected) {
        if (range.length() != expected.length) {
            return false;
        }
        for (int i = 0; i < expected.length; i++) {
            if (der.get(ValueLayout.JAVA_BYTE, range.offset() + i) != expected[i]) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean is(String type) {
        checkOpen();
        return switch (type.toUpperCase(java.util.Locale.ROOT)) {
            case "RSA" -> kind == Kind.RSA;
            case "EC" -> kind == Kind.EC;
            default -> false;
        };
    }

    @Override
    public byte[] publicKey() {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(4096);
            MemorySegment written = arena.allocate(ValueLayout.JAVA_INT);
            int status = (int) EXPORT.invokeExact(key, 0L,
                    wide(arena, kind == Kind.RSA ? "RSAPUBLICBLOB" : "ECCPUBLICBLOB"),
                    MemorySegment.NULL, out, (int) out.byteSize(), written, 0);
            if (status != 0) {
                throw new IllegalStateException("CNG did not export the public key: "
                        + "SECURITY_STATUS 0x" + Integer.toHexString(status));
            }
            if (kind == Kind.RSA) {
                int exponentLength = out.get(ValueLayout.JAVA_INT_UNALIGNED, 8);
                int modulusLength = out.get(ValueLayout.JAVA_INT_UNALIGNED, 12);
                BigInteger exponent = new BigInteger(1, out.asSlice(RSA_HEADER, exponentLength) // seclume-allow: a public key's numbers
                        .toArray(ValueLayout.JAVA_BYTE));
                BigInteger modulus = new BigInteger(1, out.asSlice(RSA_HEADER + exponentLength, // seclume-allow: a public key's numbers
                        modulusLength).toArray(ValueLayout.JAVA_BYTE));
                return KeyFactory.getInstance("RSA").generatePublic(
                        new RSAPublicKeySpec(modulus, exponent)).getEncoded();
            }
            int size = out.get(ValueLayout.JAVA_INT_UNALIGNED, 4);
            BigInteger x = new BigInteger(1, out.asSlice(ECC_HEADER, size) // seclume-allow: a public key's numbers
                    .toArray(ValueLayout.JAVA_BYTE));
            BigInteger y = new BigInteger(1, out.asSlice(ECC_HEADER + size, size) // seclume-allow: a public key's numbers
                    .toArray(ValueLayout.JAVA_BYTE));
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(switch (size) {
                case 32 -> "secp256r1";
                case 48 -> "secp384r1";
                case 66 -> "secp521r1";
                default -> throw new IllegalStateException("an EC key of " + size
                        + "-byte coordinates");
            }));
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
                    new ECPoint(x, y), parameters.getParameterSpec(ECParameterSpec.class)))
                    .getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("the public key could not be encoded", e);
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("NCryptExportKey failed", t);
        }
    }

    @Override
    public int sign(String digest, boolean pss, MemorySegment message, long length,
            MemorySegment signature) {
        checkOpen();
        if (digest == null) {
            throw new IllegalStateException("CNG signs a hash, and none was named");
        }
        if (pss && kind != Kind.RSA) {
            throw new IllegalStateException("PSS needs an RSA key, and this one is not");
        }
        HashAlgorithm hash = switch (digest.toUpperCase(java.util.Locale.ROOT).replace("-", "")) {
            case "SHA256" -> HashAlgorithm.SHA_256;
            case "SHA384" -> HashAlgorithm.SHA_384;
            case "SHA512" -> HashAlgorithm.SHA_512;
            default -> throw new IllegalArgumentException("no " + digest + " in CNG signing");
        };
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment hashed = arena.allocate(hash.digestLength());
            hash.hash(message, 0, length, hashed, 0);
            MemorySegment padding = MemorySegment.NULL;
            int flags = 0;
            if (kind == Kind.RSA) {
                MemorySegment algorithm = wide(arena, digest.toUpperCase(java.util.Locale.ROOT)
                        .replace("-", ""));
                if (pss) {
                    // BCRYPT_PSS_PADDING_INFO { LPCWSTR pszAlgId; ULONG cbSalt; }
                    padding = arena.allocate(16, 8);
                    padding.set(ValueLayout.ADDRESS, 0, algorithm);
                    padding.set(ValueLayout.JAVA_INT, 8, hash.digestLength());
                    flags = BCRYPT_PAD_PSS;
                } else {
                    // BCRYPT_PKCS1_PADDING_INFO { LPCWSTR pszAlgId; }
                    padding = arena.allocate(ValueLayout.ADDRESS);
                    padding.set(ValueLayout.ADDRESS, 0, algorithm);
                    flags = BCRYPT_PAD_PKCS1;
                }
            }
            MemorySegment raw = arena.allocate(MAX_SIGNATURE);
            MemorySegment written = arena.allocate(ValueLayout.JAVA_INT);
            int status = (int) SIGN.invokeExact(key, padding, hashed, hash.digestLength(), raw,
                    (int) raw.byteSize(), written, flags);
            hashed.fill((byte) 0);
            if (status != 0) {
                throw new IllegalStateException("NCryptSignHash failed: SECURITY_STATUS 0x"
                        + Integer.toHexString(status));
            }
            int size = written.get(ValueLayout.JAVA_INT, 0);
            if (kind == Kind.EC) {
                // CNG writes r || s; OpenSSL, and so every caller, DER.
                byte[] der = derSignature(raw.asSlice(0, size).toArray(ValueLayout.JAVA_BYTE));
                if (der.length > signature.byteSize()) {
                    throw new IllegalStateException("the signature does not fit");
                }
                MemorySegment.copy(der, 0, signature, ValueLayout.JAVA_BYTE, 0, der.length);
                return der.length;
            }
            if (size > signature.byteSize()) {
                throw new IllegalStateException("the signature does not fit");
            }
            MemorySegment.copy(raw, 0, signature, 0, size);
            return size;
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("NCryptSignHash failed", t);
        }
    }

    /**
     * {@code SEQUENCE { INTEGER r, INTEGER s }} from {@code r || s} - with a
     * long-form length where P-521's needs one, which a one-byte length
     * written for P-256 and P-384 does not cover. A signature is public.
     */
    static byte[] derSignature(byte[] raw) {
        int field = raw.length / 2;
        byte[] r = integer(raw, 0, field);
        byte[] s = integer(raw, field, field);
        int content = r.length + s.length;
        byte[] head = header(0x30, content);
        byte[] out = new byte[head.length + content]; // seclume-allow: a signature, public
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(r, 0, out, head.length, r.length);
        System.arraycopy(s, 0, out, head.length + r.length, s.length);
        return out;
    }

    /** One DER INTEGER: minimal, and a zero in front where the top bit is set. */
    private static byte[] integer(byte[] raw, int from, int length) {
        int start = from;
        while (start < from + length - 1 && raw[start] == 0) {
            start++;
        }
        boolean pad = (raw[start] & 0x80) != 0;
        int valueLength = from + length - start + (pad ? 1 : 0);
        byte[] head = header(0x02, valueLength);
        byte[] out = new byte[head.length + valueLength]; // seclume-allow: half a signature, public
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(raw, start, out, head.length + (pad ? 1 : 0), from + length - start);
        return out;
    }

    private void checkOpen() {
        if (key == 0) {
            throw new IllegalStateException("the key is closed");
        }
    }

    @Override
    public synchronized void close() {
        if (key != 0) {
            try {
                int _ = (int) FREE.invokeExact(key);
            } catch (Throwable ignored) {
                // nothing else frees it
            }
            key = 0;
        }
    }

    private static MemorySegment wide(Arena arena, String text) {
        MemorySegment out = arena.allocate((text.length() + 1) * 2L);
        for (int i = 0; i < text.length(); i++) {
            out.set(ValueLayout.JAVA_CHAR_UNALIGNED, i * 2L, text.charAt(i));
        }
        return out;
    }

    private static byte[] hex(String text) {
        return java.util.HexFormat.of().parseHex(text); // seclume-allow: OIDs, public
    }
}
