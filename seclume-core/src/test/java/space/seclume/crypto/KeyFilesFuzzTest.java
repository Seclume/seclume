package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.junit.FuzzTest;

import space.seclume.internal.Base64Off;

/**
 * Key files are read before anything else is known about them - PEM or DER,
 * PKCS#8 or SEC 1, an OpenSSH file - and they come from a mount, a secret
 * manager, an operator's copy and paste. Whatever is in them, the readers
 * answer or refuse with {@link IllegalArgumentException}, the one refusal
 * they document, and write nothing outside the space they were given.
 *
 * <p>Only generated test keys cross the heap here.
 */
class KeyFilesFuzzTest {

    private static final byte GUARD = 0x5a;
    private static final int ROUNDS = Integer.getInteger("seclume.keys.fuzz.rounds", 20_000);

    /**
     * A private key file as ssh-keygen wrote it, the public key line next to
     * it, and - for RSA - the same key as ssh-keygen exports it in PKCS#8.
     */
    private record SshKey(String type, byte[] file, String publicLine, byte[] pkcs8) {
    }

    private static int sshKeygen(List<String> command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        process.getInputStream().readAllBytes();
        return process.waitFor();
    }

    /** What ssh-keygen writes, made once per run; empty without ssh-keygen. */
    private static List<SshKey> sshKeygenKeys;

    private static synchronized List<SshKey> sshKeygen() throws Exception {
        if (sshKeygenKeys != null) {
            return sshKeygenKeys;
        }
        List<SshKey> keys = new ArrayList<>();
        Path directory = Files.createTempDirectory("seclume-ssh-keygen-");
        try {
            for (String[] type : List.of(new String[] {"ed25519", "-t", "ed25519"},
                    new String[] {"ecdsa256", "-t", "ecdsa", "-b", "256"},
                    new String[] {"ecdsa521", "-t", "ecdsa", "-b", "521"},
                    new String[] {"rsa", "-t", "rsa", "-b", "2048"})) {
                Path file = directory.resolve(type[0]);
                List<String> command = new ArrayList<>(List.of("ssh-keygen", "-q", "-N", "",
                        "-C", "seclume-fuzz", "-f", file.toString()));
                command.addAll(List.of(type).subList(1, type.length));
                try {
                    if (sshKeygen(command) != 0) {
                        continue;
                    }
                } catch (java.io.IOException notInstalled) {
                    break;
                }
                byte[] pkcs8 = null;
                if (type[0].equals("rsa")) {
                    Path copy = directory.resolve("rsa.pkcs8");
                    Files.copy(file, copy);
                    assertEquals(0, sshKeygen(List.of("ssh-keygen", "-q", "-p", "-P", "", "-N", "",
                            "-m", "PKCS8", "-f", copy.toString())), "ssh-keygen -m PKCS8");
                    pkcs8 = Base64.getMimeDecoder().decode(Files.readString(copy)
                            .replaceAll("-----[A-Z ]+-----", ""));
                }
                keys.add(new SshKey(type[0], Files.readAllBytes(file),
                        Files.readString(directory.resolve(type[0] + ".pub")).trim(), pkcs8));
            }
        } finally {
            try (var files = Files.list(directory)) {
                for (Path file : files.toList()) {
                    Files.deleteIfExists(file);
                }
            }
            Files.deleteIfExists(directory);
        }
        sshKeygenKeys = List.copyOf(keys);
        return sshKeygenKeys;
    }

    private static List<byte[]> seeds() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        byte[] pkcs8 = generator.generateKeyPair().getPrivate().getEncoded();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(pkcs8)
                + "\n-----END PRIVATE KEY-----\n";
        byte[] opensshBody = "openssh-key-v1\0\0\0\0\4none\0\0\0\4none\0\0\0\0\0\0\0\1"
                .getBytes(StandardCharsets.ISO_8859_1);
        String openssh = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + Base64.getEncoder().encodeToString(opensshBody)
                + "\n-----END OPENSSH PRIVATE KEY-----\n";
        List<byte[]> seeds = new ArrayList<>();
        seeds.add(pkcs8);
        seeds.add(pem.getBytes(StandardCharsets.US_ASCII));
        seeds.add(openssh.getBytes(StandardCharsets.US_ASCII));
        for (SshKey key : sshKeygen()) {
            seeds.add(key.file());
        }
        return seeds;
    }

    /** Every reader on one input; only IllegalArgumentException may come out. */
    private static void readAll(byte[] input) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = arena.allocate(Math.max(1, input.length));
            MemorySegment.copy(input, 0, source, ValueLayout.JAVA_BYTE, 0, input.length);

            guarded(arena, 48, out -> EcPrivateKeyFile.scalar(source, input.length, out, 32));
            guarded(arena, 48, out -> EcPrivateKeyFile.scalar(source, input.length, out, 48));
            guarded(arena, Base64Off.decodedUpperBound(input.length),
                    out -> Base64Off.decode(source, 0, input.length, out, 0));
            if (OpenSshPrivateKey.is(source, input.length)) {
                guarded(arena, OpenSshPrivateKey.maxDerLength(input.length),
                        out -> OpenSshPrivateKey.toDer(source, input.length, out));
            }
            assertTrue(java.util.Arrays.equals(input, source.asSlice(0, input.length)
                    .toArray(ValueLayout.JAVA_BYTE)), "the input was changed");
        }
    }

    private interface Reader {
        int read(MemorySegment out);
    }

    /** {@code size} bytes between two guards; the reader's answer has to fit them. */
    private static void guarded(Arena arena, int size, Reader reader) {
        MemorySegment storage = arena.allocate(size + 2L);
        storage.fill(GUARD);
        MemorySegment out = storage.asSlice(1, size);
        try {
            int written = reader.read(out);
            assertTrue(written >= 0 && written <= size, "wrote " + written + " of " + size);
        } catch (IllegalArgumentException refused) {
            // the documented refusal
        } catch (RuntimeException | StackOverflowError | OutOfMemoryError other) {
            fail("not an IllegalArgumentException: " + other, other);
        }
        assertEquals(GUARD, storage.get(ValueLayout.JAVA_BYTE, 0), "written before the space");
        assertEquals(GUARD, storage.get(ValueLayout.JAVA_BYTE, size + 1L),
                "written after the space");
    }

    @FuzzTest(maxDuration = "60s")
    void anyKeyFileIsReadOrRefused(byte[] input) {
        if (input.length <= 16 * 1024) {
            readAll(input);
        }
    }

    /** The real shapes are read, not refused - a fuzzer that only sees refusals tests little. */
    @Test
    void theSeedsAreRealKeys() throws Exception {
        List<byte[]> seeds = seeds();
        try (Arena arena = Arena.ofConfined()) {
            for (byte[] key : seeds.subList(0, 2)) {
                MemorySegment source = arena.allocate(key.length);
                MemorySegment.copy(key, 0, source, ValueLayout.JAVA_BYTE, 0, key.length);
                assertEquals(32, EcPrivateKeyFile.scalar(source, key.length, arena.allocate(32)));
            }
        }
    }

    /**
     * What ssh-keygen writes - Ed25519, ECDSA P-256 and P-521, RSA - is
     * converted, not refused, so the mutations start from files that read.
     * And converted right: the key that comes out signs, and the public key
     * ssh-keygen wrote next to it verifies the signature - one wrong byte
     * anywhere in the conversion and it does not.
     */
    @Test
    void theSshKeygenSeedsAreRealKeys() throws Exception {
        List<SshKey> keys = sshKeygen();
        Assumptions.assumeTrue(!keys.isEmpty(), "ssh-keygen is not installed");
        assertEquals(4, keys.size(), "ssh-keygen made only " + keys.size() + " of the four keys");
        try (Arena arena = Arena.ofConfined()) {
            for (SshKey key : keys) {
                byte[] file = key.file();
                MemorySegment source = arena.allocate(file.length);
                MemorySegment.copy(file, 0, source, ValueLayout.JAVA_BYTE, 0, file.length);
                assertTrue(OpenSshPrivateKey.is(source, file.length), key.type());
                MemorySegment out = arena.allocate(OpenSshPrivateKey.maxDerLength(file.length));
                int length = OpenSshPrivateKey.toDer(source, file.length, out);
                assertSignsFor(key, out.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE));
            }
        }
    }

    /** Signs with the converted key and verifies with ssh-keygen's public key. */
    private static void assertSignsFor(SshKey key, byte[] der) throws Exception {
        ByteBuffer wire = ByteBuffer.wrap(
                Base64.getDecoder().decode(key.publicLine().split(" ")[1]));
        String type = new String(field(wire), StandardCharsets.US_ASCII);
        PrivateKey privateKey;
        PublicKey publicKey;
        String algorithm;
        switch (key.type()) {
            case "ed25519" -> {
                assertEquals("ssh-ed25519", type);
                KeyFactory factory = KeyFactory.getInstance("Ed25519");
                privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(der));
                publicKey = factory.generatePublic(new X509EncodedKeySpec(concat(
                        HexFormat.of().parseHex("302a300506032b6570032100"), field(wire))));
                algorithm = "Ed25519";
            }
            case "ecdsa256", "ecdsa521" -> {
                boolean p256 = key.type().equals("ecdsa256");
                int size = p256 ? 32 : 66;
                field(wire);                                  // the curve's name
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec(p256 ? "secp256r1" : "secp521r1"));
                ECParameterSpec curve = ((ECKey) generator.generateKeyPair().getPublic())
                        .getParams();
                // SEC 1 inside PKCS#8: version 0, id-ecPublicKey with the curve.
                byte[] algorithmId = der(0x30, concat(
                        HexFormat.of().parseHex("06072a8648ce3d0201"), HexFormat.of().parseHex(
                                p256 ? "06082a8648ce3d030107" : "06052b81040023")));
                KeyFactory factory = KeyFactory.getInstance("EC");
                privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(der(0x30, concat(
                        concat(HexFormat.of().parseHex("020100"), algorithmId),
                        der(0x04, der)))));
                byte[] point = field(wire);
                publicKey = factory.generatePublic(new ECPublicKeySpec(new ECPoint(
                        new BigInteger(1, Arrays.copyOfRange(point, 1, 1 + size)),
                        new BigInteger(1, Arrays.copyOfRange(point, 1 + size, 1 + 2 * size))),
                        curve));
                algorithm = p256 ? "SHA256withECDSA" : "SHA512withECDSA";
            }
            default -> {
                assertEquals("ssh-rsa", type);
                BigInteger exponent = new BigInteger(1, field(wire));
                BigInteger modulus = new BigInteger(1, field(wire));
                // PKCS#1 inside PKCS#8: version 0, rsaEncryption with NULL parameters.
                byte[] pkcs8 = der(0x30, concat(HexFormat.of().parseHex(
                        "020100300d06092a864886f70d0101010500"), der(0x04, der)));
                // Byte for byte what ssh-keygen exports: minimal integers, the
                // CRT values a native signer uses - the JDK signs right with
                // wrong ones, it checks and falls back.
                assertEquals(HexFormat.of().formatHex(key.pkcs8()),
                        HexFormat.of().formatHex(pkcs8), "rsa: not the PKCS#1 ssh-keygen exports");
                KeyFactory factory = KeyFactory.getInstance("RSA");
                privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
                publicKey = factory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
                algorithm = "SHA256withRSA";
            }
        }
        byte[] message = ("signed by " + key.type()).getBytes(StandardCharsets.US_ASCII);
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(privateKey);
        signer.update(message);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(signature),
                key.type() + ": the converted key is not the one ssh-keygen made");
    }

    /** One SSH wire string: a 4-byte length, then that many bytes. */
    private static byte[] field(ByteBuffer wire) {
        byte[] value = new byte[wire.getInt()];
        wire.get(value);
        return value;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] both = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, both, a.length, b.length);
        return both;
    }

    /** A DER element with a definite length, short or long form. */
    private static byte[] der(int tag, byte[] content) {
        int n = content.length;
        byte[] length = n < 0x80 ? new byte[] {(byte) n}
                : n < 0x100 ? new byte[] {(byte) 0x81, (byte) n}
                : new byte[] {(byte) 0x82, (byte) (n >> 8), (byte) n};
        return concat(concat(new byte[] {(byte) tag}, length), content);
    }

    @Test
    void mutatedKeyFilesAreReadOrRefused() throws Exception {
        List<byte[]> seeds = seeds();
        long seed = Long.getLong("seclume.keys.fuzz.seed", 0x5EC_4E75);
        Random random = new Random(seed);
        for (int round = 0; round < ROUNDS; round++) {
            byte[] input = seeds.get(round % seeds.size()).clone();
            int edits = 1 + random.nextInt(4);
            for (int e = 0; e < edits && input.length > 0; e++) {
                int at = random.nextInt(input.length);
                switch (random.nextInt(4)) {
                    case 0 -> input[at] = (byte) random.nextInt(256);
                    case 1 -> input[at] = (byte) (0x80 | random.nextInt(4));   // long DER lengths
                    case 2 -> input = java.util.Arrays.copyOf(input, at);
                    default -> input[at] = (byte) (input[at] ^ (1 << random.nextInt(8)));
                }
            }
            try {
                readAll(input);
            } catch (AssertionError broken) {
                throw new AssertionError("seed " + seed + " round " + round + ": "
                        + broken.getMessage(), broken);
            }
        }
    }
}
