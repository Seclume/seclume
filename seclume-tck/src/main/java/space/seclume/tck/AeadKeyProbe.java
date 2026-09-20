package space.seclume.tck;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.file.Path;

import space.seclume.crypto.Aes;
import space.seclume.crypto.AesKey;
import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretScope;

/**
 * Where an AES key ends up, depending on who does the encrypting.
 *
 * <p>This settles the open question of {@code PROVENANCE.md}. TLS 1.3 needs AEAD,
 * our own AES has none, and the two ways out are to write GHASH or to let the
 * JCA do AES-GCM. The second is far less work and the argument against it is
 * that it puts the traffic key on the heap - which is an argument until somebody
 * measures it.
 *
 * <p>So: a JVM of its own encrypts one block with the key, drops every
 * reference it can, asks for a collection and writes out its own heap. What is
 * then in the dump is not an opinion.
 *
 * <p>Two modes, because a result without its control is worth nothing. In
 * {@code jca} the key goes through {@code SecretKeySpec}; in {@code ours} it
 * stays in the {@link SecretScope} it arrived in and is used by this project's
 * own AES. If the dump were dirty in both cases the experiment would be
 * measuring the harness rather than the question.
 *
 * <p>The key arrives through a <b>file</b> and never as an argument: arguments
 * are a {@code String[]} on the heap and readable from outside the process
 * besides. That mistake has been made in this repository once already, and the
 * tool that found it was this one.
 *
 * <pre>java ... AeadKeyProbe jca|ours &lt;key file&gt; &lt;dump file&gt;</pre>
 */
public final class AeadKeyProbe {

    private AeadKeyProbe() {
    }

    /**
     * What the probe keeps alive while its heap is written out.
     *
     * <p>Static on purpose, and this is the whole correctness of the
     * experiment. The first version dropped the references and asked for a
     * collection before dumping - and found nothing, which is true and answers
     * the wrong question. A TLS connection holds its cipher for as long as it
     * is open; what matters is what is on the heap <b>then</b>, not after the
     * connection has gone away and the collector has been through.
     */
    private static Object alive;

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        Path keyFile = Path.of(args[1]);
        Path dumpFile = Path.of(args[2]);

        try (SecretScope key = SecretScope.fromProvider(new FileSecretProvider(keyFile, 64))) {
            if ("jca".equals(mode)) {
                throughTheJca(key);
            } else {
                throughOurOwn(key);
            }
            Heap.collect();
            Heap.dump(dumpFile);
            System.out.println("encrypted with " + mode + ", dump written");
        }
    }

    /**
     * The JCA route: the key has to become a {@code byte[]}.
     *
     * <p>There is no way around it. {@code Cipher.init} takes a
     * {@code SecretKey}, every implementation of that hands its bytes out as a
     * heap array, and {@code SecretKeySpec} keeps a copy of its own for as long
     * as the object lives. It does not even implement {@code destroy()} - the
     * default throws - so the copy cannot be wiped either.
     *
     * <p>The local array is zeroed here anyway, so that what the dump finds is
     * the copy inside the JCA rather than ours.
     */
    private static void throughTheJca(SecretScope key) throws Exception {
        byte[] material = new byte[32];  // seclume-allow: the point of the experiment
        MemorySegment.copy(key.secret(), ValueLayout.JAVA_BYTE, 0, material, 0, 32);
        javax.crypto.SecretKey secret = // seclume-allow: this leak is the experiment
                new javax.crypto.spec.SecretKeySpec(material, "AES");
        java.util.Arrays.fill(material, (byte) 0);

        javax.crypto.Cipher cipher = // seclume-allow: this leak is the experiment
                javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secret, // seclume-allow: see above
                new javax.crypto.spec.GCMParameterSpec(128, new byte[12])); // seclume-allow
        cipher.doFinal(new byte[64]);
        // Held, the way an open connection holds its cipher.
        alive = new Object[] {secret, cipher};
    }

    /**
     * Our own route: the key never leaves the segment it arrived in.
     *
     * <p>Kept alive exactly as long as the other one, or the comparison would
     * be between a live key and a collected one.
     */
    private static void throughOurOwn(SecretScope key) {
        Arena arena = Arena.ofShared();
        AesKey expanded = new AesKey(key.secret(), 0, 32);
        MemorySegment iv = arena.allocate(16);
        MemorySegment plain = arena.allocate(64);
        MemorySegment cipher = arena.allocate(64);
        Aes.cbcEncrypt(expanded, iv, plain, 0, cipher, 0, 64);
        alive = new Object[] {arena, expanded, iv, plain, cipher};
    }
}
