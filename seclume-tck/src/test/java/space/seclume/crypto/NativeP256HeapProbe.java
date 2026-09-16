package space.seclume.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.ref.Reference;
import java.math.BigInteger;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import space.seclume.secret.SecretScope;
import space.seclume.tck.Heap;

/** Child-only measurement; package access permits native scalar export without a public API. */
public final class NativeP256HeapProbe {
    private static Object alive;

    private NativeP256HeapProbe() { }

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        Path needles = Path.of(args[1]);
        Path dump = Path.of(args[2]);
        try (Arena arena = Arena.ofConfined(); SecretScope scalar = SecretScope.allocate(32);
                SecretScope shared = SecretScope.allocate(32)) {
            if (mode.equals("jca")) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp256r1"));
                var own = generator.generateKeyPair();
                var peer = generator.generateKeyPair();
                BigInteger integer = ((ECPrivateKey) own.getPrivate()).getS();
                for (int i = 0; i < 32; i++) {
                    scalar.segment().set(ValueLayout.JAVA_BYTE, 31 - i, integer.shiftRight(8 * i).byteValue());
                }
                KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
                agreement.init(own.getPrivate());
                agreement.doPhase(peer.getPublic(), true);
                byte[] secret = agreement.generateSecret();
                MemorySegment.copy(MemorySegment.ofArray(secret), 0, shared.segment(), 0, 32);
                alive = new Object[] {own, peer, agreement, secret};
                measure(needles, dump, scalar.segment(), shared.segment());
            } else if (mode.equals("native") || mode.equals("leak")) {
                try (NativeP256 own = NativeP256.generate(); NativeP256 peer = NativeP256.generate()) {
                    MemorySegment publicKey = arena.allocate(65);
                    peer.publicKey(publicKey);
                    own.derive(publicKey, shared.segment());
                    own.privateScalar(scalar.segment());
                    alive = mode.equals("leak")
                            ? new Object[] {own, peer, scalar.segment().toArray(ValueLayout.JAVA_BYTE),
                                    shared.segment().toArray(ValueLayout.JAVA_BYTE)}
                            : new Object[] {own, peer, scalar, shared};
                    measure(needles, dump, scalar.segment(), shared.segment());
                }
            } else {
                throw new IllegalArgumentException("unknown mode");
            }
        } finally {
            alive = null;
        }
    }

    private static void measure(Path needles, Path dump, MemorySegment scalar, MemorySegment shared)
            throws Exception {
        // Needles leave the child directly from native memory. The parent reads
        // them only in its own JVM. They never travel as arguments, strings or logs.
        try (FileChannel file = FileChannel.open(needles, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            for (MemorySegment secret : new MemorySegment[] {scalar, shared}) {
                var buffer = secret.asByteBuffer();
                while (buffer.hasRemaining()) file.write(buffer);
            }
        }
        // No requested GC: include unreachable copies too. Both native handles
        // and the result are alive while Heap.dump(live=false) takes the snapshot.
        Heap.dump(dump);
        Reference.reachabilityFence(alive);
    }
}
