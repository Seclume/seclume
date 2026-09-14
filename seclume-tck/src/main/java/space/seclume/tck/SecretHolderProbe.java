package space.seclume.tck;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;
import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The specimen: a <b>JVM of its own</b> that uses a secret and
 * anschliessend ihren eigenen Heap ausschreibt.
 *
 * <p>Why a JVM of its own: the test runner itself keeps test data, assertion
 * messages and expected values on the heap - the searched-for password among
 * them. In a dump of the test runner every finding would be worthless, because
 * one could no longer tell whether it came from the driver or from the test.
 *
 * <p>The password arrives through a <b>file</b>, never through a command line
 * argument: arguments sit on the heap as a {@code String[]} and
 * are visible outside the process in {@code /proc/<pid>/cmdline} as well. The
 * experiment would be spoiled from the outset.
 *
 * <p>Invocation:
 * {@snippet :
 * java SecretHolderProbe <offheap|offheap-open|leaking> <secretFile> <dumpFile> <cycles>
 * }
 *
 * <p>{@code offheap-open} keeps the secret <b>open</b> while the dump is taken
 * - mid-handshake, so to speak. Even then nothing may be findable: the segment
 * lives in native memory, and that appears in no hprof.
 */
public final class SecretHolderProbe {

    private SecretHolderProbe() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println(
                    "usage: <offheap|offheap-open|leaking> <secretFile> <dumpFile> <cycles>");
            System.exit(2);
            return;
        }
        String mode = args[0];
        Path secretFile = Path.of(args[1]);
        Path dumpFile = Path.of(args[2]);
        int cycles = Integer.parseInt(args[3]);

        SecretProvider provider = switch (mode) {
            case "offheap", "offheap-open" -> new FileSecretProvider(secretFile, 256);
            case "leaking" -> StaticSecretProvider.fromFile(secretFile);
            default -> throw new IllegalArgumentException("unknown mode " + mode);
        };

        // Several cycles, because a pool asks again on every reconnect. What
        // arises in the process has to be gone again after each cycle.
        List<Object> connections = new ArrayList<>();
        for (int i = 0; i < cycles; i++) {
            connections.add(handshake(provider));
        }

        // Clean up and provoke: after a full GC nothing may be left, and the
        // dump takes dead objects along anyway.
        Heap.collect();

        if (mode.equals("offheap-open")) {
            // The hardest case: at this very moment the secret is in memory,
            // mid-handshake. It is still not on the heap.
            try (SecretScope open = SecretScope.fromProvider(provider)) {
                Heap.dump(dumpFile);
                System.out.println("held " + open.length() + " bytes during the dump");
            }
        } else {
            Heap.dump(dumpFile);
        }

        // The connections have to stay alive until here, otherwise the GC
        // clears them before the dump and the test checks nothing.
        System.out.println("cycles=" + connections.size() + " mode=" + mode);
    }

    /**
     * A handshake the way a driver runs one: fetch the secret, compute with
     * it,
     * and get rid of the secret again. What remains is something connection-like
     * that no longer contains the secret.
     */
    private static Object handshake(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined();
             SecretScope scope = SecretScope.fromProvider(provider)) {
            MemorySegment proof = arena.allocate(32);
            // Standing in for SCRAM: HMAC over the password.
            try (Hmac hmac = new Hmac(HashAlgorithm.SHA_256, scope.secret())) {
                hmac.update(scope.secret());
                hmac.doFinal(proof, 0);
            }
            // The "proof" leaves the handshake as a copy on the heap - which
            // it may, since it cannot be reversed. That is exactly how the real
            // protocol works too.
            byte[] handshakeResult = new byte[32];
            MemorySegment.copy(proof, java.lang.foreign.ValueLayout.JAVA_BYTE, 0,
                    handshakeResult, 0, 32);
            return handshakeResult;
        }
    }
}
