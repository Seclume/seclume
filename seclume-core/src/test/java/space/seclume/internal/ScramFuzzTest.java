package space.seclume.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import space.seclume.crypto.HashAlgorithm;

/**
 * The SCRAM client reads two messages a server writes: its first one (nonce,
 * salt, iteration count) and its last (the signature, or an error). Kafka
 * brokers and PostgreSQL servers both reach it now. Whatever they send, the
 * answer is the login refused - an {@link IllegalStateException} or
 * {@link IllegalArgumentException} - never another exception and never a hang.
 *
 * <p>An ordinary build replays the saved inputs; {@code JAZZER_FUZZ=1 mvn test
 * -Dtest=ScramFuzzTest} searches for new ones.
 */
class ScramFuzzTest {

    @FuzzTest(maxDuration = "30s")
    void anyServerMessageIsReadOrRefused(FuzzedDataProvider data) {
        boolean sha512 = data.consumeBoolean();
        byte[] first = data.consumeBytes(600);
        byte[] last = data.consumeRemainingAsBytes();
        try (Arena arena = Arena.ofConfined();
             Scram scram = new Scram(sha512 ? HashAlgorithm.SHA_512 : HashAlgorithm.SHA_256)) {
            MemorySegment out = arena.allocate(4096);
            scram.clientFirst(out, "fuzz");
            // Let a fuzzed first message carry our nonce, so the later steps are reached.
            String nonce = new String(out.asSlice(12, 32).toArray(ValueLayout.JAVA_BYTE),  // seclume-allow: a nonce in a test, not a secret
                    java.nio.charset.StandardCharsets.US_ASCII);
            byte[] prefix = ("r=" + nonce).getBytes(java.nio.charset.StandardCharsets.US_ASCII); // seclume-allow: a test nonce
            MemorySegment serverFirst = arena.allocate(prefix.length + first.length + 1L);
            MemorySegment.copy(prefix, 0, serverFirst, ValueLayout.JAVA_BYTE, 0, prefix.length);
            MemorySegment.copy(first, 0, serverFirst, ValueLayout.JAVA_BYTE, prefix.length,
                    first.length);
            try {
                scram.serverFirst(serverFirst, 0, prefix.length + first.length);
                if (scram.iterations() > 5000) {
                    return;                  // real work, not a parser question
                }
                MemorySegment password = arena.allocate(8);
                scram.clientFinal(out, password);
                MemorySegment serverFinal = arena.allocate(Math.max(1, last.length));
                MemorySegment.copy(last, 0, serverFinal, ValueLayout.JAVA_BYTE, 0, last.length);
                scram.verifyServerFinal(serverFinal, 0, last.length);
            } catch (IllegalStateException | IllegalArgumentException refused) {
                // the login refused: what should happen
            }
        }
    }
}
