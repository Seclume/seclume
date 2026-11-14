package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import space.seclume.crypto.HashAlgorithm;

/**
 * Everything a SCRAM exchange held is zero when its memory is given back -
 * after a login that worked, after one the server refused, and after one this
 * client refused.
 *
 * <p>The class promises an arena "zeroed on close" (its javadoc, and the
 * external audit of 28.09.2026 that added the wiping in {@code close()}). No
 * test looked at the memory: every {@code wipe} in {@code close()} could be
 * removed and the tests stayed green (run 43416680859: seven survivors there,
 * and one for the {@code arena.close()} itself).
 *
 * <p>How it looks: the exchange's arena is replaced, right after construction,
 * by one that hands out the real arena's memory and, when {@code close()}
 * reaches it, reads every segment of the exchange - the ones held in fields
 * and every one allocated since - before the real arena frees them. Reading
 * them earlier, before the close, is the control: the same segments hold
 * non-zero bytes then, so a check that finds zeros is not one that could find
 * nothing else.
 */
class ScramWipeTest {

    private static final byte[] SALT = "a salt of sixteen".getBytes(StandardCharsets.US_ASCII);
    private static final int ITERATIONS = 4096;

    /** The real arena behind a window: what was allocated, and what it held when close() came. */
    private static final class Watching implements Arena {
        final Arena real;
        final Scram scram;
        final List<MemorySegment> allocated = new ArrayList<>();
        final Map<String, String> notZeroAtClose = new LinkedHashMap<>();
        int closes;

        Watching(Arena real, Scram scram) {
            this.real = real;
            this.scram = scram;
        }

        @Override
        public MemorySegment allocate(long byteSize, long byteAlignment) {
            MemorySegment segment = real.allocate(byteSize, byteAlignment);
            allocated.add(segment);
            return segment;
        }

        @Override
        public MemorySegment.Scope scope() {
            return real.scope();
        }

        @Override
        public void close() {
            closes++;
            Map<String, MemorySegment> all = held(scram);
            for (int i = 0; i < allocated.size(); i++) {
                all.put("allocation " + i + " of " + allocated.get(i).byteSize() + " bytes", allocated.get(i));
            }
            for (Map.Entry<String, MemorySegment> one : all.entrySet()) {
                long at = firstNonZero(one.getValue());
                if (at >= 0) {
                    notZeroAtClose.put(one.getKey(), "byte " + at + " of " + one.getValue().byteSize());
                }
            }
            real.close();
        }
    }

    /** The segments an exchange keeps in its fields. */
    private static Map<String, MemorySegment> held(Scram scram) {
        Map<String, MemorySegment> held = new LinkedHashMap<>();
        for (String name : List.of("expectedServerSignature", "clientNonce", "serverNonce", "salt",
                "bindingData", "gs2Header")) {
            MemorySegment segment = (MemorySegment) field(scram, name);
            if (segment != null) {
                held.put(name, segment);
            }
        }
        Object authMessage = field(scram, "authMessage");
        try {
            var segment = authMessage.getClass().getDeclaredMethod("segment");
            segment.setAccessible(true);
            held.put("authMessage", (MemorySegment) segment.invoke(authMessage));
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
        return held;
    }

    private static Object field(Object owner, String name) {
        try {
            Field field = Scram.class.getDeclaredField(name);
            field.setAccessible(true);
            return field.get(owner);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Scram." + name, e);
        }
    }

    /** Puts the watching arena in place of the exchange's own; the own one is its delegate. */
    private static Watching watch(Scram scram) {
        try {
            Field field = Scram.class.getDeclaredField("arena");
            field.setAccessible(true);
            Watching watching = new Watching((Arena) field.get(scram), scram);
            field.set(scram, watching);
            return watching;
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    private static long firstNonZero(MemorySegment segment) {
        for (long i = 0; i < segment.byteSize(); i++) {
            if (segment.get(ValueLayout.JAVA_BYTE, i) != 0) {
                return i;
            }
        }
        return -1;
    }

    private static String text(MemorySegment segment, int length) {
        byte[] bytes = new byte[length];
        MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, 0, bytes, 0, length);
        return new String(bytes, StandardCharsets.US_ASCII);
    }

    private static MemorySegment ascii(Arena arena, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    /** An exchange taken as far as the client's final message, with channel binding. */
    private record Exchange(Scram scram, Watching watching, String clientFirstBare, String serverFirst,
                            String clientFinalWithoutProof) {
    }

    private static Exchange throughClientFinal(Arena arena, String password, boolean channelBinding) {
        Scram scram = new Scram(HashAlgorithm.SHA_256);
        Watching watching = watch(scram);
        if (channelBinding) {
            MemorySegment fingerprint = arena.allocate(32);
            for (int i = 0; i < 32; i++) {
                fingerprint.set(ValueLayout.JAVA_BYTE, i, (byte) (0xA0 + i));
            }
            scram.useChannelBinding(fingerprint, 32);
        }
        MemorySegment out = arena.allocate(1024);
        String clientFirst = text(out, scram.clientFirst(out, "app"));
        String clientFirstBare = clientFirst.substring(clientFirst.indexOf("n=", 1));
        String nonce = clientFirst.substring(clientFirst.indexOf(",r=") + 3);
        String serverFirst = "r=" + nonce + "Srv0nceZz,s=" + Base64.getEncoder().encodeToString(SALT)
                + ",i=" + ITERATIONS;
        MemorySegment first = ascii(arena, serverFirst);
        scram.serverFirst(first, 0, (int) first.byteSize());
        String clientFinal = text(out, scram.clientFinal(out, ascii(arena, password)));
        return new Exchange(scram, watching, clientFirstBare, serverFirst,
                clientFinal.substring(0, clientFinal.indexOf(",p=")));
    }

    /** The server's v= for this exchange, as the server computes it. */
    private static String serverSignature(Exchange exchange, String password) throws Exception {
        byte[] salted = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(new PBEKeySpec(password.toCharArray(), SALT, ITERATIONS, 256)).getEncoded();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salted, "HmacSHA256"));
        byte[] serverKey = mac.doFinal("Server Key".getBytes(StandardCharsets.US_ASCII));
        mac.init(new SecretKeySpec(serverKey, "HmacSHA256"));
        String authMessage = exchange.clientFirstBare() + "," + exchange.serverFirst() + ","
                + exchange.clientFinalWithoutProof();
        return Base64.getEncoder().encodeToString(mac.doFinal(authMessage.getBytes(StandardCharsets.US_ASCII)));
    }

    private static void assertNonZeroBeforeClose(Watching watching, String... names) {
        Map<String, MemorySegment> held = held(watching.scram);
        for (String name : names) {
            MemorySegment segment = held.get(name);
            assertTrue(segment != null && firstNonZero(segment) >= 0,
                    "control: " + name + " holds data before the close");
        }
    }

    private static void assertAllZeroAtClose(Watching watching) {
        assertEquals(1, watching.closes, "close() reached the arena once");
        assertEquals(Map.of(), watching.notZeroAtClose, "memory given back with data still in it");
        assertFalse(watching.real.scope().isAlive(), "and the memory itself was given back");
    }

    @Test
    void afterALoginThatWorkedEverySegmentIsZeroWhenTheArenaIsFreed() throws Exception {
        try (Arena arena = Arena.ofConfined()) {
            String password = "correct horse battery staple";
            Exchange exchange = throughClientFinal(arena, password, true);
            MemorySegment last = ascii(arena, "v=" + serverSignature(exchange, password));
            exchange.scram().verifyServerFinal(last, 0, (int) last.byteSize());
            assertNonZeroBeforeClose(exchange.watching(), "expectedServerSignature", "clientNonce",
                    "serverNonce", "salt", "bindingData", "gs2Header", "authMessage");
            assertTrue(exchange.watching().allocated.size() >= 5, "the steps allocated through the window");

            exchange.scram().close();
            assertAllZeroAtClose(exchange.watching());
        }
    }

    /** "Cleanup bei fehlgeschlagenen Authentifizierungen": the server could not prove the password. */
    @Test
    void afterTheServerFailedItsProofEverySegmentIsZeroWhenTheArenaIsFreed() {
        try (Arena arena = Arena.ofConfined()) {
            Exchange exchange = throughClientFinal(arena, "a password", false);
            MemorySegment forged = ascii(arena, "v=" + Base64.getEncoder().encodeToString(new byte[32]));
            assertThrows(IllegalStateException.class,
                    () -> exchange.scram().verifyServerFinal(forged, 0, (int) forged.byteSize()));
            MemorySegment refused = ascii(arena, "e=invalid-proof");
            assertThrows(IllegalStateException.class,
                    () -> exchange.scram().verifyServerFinal(refused, 0, (int) refused.byteSize()));
            assertNonZeroBeforeClose(exchange.watching(), "expectedServerSignature", "salt", "authMessage");

            exchange.scram().close();
            assertAllZeroAtClose(exchange.watching());
        }
    }

    /** A server-first this client refuses leaves fields half set; they are wiped too. */
    @Test
    void afterThisClientRefusedTheServerEverySegmentIsZeroWhenTheArenaIsFreed() {
        try (Arena arena = Arena.ofConfined()) {
            Scram scram = new Scram(HashAlgorithm.SHA_256);
            Watching watching = watch(scram);
            MemorySegment out = arena.allocate(256);
            String clientFirst = text(out, scram.clientFirst(out));
            String nonce = clientFirst.substring(clientFirst.indexOf(",r=") + 3);
            MemorySegment tooFew = ascii(arena, "r=" + nonce + "Srv,s="
                    + Base64.getEncoder().encodeToString(SALT) + ",i=1");
            assertThrows(IllegalStateException.class,
                    () -> scram.serverFirst(tooFew, 0, (int) tooFew.byteSize()));
            assertNonZeroBeforeClose(watching, "serverNonce", "salt", "clientNonce", "authMessage");
            MemorySegment password = ascii(arena, "never used");
            assertThrows(IllegalStateException.class, () -> scram.clientFinal(out, password),
                    "no proof is made from a refused server-first");

            scram.close();
            assertAllZeroAtClose(watching);
        }
    }

    @Test
    void aSecondCloseDoesNothing() {
        Scram scram = new Scram(HashAlgorithm.SHA_256);
        Watching watching = watch(scram);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(256);
            scram.clientFirst(out);
        }
        scram.close();
        scram.close();
        assertAllZeroAtClose(watching);
    }
}
