package space.seclume.nats;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import io.nats.client.AuthHandler;
import io.nats.client.NKey;
import org.junit.jupiter.api.Test;

class NKeyOffTest {

    @Test
    void derivesSamePublicKeyAndSignatureAsOfficialNKey() throws Exception {
        for (NKey official : new NKey[] {
                NKey.createUser(null),
                NKey.createAccount(null),
                NKey.createOperator(null)
        }) {
            char[] seedChars = official.getSeed();
            byte[] seedBytes = new String(seedChars).getBytes(StandardCharsets.US_ASCII); // seclume-allow: test vector in NKeyOffTest
            byte[] nonce = "server-challenge-nonce-12345".getBytes(StandardCharsets.US_ASCII); // seclume-allow: test nonce

            try (Arena arena = Arena.ofConfined()) {
                MemorySegment seg = arena.allocate(seedBytes.length);
                MemorySegment.copy(seedBytes, 0, seg, JAVA_BYTE, 0, seedBytes.length);

                char[] derivedPub = NKeyOff.publicKey(seg, seedBytes.length);
                assertArrayEquals(official.getPublicKey(), derivedPub);
                assertNull(NKeyOff.extractJwt(seg, seedBytes.length));

                byte[] sig = NKeyOff.sign(seg, seedBytes.length, nonce);
                assertArrayEquals(official.sign(nonce), sig);
                assertTrue(official.verify(nonce, sig));
            } finally {
                official.clear();
            }
        }
    }

    @Test
    void parsesCredsFormatWithJwtAndUserSeed() throws Exception {
        NKey official = NKey.createUser(null);
        String seed = new String(official.getSeed());
        String jwt = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyIn0.c2ln";
        String creds = """
                -----BEGIN NATS USER JWT-----
                  %s
                ------END NATS USER JWT------

                ************************* IMPORTANT *************************
                NKEY Seed printed below can be used to sign and prove identity.
                NKEYs are sensitive and should be treated as secrets.

                -----BEGIN USER NKEY SEED-----
                  %s
                ------END USER NKEY SEED------
                """.formatted(jwt, seed);

        Path credsFile = Files.createTempFile("seclume-nats", ".creds");
        try {
            Files.writeString(credsFile, creds, StandardCharsets.US_ASCII);
            AuthHandler handler = SeclumeNats.authHandler(
                    "provider=file&path=" + credsFile.toString().replace('\\', '/'));

            assertArrayEquals(official.getPublicKey(), handler.getID());
            assertArrayEquals(jwt.toCharArray(), handler.getJWT());

            byte[] nonce = "challenge-from-nats-server".getBytes(StandardCharsets.US_ASCII); // seclume-allow: test nonce
            byte[] sig = handler.sign(nonce);
            assertArrayEquals(official.sign(nonce), sig);
            assertTrue(official.verify(nonce, sig));
        } finally {
            official.clear();
            Files.deleteIfExists(credsFile);
        }
    }

    @Test
    void separateJwtAndSeedFiles() throws Exception {
        NKey official = NKey.createUser(null);
        String seed = new String(official.getSeed());
        String jwt = "eyJhbGciOiJFZDI1NTE5In0.eyJzdWIiOiJzZXBhcmF0ZSJ9.c2ln";

        Path jwtFile = Files.createTempFile("seclume-nats", ".jwt");
        Path seedFile = Files.createTempFile("seclume-nats", ".nk");
        try {
            Files.writeString(jwtFile, jwt + "\n", StandardCharsets.US_ASCII);
            Files.writeString(seedFile, seed + "\n", StandardCharsets.US_ASCII);

            AuthHandler handler = SeclumeNats.authHandler(
                    "provider=file&path=" + jwtFile.toString().replace('\\', '/'),
                    "provider=file&path=" + seedFile.toString().replace('\\', '/'));

            assertArrayEquals(official.getPublicKey(), handler.getID());
            assertArrayEquals(jwt.toCharArray(), handler.getJWT());
            byte[] nonce = "separate-nonce".getBytes(StandardCharsets.US_ASCII); // seclume-allow: test nonce
            assertTrue(official.verify(nonce, handler.sign(nonce)));
        } finally {
            official.clear();
            Files.deleteIfExists(jwtFile);
            Files.deleteIfExists(seedFile);
        }
    }

    @Test
    void rejectsCorruptedCrcAndNonSeedInputs() throws Exception {
        NKey official = NKey.createUser(null);
        char[] seed = official.getSeed();
        char[] pub = official.getPublicKey();
        official.clear();

        // Flip one character in the seed -> CRC mismatch
        seed[10] = seed[10] == 'A' ? 'B' : 'A';
        byte[] corrupted = new String(seed).getBytes(StandardCharsets.US_ASCII); // seclume-allow: test vector
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = arena.allocate(corrupted.length);
            MemorySegment.copy(corrupted, 0, seg, JAVA_BYTE, 0, corrupted.length);
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> NKeyOff.publicKey(seg, corrupted.length));
            assertTrue(ex.getMessage().contains("CRC-16"), ex.getMessage());
        }

        // Public key passed where a seed is expected -> rejected
        byte[] pubBytes = new String(pub).getBytes(StandardCharsets.US_ASCII); // seclume-allow: public key test vector
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = arena.allocate(pubBytes.length);
            MemorySegment.copy(pubBytes, 0, seg, JAVA_BYTE, 0, pubBytes.length);
            assertThrows(IllegalArgumentException.class,
                    () -> NKeyOff.publicKey(seg, pubBytes.length));
        }
    }

    @Test
    void jsonEscapingInNativeMemoryMatchesExpected() throws Exception {
        byte[] raw = "p\"w\\/\b\f\n\r\t\u0007end".getBytes(StandardCharsets.UTF_8); // seclume-allow: test input
        String expected = "p\\\"w\\\\\\/\\b\\f\\n\\r\\t\\u0007end";
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment in = arena.allocate(raw.length);
            MemorySegment.copy(raw, 0, in, JAVA_BYTE, 0, raw.length);
            int escapedLen = SeclumeNatsDataPort.jsonEscapedLength(in, raw.length);
            assertEquals(expected.length(), escapedLen);
            MemorySegment out = arena.allocate(escapedLen);
            int end = SeclumeNatsDataPort.writeJsonEscaped(in, raw.length, out, 0);
            assertEquals(escapedLen, end);
            assertEquals(expected, new String(out.toArray(JAVA_BYTE), StandardCharsets.UTF_8)); // seclume-allow: test assertion
        }
    }
}
