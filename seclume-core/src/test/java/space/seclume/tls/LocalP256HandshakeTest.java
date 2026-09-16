package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hkdf;
import space.seclume.crypto.NativeP256;
import space.seclume.internal.Entropy;
import space.seclume.secret.SecretScope;

/**
 * Connect native ECDH to the existing transcript/HKDF/record implementations.
 * The AEAD tag on a real server's first encrypted flight is the outside verdict.
 * This fixture does NOT authenticate the certificate, verify Finished, or log in.
 * It expects ServerHello in one plaintext record; general reassembly remains open.
 */
class LocalP256HandshakeTest {
    @Test
    void nativeEcdhOpensPostgresEncryptedFlightAndWrongSecretDoesNot() throws Exception {
        String host = System.getProperty("seclume.tls.hello.host");
        Assumptions.assumeTrue(host != null && !host.isBlank(), "no TLS fixture configured");
        int port = Integer.getInteger("seclume.tls.hello.port", 5433);
        try (Arena arena = Arena.ofConfined(); Socket socket = new Socket();
                NativeP256 key = NativeP256.generate(); SecretScope secret = SecretScope.allocate(32)) {
            socket.connect(new InetSocketAddress(host, port), 5000);
            socket.setSoTimeout(5000);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());
            out.writeInt(8);
            out.writeInt(80877103);
            out.flush();
            assertEquals('S', in.readUnsignedByte());
            MemorySegment random = arena.allocate(32);
            MemorySegment session = arena.allocate(32);
            Entropy.fill(random);
            Entropy.fill(session);
            MemorySegment publicKey = arena.allocate(65);
            key.publicKey(publicKey);
            MemorySegment hello = arena.allocate(512);
            int count = ClientHello.write(hello, 0, random, session, ClientHello.SECP256R1, publicKey, null);
            out.writeByte(22);
            out.writeShort(0x0301);
            out.writeShort(count);
            out.write(hello.asSlice(0, count).toArray(ValueLayout.JAVA_BYTE)); // public only
            out.flush();

            MemorySegment serverRecord = record(in, arena);
            assertEquals(22, serverRecord.get(ValueLayout.JAVA_BYTE, 0));
            MemorySegment server = serverRecord.asSlice(5);
            assertEquals(Handshake.SERVER_HELLO, Handshake.type(server, 0));
            assertEquals(server.byteSize(), Handshake.totalLength(server, 0));
            assertEquals(-1, session.mismatch(server.asSlice(Handshake.sessionIdOffset(4), 32)));
            int suite = Handshake.cipherSuite(server, 4);
            assertTrue(suite == 0x1301 || suite == 0x1302);
            int[] length = new int[1];
            long start = Handshake.serverHelloExtensions(server, 4, length);
            boolean[] found = {false, false};
            Handshake.extensions(server, start, length[0], (type, at, size) -> {
                if (type == Handshake.EXTENSION_KEY_SHARE) {
                    assertFalse(found[0]);
                    long[] share = new long[2];
                    assertEquals(23, Handshake.serverKeyShare(server, at, share));
                    assertEquals(65, share[1]);
                    key.derive(server.asSlice(share[0], share[1]), secret.segment());
                    found[0] = true;
                } else if (type == Handshake.EXTENSION_SUPPORTED_VERSIONS) {
                    assertEquals(0x0304, Handshake.selectedVersion(server, at));
                    found[1] = true;
                }
            });
            assertTrue(found[0] && found[1]);
            MemorySegment encrypted = record(in, arena);
            if (encrypted.get(ValueLayout.JAVA_BYTE, 0) == 20) {
                assertEquals(6, encrypted.byteSize());
                assertEquals(1, encrypted.get(ValueLayout.JAVA_BYTE, 5));
                encrypted = record(in, arena); // compatibility ChangeCipherSpec, outside transcript
            }
            assertEquals(23, encrypted.get(ValueLayout.JAVA_BYTE, 0));
            HashAlgorithm hash = suite == 0x1302 ? HashAlgorithm.SHA_384 : HashAlgorithm.SHA_256;
            int keySize = suite == 0x1302 ? 32 : 16;
            MemorySegment plain = arena.allocate(16384);
            try (RecordProtection good = protection(hash, keySize, hello.asSlice(0, count), server, secret.segment())) {
                RecordProtection.Opened opened = good.open(encrypted, 0, (int) encrypted.byteSize(), plain, 0);
                assertNotNull(opened, "server AEAD tag must verify");
                assertEquals(22, opened.contentType());
                assertTrue(opened.length() >= 6);
                assertEquals(Handshake.ENCRYPTED_EXTENSIONS, Handshake.type(plain, 0));
                assertTrue(Handshake.totalLength(plain, 0) <= opened.length());
            }
            secret.segment().set(ValueLayout.JAVA_BYTE, 0,
                    (byte) (secret.segment().get(ValueLayout.JAVA_BYTE, 0) ^ 1));
            try (RecordProtection bad = protection(hash, keySize, hello.asSlice(0, count), server, secret.segment())) {
                plain.fill((byte) 0x5a);
                assertNull(bad.open(encrypted, 0, (int) encrypted.byteSize(), plain, 0),
                        "a one-bit error in ECDH must fail the same server record's tag");
                for (int i = 0; i < 16384; i++) assertEquals(0x5a, plain.get(ValueLayout.JAVA_BYTE, i));
            } finally {
                plain.fill((byte) 0);
            }
            System.err.println("[native P-256] PostgreSQL encrypted flight opens; one-bit ECDH control fails the tag");
        }
    }

    private static RecordProtection protection(HashAlgorithm hash, int keySize,
            MemorySegment client, MemorySegment server, MemorySegment shared) {
        int size = hash.digestLength();
        try (SecretScope material = SecretScope.allocate(size * 6);
                TranscriptHash transcript = new TranscriptHash(hash)) {
            MemorySegment zeros = material.segment().asSlice(0, size);
            MemorySegment emptyHash = material.segment().asSlice(size, size);
            MemorySegment early = material.segment().asSlice(size * 2L, size);
            MemorySegment derived = material.segment().asSlice(size * 3L, size);
            MemorySegment handshake = material.segment().asSlice(size * 4L, size);
            MemorySegment traffic = material.segment().asSlice(size * 5L, size);
            transcript.current(emptyHash, 0);
            Hkdf.extract(hash, zeros, zeros, early, 0);
            Hkdf.expandLabel(hash, early, "derived", emptyHash, derived, 0, size);
            Hkdf.extract(hash, derived, shared, handshake, 0);
            transcript.update(client, 0, (int) client.byteSize());
            transcript.update(server, 0, (int) server.byteSize());
            transcript.current(emptyHash, 0);
            Hkdf.expandLabel(hash, handshake, "s hs traffic", emptyHash, traffic, 0, size);
            return RecordProtection.fromSecret(hash, traffic, keySize);
        }
    }

    private static MemorySegment record(DataInputStream in, Arena arena) throws Exception {
        int type = in.readUnsignedByte();
        int version = in.readUnsignedShort();
        int length = in.readUnsignedShort();
        assertEquals(0x0303, version);
        assertTrue(length > 0 && length <= 16640);
        MemorySegment record = arena.allocate(length + 5);
        record.asByteBuffer().put((byte) type).putShort((short) version).putShort((short) length);
        byte[] wire = new byte[length]; // public plaintext Hello or encrypted bytes, never key material
        in.readFully(wire);
        MemorySegment.copy(wire, 0, record, ValueLayout.JAVA_BYTE, 5, length);
        return record;
    }
}
