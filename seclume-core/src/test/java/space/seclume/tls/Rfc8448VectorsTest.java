package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hkdf;

/**
 * The key schedule against the published traces of RFC 8448.
 *
 * <p>This is the outside anchor the rest of the TLS work rests on. Everything
 * else here can only be checked against the specification as somebody read it,
 * and a misreading is invisible: HKDF produces bytes that look perfectly random
 * whether or not they are the right ones, and the first sign of a wrong answer
 * would be a server closing the connection with no explanation. RFC 8448 prints
 * a complete handshake with every intermediate value, so a wrong answer is
 * visible immediately and names itself.
 *
 * <p><b>The vectors are not typed.</b> {@code tools/rfc8448_vectors.py} parses
 * them out of the RFC text into {@code rfc8448-vectors.txt}; 186 of them,
 * across all five traces - secrets, key material, encrypted records, handshake
 * messages and the ephemeral public keys. A hand-copied vector that is wrong in
 * one nibble fails in a way that looks like a bug in the code it is meant to
 * check, and the hours that costs have been paid once already on the Oracle
 * work.
 *
 * <p>Every expand vector is checked <b>twice</b>, and the split is the point:
 * once through {@link Hkdf#expand} with the {@code info} structure the RFC
 * itself prints, and once through {@link Hkdf#expandLabel}, which builds that
 * structure. If only the second fails, the label encoding is wrong - the u16
 * length, the {@code "tls13 "} prefix, one of the one-byte prefixes. If both
 * fail, HKDF itself is. One test would have conflated the two.
 */
class Rfc8448VectorsTest {

    private static final HexFormat HEX = HexFormat.of();

    /** One line of the generated resource. */
    record Vector(String kind, String section, String name, List<String> fields) {

        byte[] at(int index) {
            return HEX.parseHex(fields.get(index));
        }

        @Override
        public String toString() {
            String extra = kind.equals("message") ? " " + fields.get(0) : "";
            return "section " + section + " " + name + extra;   // what a failure is called
        }
    }

    // ---- the vectors ------------------------------------------------------

    private static List<Vector> load(String kind) {
        List<Vector> out = new ArrayList<>();
        try (InputStream in = Rfc8448VectorsTest.class
                .getResourceAsStream("/rfc8448-vectors.txt")) {
            assertTrue(in != null, "rfc8448-vectors.txt is not on the test classpath - "
                    + "run tools/rfc8448_vectors.py");
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\t", -1);
                if (!parts[0].equals(kind)) {
                    continue;
                }
                out.add(new Vector(parts[0], parts[1], parts[2],
                        List.of(parts).subList(3, parts.length)));
            }
        } catch (IOException e) {
            throw new AssertionError("cannot read the vectors", e);
        }
        assertTrue(!out.isEmpty(), "no " + kind + " vectors were loaded");
        return out;
    }

    static Stream<Vector> extractVectors() {
        return load("extract").stream();
    }

    static Stream<Vector> expandVectors() {
        return load("expand").stream();
    }

    static Stream<Vector> keyVectors() {
        return load("keys").stream();
    }

    /** Only the encrypted ones; a ClientHello is not a test of this. */
    static Stream<Vector> encryptedRecordVectors() {
        return load("record").stream()
                .filter(v -> v.fields().get(1).startsWith("17"));
    }

    static Stream<Vector> messageVectors() {
        return load("message").stream();
    }

    static Stream<Vector> serverHelloVectors() {
        return load("message").stream().filter(v -> messageType(v).equals("ServerHello"));
    }

    /** A message row carries the speaker in the name column and the type here. */
    private static String messageType(Vector vector) {
        return vector.fields().get(0);
    }

    // ---- the tests --------------------------------------------------------

    /**
     * {@code HKDF-Extract(salt, IKM)}, salt and all.
     *
     * <p>A salt the RFC prints as "0 (all zero octets)" arrives here empty and
     * becomes a hash length of zeroes, which is what RFC 5869 says an absent
     * salt means - and what HMAC's key padding makes equivalent anyway.
     */
    @ParameterizedTest(name = "extract {0}")
    @MethodSource("extractVectors")
    void extractMatchesTheTrace(Vector vector) {
        byte[] salt = vector.at(0);
        byte[] ikm = vector.at(1);
        byte[] expected = vector.at(2);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(expected.length);
            Hkdf.extract(HashAlgorithm.SHA_256,
                    of(arena, salt.length == 0 ? new byte[32] : salt),
                    of(arena, ikm), out, 0);
            assertArrayEquals(expected, bytes(out, expected.length));
        }
    }

    /** {@code HKDF-Expand} against the info structure the RFC prints. */
    @ParameterizedTest(name = "expand {0}")
    @MethodSource("expandVectors")
    void expandMatchesTheTrace(Vector vector) {
        byte[] prk = vector.at(0);
        byte[] info = vector.at(2);
        byte[] expected = vector.at(3);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(expected.length);
            Hkdf.expand(HashAlgorithm.SHA_256, of(arena, prk), of(arena, info), out, 0,
                    expected.length);
            assertArrayEquals(expected, bytes(out, expected.length));
        }
    }

    /**
     * And {@code HKDF-Expand-Label}, which has to build that same structure.
     *
     * <p>The context is usually a transcript hash, but not always: the
     * resumption secret takes a two-byte ticket nonce, and that one vector is
     * the only thing here that would catch an implementation which assumed the
     * context is always a digest.
     */
    @ParameterizedTest(name = "expandLabel {0}")
    @MethodSource("expandVectors")
    void expandLabelBuildsTheSameInfo(Vector vector) {
        byte[] prk = vector.at(0);
        byte[] context = vector.at(1);
        byte[] expected = vector.at(3);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(expected.length);
            Hkdf.expandLabel(HashAlgorithm.SHA_256, of(arena, prk), vector.name(),
                    context.length == 0 ? null : of(arena, context), out, 0, expected.length);
            assertArrayEquals(expected, bytes(out, expected.length),
                    "label \"" + vector.name() + "\" - the info structure disagrees with the "
                            + "trace; expand itself passing means the encoding is at fault");
        }
    }

    /**
     * The record layer's key and IV, anchored against published key material.
     *
     * <p>{@code RecordProtectionTest} could only check the construction against
     * the specification as read, because it had no outside key to check it
     * with. These vectors are that key: the RFC prints the traffic secret and
     * the key and IV derived from it, so a record sealed from the secret by
     * {@link RecordProtection} must equal one built from the published key and
     * IV with the JDK's cipher. Derivation, nonce, additional data and the
     * inner content type are all in the comparison at once.
     */
    @ParameterizedTest(name = "record keys {0}")
    @MethodSource("keyVectors")
    void theRecordKeysComeFromTheTrafficSecret(Vector vector) throws Exception {
        byte[] trafficSecret = vector.at(0);
        byte[] key = vector.at(1);
        byte[] iv = vector.at(2);
        byte[] payload = HEX.parseHex("0102030405060708090a0b0c0d0e0f10");

        byte[] ours;
        try (Arena arena = Arena.ofConfined()) {
            try (RecordProtection protection = RecordProtection.fromSecret(
                    HashAlgorithm.SHA_256, of(arena, trafficSecret), key.length)) {
                MemorySegment out =
                        arena.allocate(RecordProtection.sealedLength(payload.length));
                int written = protection.seal((byte) 23, of(arena, payload), 0, payload.length,
                        out, 0);
                ours = bytes(out, written);
            }
        }

        int body = payload.length + 1 + 16;
        byte[] header = {23, 3, 3, (byte) (body >>> 8), (byte) body};
        byte[] inner = new byte[payload.length + 1];
        System.arraycopy(payload, 0, inner, 0, payload.length);
        inner[payload.length] = 23;
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, iv));     // sequence 0: the nonce is the IV
        cipher.updateAAD(header);
        byte[] sealed = cipher.doFinal(inner);

        byte[] expected = new byte[header.length + sealed.length];
        System.arraycopy(header, 0, expected, 0, header.length);
        System.arraycopy(sealed, 0, expected, header.length, sealed.length);
        assertArrayEquals(expected, ours);
    }

    /**
     * A record somebody else produced, opened by ours.
     *
     * <p>This is the thing {@code RecordProtectionTest} names as missing. Every
     * check there rebuilds the record from the same reading of the
     * specification that the code was written from, so a misreading agrees with
     * itself and passes. RFC 8448 prints, for every record of five complete
     * handshakes, the plaintext beside the encrypted bytes that went on the
     * wire - produced by an implementation that never saw this code. If the
     * construction here is wrong in any detail, none of them open.
     *
     * <p>Which traffic key and which sequence number belong to a given record
     * is a question about the handshake state machine, which does not exist
     * yet. So the test tries every key the same trace publishes at the first
     * few sequence numbers and requires one to fit. That is not a weakening:
     * AEAD is what makes it sound, because a wrong key or a wrong counter does
     * not produce wrong plaintext, it fails the tag. A match is therefore proof
     * and not a coincidence - and an implementation that ignored the sequence
     * number entirely would still fail every record after the first in its
     * direction.
     */
    @ParameterizedTest(name = "open {0}")
    @MethodSource("encryptedRecordVectors")
    void aRecordFromAnotherImplementationOpens(Vector vector) {
        byte[] payload = vector.at(0);
        byte[] record = vector.at(1);
        List<Vector> keys = load("keys").stream()
                .filter(k -> k.section().equals(vector.section()))
                .toList();

        String found = null;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment wire = of(arena, record);
            MemorySegment out = arena.allocate(Math.max(payload.length, 1));
            for (Vector key : keys) {
                for (long sequence = 0; sequence < 8 && found == null; sequence++) {
                    try (RecordProtection protection = RecordProtection.fromSecret(
                            HashAlgorithm.SHA_256, of(arena, key.at(0)), key.at(1).length)) {
                        protection.sequence(sequence);
                        RecordProtection.Opened opened =
                                protection.open(wire, 0, record.length, out, 0);
                        if (opened == null) {
                            continue;
                        }
                        assertArrayEquals(payload, bytes(out, opened.length()),
                                "the tag matched but the plaintext is not what the trace says - "
                                        + "the padding or the inner content type is misread");
                        found = key.name() + " at sequence " + sequence;
                    }
                }
            }
        }
        assertTrue(found != null,
                "no published key of this trace opens the record - the nonce, the additional "
                        + "data or the key derivation disagrees with a real implementation");
    }

    /**
     * The framing of forty messages encoded by somebody else.
     *
     * <p>Small, and the point is that it is not circular: the type byte has to
     * be the one the RFC's prose calls the message, and the three-byte length
     * has to account for exactly the bytes that are there. A parser that read
     * the length as two bytes or four passes neither.
     */
    @ParameterizedTest(name = "frame {0}")
    @MethodSource("messageVectors")
    void theFramingOfEveryMessageIsRead(Vector vector) {
        byte[] message = vector.at(1);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = of(arena, message);
            assertEquals(typeOf(messageType(vector)), Handshake.type(data, 0),
                    "the type byte is not the message the RFC says this is");
            if (messageType(vector).endsWith("-truncated")) {
                // The ClientHello a PSK binder is computed over: the header
                // already counts the binders, the bytes stop before them. Not
                // an exception made for a failing test - the RFC prints the
                // whole message a block later, and this shape is the one the
                // binder covers.
                assertTrue(Handshake.totalLength(data, 0) > message.length,
                        "a truncated ClientHello whose header does not claim more than it "
                                + "carries is not truncated at all");
                return;
            }
            assertEquals(message.length, Handshake.totalLength(data, 0),
                    "the three-byte length does not account for the message");
        }
    }

    /**
     * A ServerHello parsed down to the version it really selected.
     *
     * <p>The header says 0x0303 in every one of these, which is TLS 1.2 and is
     * a lie the protocol tells on purpose. The truth is in
     * {@code supported_versions}, and a client that reads the header instead
     * negotiates itself down while the server thinks it agreed to 1.3.
     */
    @ParameterizedTest(name = "ServerHello {0}")
    @MethodSource("serverHelloVectors")
    void aServerHelloSaysTwelveAndMeansThirteen(Vector vector) {
        byte[] message = vector.at(1);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = of(arena, message);
            long body = Handshake.HEADER;
            assertEquals(Handshake.LEGACY_VERSION, Handshake.u16(data, body),
                    "the legacy version in the header");

            int[] extensionsLength = new int[1];
            long extensions = Handshake.serverHelloExtensions(data, body, extensionsLength);
            assertTrue(extensionsLength[0] > 0, "a ServerHello without extensions");
            assertEquals(message.length, extensions + extensionsLength[0],
                    "the extensions do not end where the message does - the session id or "
                            + "the compression byte is being skipped wrongly");

            int[] selected = {0};
            Handshake.extensions(data, extensions, extensionsLength[0], (type, at, length) -> {
                if (type == Handshake.EXTENSION_SUPPORTED_VERSIONS) {
                    selected[0] = Handshake.selectedVersion(data, at);
                }
            });
            assertEquals(0x0304, selected[0], "the selected version is not TLS 1.3");
        }
    }

    /**
     * And the key share in a Hello is the key the trace published separately.
     *
     * <p>This is the cross-check worth having: the public key comes out of the
     * "create an ephemeral key pair" block and the key share out of the encoded
     * message, two extractions that never meet. If the extension walk is off by
     * the two bytes of the group, or reads a client's list shape where a server
     * sends a bare entry, the thirty-two bytes do not match anything.
     *
     * <p>A HelloRetryRequest is skipped rather than fudged: its key_share
     * carries only the group it wants and no key at all, so there is nothing
     * here to compare.
     */
    @ParameterizedTest(name = "key share {0}")
    @MethodSource("serverHelloVectors")
    void theServersKeyShareIsThePublishedPublicKey(Vector vector) {
        byte[] message = vector.at(1);
        List<String> published = load("keypair").stream()
                .filter(k -> k.section().equals(vector.section()))
                .map(k -> k.fields().get(0))
                .toList();

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = of(arena, message);
            int[] extensionsLength = new int[1];
            long extensions =
                    Handshake.serverHelloExtensions(data, Handshake.HEADER, extensionsLength);
            String[] share = {null};
            Handshake.extensions(data, extensions, extensionsLength[0], (type, at, length) -> {
                if (type == Handshake.EXTENSION_KEY_SHARE && length > 2) {
                    long[] where = new long[2];
                    Handshake.serverKeyShare(data, at, where);
                    share[0] = HEX.formatHex(bytes(data.asSlice(where[0]), (int) where[1]));
                }
            });
            if (share[0] == null) {
                return;                       // a HelloRetryRequest; nothing to compare
            }
            assertTrue(published.contains(share[0]),
                    "the key share in the ServerHello is not any public key this trace "
                            + "published - the extension walk or the entry shape is wrong");
        }
    }

    /**
     * The transcript hash ties the messages to the key schedule.
     *
     * <p>The two halves of this file have been independent until now: the
     * handshake messages on one side, the {@code hash} field of every
     * {@code Derive-Secret} on the other, extracted from different blocks of
     * the RFC by different branches of the same script. They meet here. If
     * {@link TranscriptHash} feeds the messages in the right order, with their
     * four-byte headers included and the record framing excluded, then the
     * digest after ServerHello <b>is</b> the context of {@code c hs traffic},
     * the digest after the server's Finished is the context of
     * {@code c ap traffic}, and so on. Nothing here is asserted about where a
     * given hash should appear; what is asserted is that every context the key
     * schedule used turns up somewhere in the running transcript, which cannot
     * happen by accident.
     *
     * <p>Two shapes the specification demands and this checks by including
     * them: the digest of an <b>empty</b> transcript, which is the context of
     * every {@code derived} step, and the {@code message_hash} substitution
     * after a HelloRetryRequest, without which section 5 agrees with nothing
     * after its second ServerHello.
     *
     * <p><b>Section 4 is left out, and why.</b> Its transcript needs the
     * ClientHello <i>with</i> its PSK binders, and the block the extractor
     * takes messages from holds the truncated one the binder is computed over.
     * The complete message is in the trace, inside a record, and reaching it
     * means reassembling records - which belongs to milestone 4, not here.
     */
    @ParameterizedTest(name = "transcript of section {0}")
    @ValueSource(strings = {"3", "5", "6", "7"})
    void theTranscriptReproducesTheKeyScheduleContexts(String section) {
        List<Vector> messages = load("message").stream()
                .filter(v -> v.section().equals(section))
                .toList();
        // Only the contexts that are a digest; the resumption secret's is a
        // two-byte ticket nonce and belongs to no transcript.
        List<String> wanted = load("expand").stream()
                .filter(v -> v.section().equals(section))
                .map(v -> v.fields().get(1))
                .filter(context -> context.length() == 64)
                .distinct()
                .toList();
        assertTrue(wanted.size() >= 3, "too few contexts to be worth asserting");

        // A second ClientHello is what a HelloRetryRequest leaves behind. A
        // real client recognises one by the ServerHello's random; a test over
        // a published trace may recognise it by its shape.
        boolean retried = messages.stream()
                .filter(v -> messageType(v).startsWith("ClientHello")).count() > 1;

        List<String> running = new ArrayList<>();
        try (Arena arena = Arena.ofConfined();
             TranscriptHash transcript = new TranscriptHash(HashAlgorithm.SHA_256)) {
            MemorySegment digest = arena.allocate(32);
            transcript.current(digest, 0);
            running.add(HEX.formatHex(bytes(digest, 32)));      // the empty transcript

            boolean substituted = false;
            for (Vector message : messages) {
                if (retried && !substituted && !messageType(message).startsWith("ClientHello")) {
                    transcript.substituteWithMessageHash();
                    substituted = true;
                }
                byte[] bytes = message.at(1);
                transcript.update(of(arena, bytes), 0, bytes.length);
                transcript.current(digest, 0);
                running.add(HEX.formatHex(bytes(digest, 32)));
            }
        }

        for (String context : wanted) {
            assertTrue(running.contains(context),
                    "no point in the transcript produces the context " + context.substring(0, 16)
                            + "... that the key schedule of section " + section + " used");
        }
    }

    /**
     * The resource is what the extractor produced, and all of it arrived.
     *
     * <p>A parser that silently stopped at the first page break would leave a
     * handful of vectors that all pass, and every test above would be green
     * while checking a fraction of what it claims to. So the count is asserted,
     * and so is the presence of the awkward one.
     */
    @Test
    void everyVectorFromTheRfcIsHere() {
        assertArrayEquals(new int[] {15, 58, 21, 41, 40, 11},
                new int[] {load("extract").size(), load("expand").size(), load("keys").size(),
                    load("record").size(), load("message").size(), load("keypair").size()},
                "the vector file does not hold what tools/rfc8448_vectors.py produced");
        assertTrue(load("expand").stream().anyMatch(v -> v.name().equals("resumption")),
                "the ticket-nonce vector is missing - it is the only non-digest context");
        assertEquals(27, encryptedRecordVectors().count(),
                "the encrypted records are the ones that exercise the record layer");
    }

    // ---- the small machinery ---------------------------------------------

    /** The handshake type the RFC's prose gives each message. */
    private static int typeOf(String name) {
        return switch (name) {
            case "ClientHello", "ClientHello-truncated" -> Handshake.CLIENT_HELLO;
            case "ServerHello" -> Handshake.SERVER_HELLO;
            case "NewSessionTicket" -> Handshake.NEW_SESSION_TICKET;
            case "EndOfEarlyData" -> Handshake.END_OF_EARLY_DATA;
            case "EncryptedExtensions" -> Handshake.ENCRYPTED_EXTENSIONS;
            case "Certificate" -> Handshake.CERTIFICATE;
            case "CertificateRequest" -> Handshake.CERTIFICATE_REQUEST;
            case "CertificateVerify" -> Handshake.CERTIFICATE_VERIFY;
            case "Finished" -> Handshake.FINISHED;
            default -> throw new AssertionError("the extractor produced an unknown "
                    + "message name: " + name);
        };
    }

    private static MemorySegment of(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(bytes.length, 1));
        if (bytes.length > 0) {
            MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        }
        return segment;
    }

    private static byte[] bytes(MemorySegment segment, int length) {
        byte[] out = new byte[length];
        MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, 0, out, 0, length);
        return out;
    }
}
