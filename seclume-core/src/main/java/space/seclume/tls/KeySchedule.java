package space.seclume.tls;

import java.lang.foreign.MemorySegment;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hkdf;
import space.seclume.crypto.Hmac;
import space.seclume.secret.SecretScope;

/**
 * The TLS 1.3 key schedule (RFC 8446, section 7.1): the fixed chain of
 * HKDF-Extract and Derive-Secret that turns a (EC)DHE shared secret into every
 * traffic secret a connection needs, early to resumption.
 *
 * <p>{@link space.seclume.crypto.Hkdf} and its label encoding
 * are proven against RFC 8448 one call at a time (see {@code Rfc8448VectorsTest}).
 * What is easy to get wrong is not HKDF itself but the <b>order and inputs</b>
 * of the seven calls that chain into it - a step skipped or a wrong secret fed
 * into the next one still produces bytes that look like a perfectly good
 * secret. {@code KeySchedule} names the seven steps as seven methods, one per
 * arrow in the RFC's key-schedule diagram, and {@code KeyScheduleTest} replays
 * every named secret of RFC 8448's trace 3 - not the primitive, the whole
 * chain - to give a chained mistake somewhere to be caught.
 *
 * <pre>
 *          0
 *          |
 *          v
 *    PSK ->  HKDF-Extract = Early Secret
 *          |
 *          +-----&gt; Derive-Secret(., "derived", "")
 *          |                      |
 *          v                      v
 * (EC)DHE -&gt; HKDF-Extract = Handshake Secret
 *          |
 *          +-----&gt; Derive-Secret(., "c hs traffic", CH..SH)
 *          +-----&gt; Derive-Secret(., "s hs traffic", CH..SH)
 *          |
 *          +-----&gt; Derive-Secret(., "derived", "")
 *          |                      |
 *          v                      v
 *      0 -&gt; HKDF-Extract = Master Secret
 *          |
 *          +-----&gt; Derive-Secret(., "c ap traffic", CH..SF)
 *          +-----&gt; Derive-Secret(., "s ap traffic", CH..SF)
 *          +-----&gt; Derive-Secret(., "exp master",   CH..SF)
 *          +-----&gt; Derive-Secret(., "res master",   CH..CF)
 * </pre>
 *
 * <p>Every secret this class produces stays off-heap for its whole life, in
 * one {@link SecretScope}; nothing here ever returns a {@code byte[]}. A
 * caller that needs a record-layer key passes the relevant secret straight
 * into {@link RecordProtection#fromSecret}.
 */
public final class KeySchedule implements AutoCloseable {

    private final HashAlgorithm hash;
    private final int len;
    private final SecretScope material;

    private final MemorySegment zeros;
    private final MemorySegment emptyHash;
    private final MemorySegment early;
    private final MemorySegment derivedForHandshake;
    private final MemorySegment handshakeSecret;
    private final MemorySegment clientHandshakeTraffic;
    private final MemorySegment serverHandshakeTraffic;
    private final MemorySegment derivedForMaster;
    private final MemorySegment masterSecret;
    private final MemorySegment clientApplicationTraffic;
    private final MemorySegment serverApplicationTraffic;
    private final MemorySegment exporterMasterSecret;
    private final MemorySegment resumptionMasterSecret;

    private KeySchedule(HashAlgorithm hash, MemorySegment psk) {
        this.hash = hash;
        this.len = hash.digestLength();
        this.material = SecretScope.allocate(len * 13);
        MemorySegment m = material.segment();
        material.length((int) m.byteSize());

        int at = 0;
        zeros = m.asSlice(at, len); at += len;
        emptyHash = m.asSlice(at, len); at += len;
        early = m.asSlice(at, len); at += len;
        derivedForHandshake = m.asSlice(at, len); at += len;
        handshakeSecret = m.asSlice(at, len); at += len;
        clientHandshakeTraffic = m.asSlice(at, len); at += len;
        serverHandshakeTraffic = m.asSlice(at, len); at += len;
        derivedForMaster = m.asSlice(at, len); at += len;
        masterSecret = m.asSlice(at, len); at += len;
        clientApplicationTraffic = m.asSlice(at, len); at += len;
        serverApplicationTraffic = m.asSlice(at, len); at += len;
        exporterMasterSecret = m.asSlice(at, len); at += len;
        resumptionMasterSecret = m.asSlice(at, len); at += len;

        hash.hash(zeros, 0, 0, emptyHash, 0);           // Hash("")
        MemorySegment ikm = psk != null ? psk : zeros;   // no PSK => 0-filled IKM
        Hkdf.extract(hash, zeros, ikm, early, 0);
    }

    /** A schedule for a handshake without a pre-shared key - the only kind this driver offers so far. */
    public static KeySchedule withoutPsk(HashAlgorithm hash) {
        return new KeySchedule(hash, null);
    }

    /**
     * Handshake Secret = HKDF-Extract(Derive-Secret(Early Secret, "derived", ""), (EC)DHE).
     *
     * <p>Call once, after the (EC)DHE shared secret is known.
     */
    public void deriveHandshakeSecret(MemorySegment sharedSecret) {
        Hkdf.expandLabel(hash, early, "derived", emptyHash, derivedForHandshake, 0, len);
        Hkdf.extract(hash, derivedForHandshake, sharedSecret, handshakeSecret, 0);
    }

    /**
     * The two handshake traffic secrets, over the transcript hash of
     * ClientHello through ServerHello.
     */
    public void deriveHandshakeTrafficSecrets(MemorySegment transcriptHelloToHello) {
        Hkdf.expandLabel(hash, handshakeSecret, "c hs traffic", transcriptHelloToHello,
                clientHandshakeTraffic, 0, len);
        Hkdf.expandLabel(hash, handshakeSecret, "s hs traffic", transcriptHelloToHello,
                serverHandshakeTraffic, 0, len);
    }

    /**
     * Master Secret = HKDF-Extract(Derive-Secret(Handshake Secret, "derived", ""), 0).
     *
     * <p>Call once, any time after {@link #deriveHandshakeSecret}; it does not
     * depend on the transcript.
     */
    public void deriveMasterSecret() {
        Hkdf.expandLabel(hash, handshakeSecret, "derived", emptyHash, derivedForMaster, 0, len);
        Hkdf.extract(hash, derivedForMaster, zeros, masterSecret, 0);
    }

    /**
     * The two application traffic secrets and the exporter master secret, over
     * the transcript hash of ClientHello through the server's Finished.
     */
    public void deriveApplicationTrafficSecrets(MemorySegment transcriptHelloToServerFinished) {
        Hkdf.expandLabel(hash, masterSecret, "c ap traffic", transcriptHelloToServerFinished,
                clientApplicationTraffic, 0, len);
        Hkdf.expandLabel(hash, masterSecret, "s ap traffic", transcriptHelloToServerFinished,
                serverApplicationTraffic, 0, len);
        Hkdf.expandLabel(hash, masterSecret, "exp master", transcriptHelloToServerFinished,
                exporterMasterSecret, 0, len);
    }

    /**
     * The resumption master secret, over the transcript hash of ClientHello
     * through the client's own Finished.
     */
    public void deriveResumptionMasterSecret(MemorySegment transcriptHelloToClientFinished) {
        Hkdf.expandLabel(hash, masterSecret, "res master", transcriptHelloToClientFinished,
                resumptionMasterSecret, 0, len);
    }

    // ---- accessors: each returns a live view into the one scope above -----

    public MemorySegment clientHandshakeTrafficSecret() {
        return clientHandshakeTraffic;
    }

    public MemorySegment serverHandshakeTrafficSecret() {
        return serverHandshakeTraffic;
    }

    public MemorySegment clientApplicationTrafficSecret() {
        return clientApplicationTraffic;
    }

    public MemorySegment serverApplicationTrafficSecret() {
        return serverApplicationTraffic;
    }

    public MemorySegment exporterMasterSecret() {
        return exporterMasterSecret;
    }

    public MemorySegment resumptionMasterSecret() {
        return resumptionMasterSecret;
    }

    /** Exposed for a future PSK binder / resumption path; not needed by the handshake itself. */
    public MemorySegment masterSecret() {
        return masterSecret;
    }

    /**
     * The Finished key for one side (RFC 8446, section 4.4.4): a plain
     * {@code HKDF-Expand-Label} of that side's handshake traffic secret, no
     * context. Not stored on the schedule because both sides derive it from
     * their own secret at a different point in the handshake - the caller
     * owns the output's lifetime.
     */
    public void finishedKey(MemorySegment handshakeTrafficSecret, MemorySegment out) {
        Hkdf.expandLabel(hash, handshakeTrafficSecret, "finished", null, out, 0, len);
    }

    /**
     * {@code verify_data = HMAC(finished_key, transcript_hash)} - the value
     * both the Finished message and its verification compute.
     */
    public void verifyData(MemorySegment finishedKey, MemorySegment transcriptHash,
            MemorySegment out) {
        try (Hmac hmac = new Hmac(hash, finishedKey)) {
            hmac.update(transcriptHash);
            hmac.doFinal(out, 0);
        }
    }

    public HashAlgorithm hash() {
        return hash;
    }

    public int length() {
        return len;
    }

    @Override
    public void close() {
        material.close();
    }
}
