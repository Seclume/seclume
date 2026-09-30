package space.seclume.tls;

import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Coverage-guided search behind the handshake: the records a server sends on
 * an established connection ({@link PostHandshakeRecords}) and a connection's
 * written-down state as another node hands it over ({@link FrozenConnections}).
 * Nightly under {@code JAZZER_FUZZ=1}; the deterministic samples run in every
 * build as {@code TlsRecordFuzzSampleTest}.
 */
class TlsRecordFuzzTest {

    @FuzzTest(maxDuration = "60s")
    void recordsAfterTheHandshake(byte[] input) throws Exception {
        if (!TestCertificates.available()) {
            return;
        }
        PostHandshakeRecords.run(input, EncryptedFlight.material());
    }

    @FuzzTest(maxDuration = "60s")
    void aFrozenConnection(byte[] input) {
        FrozenConnections.run(input);
    }
}
