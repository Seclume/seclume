package space.seclume.kafka;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.internal.Scram;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;

/**
 * One SCRAM login (RFC 5802) as a {@link SaslClient}: client-first, then the
 * client-final with the proof, then the server's signature checked.
 *
 * <p>The password is read from its provider into native memory when the
 * server's first message has arrived, turned into the proof, and wiped -
 * before the proof leaves. What Kafka gets back are the protocol messages,
 * and the only one derived from the password is the proof: bound to this
 * login's nonces, useless for another, and no way back to the password.
 */
final class ScramClient implements SaslClient {

    private enum State { FIRST, FINAL, VERIFY, COMPLETE, FAILED }

    private final String mechanism;
    private final String username;
    private final SecretProvider provider;
    private final Scram scram;
    private State state = State.FIRST;

    ScramClient(String mechanism, HashAlgorithm algorithm, String username,
                SecretProvider provider) {
        this.mechanism = mechanism;
        this.username = username;
        this.provider = provider;
        this.scram = new Scram(algorithm, 24, true);
    }

    @Override
    public String getMechanismName() {
        return mechanism;
    }

    @Override
    public boolean hasInitialResponse() {
        return true;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        try (Arena arena = Arena.ofConfined()) {
            switch (state) {
                case FIRST -> {
                    MemorySegment out = arena.allocate(64 + 9L * username.length());
                    int length = scram.clientFirst(out, username);
                    state = State.FINAL;
                    return bytes(out, length);
                }
                case FINAL -> {
                    MemorySegment in = copy(arena, challenge);
                    scram.serverFirst(in, 0, challenge.length);
                    MemorySegment out = arena.allocate(challenge.length + 256L);
                    int length;
                    try (SecretScope password = SecretScope.fromProvider(provider)) {
                        length = scram.clientFinal(out, password.secret());
                    }
                    state = State.VERIFY;
                    return bytes(out, length);
                }
                case VERIFY -> {
                    MemorySegment in = copy(arena, challenge);
                    scram.verifyServerFinal(in, 0, challenge.length);
                    state = State.COMPLETE;
                    return null;
                }
                default -> throw new SaslException("SCRAM is " + state.name().toLowerCase()
                        + " - no challenge expected");
            }
        } catch (IllegalStateException | IllegalArgumentException
                 | space.seclume.secret.SecretUnavailableException e) {
            state = State.FAILED;
            throw new SaslException(mechanism + " login of " + username + " failed: "
                    + e.getMessage(), e);
        }
    }

    @Override
    public boolean isComplete() {
        return state == State.COMPLETE;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
        throw new IllegalStateException("SCRAM has no security layer");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
        throw new IllegalStateException("SCRAM has no security layer");
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (!isComplete()) {
            throw new IllegalStateException("the SCRAM login has not completed");
        }
        return null;
    }

    @Override
    public void dispose() {
        scram.close();
    }

    private static MemorySegment copy(Arena arena, byte[] message) {
        MemorySegment segment = arena.allocate(Math.max(1, message.length));
        MemorySegment.copy(message, 0, segment, ValueLayout.JAVA_BYTE, 0, message.length);
        return segment;
    }

    private static byte[] bytes(MemorySegment segment, int length) {
        return segment.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
    }
}
