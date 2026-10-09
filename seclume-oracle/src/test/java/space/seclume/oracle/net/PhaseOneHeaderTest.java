package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * The header of the first login step: type, function, sequence, then the
 * token number - except inside FAST_AUTH, which goes out before any field
 * version is agreed and which 23ai answers with a MARKER when it has one.
 */
class PhaseOneHeaderTest {

    @Test
    void onItsOwnTheCallCarriesAToken() {
        try (WireBuffer out = new WireBuffer(256)) {
            TtcAuth.putPhaseOne(out, "scott", true);
            assertEquals(TtcMessage.TYPE_FUNCTION, out.getByte(0));
            assertEquals(TtcMessage.FUNC_AUTH_PHASE_ONE, out.getByte(1) & 0xff);
            assertEquals(1, out.getByte(2), "sequence");
            assertEquals(0, out.getByte(3), "token number");
            assertEquals(1, out.getByte(4), "a user follows");
        }
    }

    @Test
    void insideFastAuthItDoesNot() {
        try (WireBuffer out = new WireBuffer(256)) {
            TtcAuth.putPhaseOne(out, "scott", false);
            assertEquals(1, out.getByte(2), "sequence");
            assertEquals(1, out.getByte(3), "a user follows");
        }
    }
}
