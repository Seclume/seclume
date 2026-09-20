package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * The query call, against a known answer.
 *
 * <p>The strongest check available without a server: build the message for the
 * same statement and compare byte for byte. Oracle answers
 * nearly every mistake by hanging up without a word, so a difference of one
 * byte here would cost an hour there.
 *
 * <p>The expectation follows {@code python-oracledb} 4.0.2 against Oracle
 * Free 23ai; see {@code PROVENANCE.md}.
 */
class TtcQueryTest {

    private static final String SQL = "select 42 as answer, 'abc' as text from dual";

    /** The message, without the packet header and data flags. */
    private static final String EXPECTED =
            "035E03000280610001012C01010D0000000102047FFFFFFF00000000000000"
            + "00000000010000000000000000000000000000002C73656C65637420343220"
            + "617320616E737765722C20276162632720617320746578742066726F6D2064"
            + "75616C0101000000000000010100028000000000";

    @Test
    void buildsTheSameBytesAsTheReferenceClient() {
        try (WireBuffer out = new WireBuffer(512)) {
            TtcQuery.put(out, 3, SQL, 2);
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < out.position(); i++) {
                hex.append(String.format("%02X", out.getByte(i)));
            }
            assertEquals(EXPECTED.toUpperCase(), hex.toString(),
                    "our query call differs from the expected one");
        }
    }
}
