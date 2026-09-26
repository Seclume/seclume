package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.sql.SQLException;
import java.util.List;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import space.seclume.QueryFingerprint;

/**
 * Coverage-guided fuzzing of the parsers that read statement text an
 * application hands in - every one of them runs on every statement, so an
 * exception out of one is an outage, not a bad input.
 *
 * <p>An ordinary build replays the saved inputs (and an empty one);
 * {@code JAZZER_FUZZ=1 mvn test -Dtest=TextParsersFuzzTest} searches for new
 * ones, guided by what code they reach.
 */
class TextParsersFuzzTest {

    /** The fingerprint names every statement, whatever it is; it never throws. */
    @FuzzTest(maxDuration = "30s")
    void aFingerprintIsAlwaysMade(String sql) {
        QueryFingerprint.of(sql);
    }

    /** Placeholders: never throws, and the offsets are exactly the ones counted. */
    @FuzzTest(maxDuration = "30s")
    void placeholderOffsetsMatchTheCount(String sql) {
        if (sql == null) {
            return;                 // the drivers refuse a null statement before this
        }
        int[] offsets = CallSyntax.placeholderOffsets(sql);
        assertEquals(CallSyntax.placeholders(sql), offsets.length);
        for (int offset : offsets) {
            assertEquals('?', sql.charAt(offset));
        }
    }

    /** Session state is noted from any text without an exception. */
    @FuzzTest(maxDuration = "30s")
    void sessionStateReadsAnyText(String sql) {
        new SessionState().note(sql);           // null included: noted as nothing
    }

    /**
     * A list bound to any placeholder of any text: either the text comes back
     * rewritten with the same number of placeholders, or an SQLException says
     * why not - nothing else.
     */
    @FuzzTest(maxDuration = "30s")
    void inListsRewriteOrRefuse(FuzzedDataProvider data) {
        String sql = data.consumeString(400);
        int index = data.consumeInt(1, 4);
        List<Object> list = data.consumeBoolean()
                ? List.of(data.consumeLong(), data.consumeLong())
                : List.of(data.consumeString(20), data.consumeString(20));
        for (InLists.Dialect dialect : InLists.Dialect.values()) {
            try {
                InLists.Bound[] lists = InLists.note(null, index, InLists.of(list, dialect));
                String rewritten = InLists.apply(sql, lists, dialect);
                assertEquals(CallSyntax.placeholders(sql), CallSyntax.placeholders(rewritten),
                        "the rewrite changed the number of placeholders");
            } catch (SQLException refused) {
                // a list where it cannot go - said, not thrown past
            }
        }
    }
}
