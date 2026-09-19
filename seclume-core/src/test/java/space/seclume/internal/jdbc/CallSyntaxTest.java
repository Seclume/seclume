package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The escape syntax, in the forms applications really write it - with and
 * without braces, with and without an argument list, with a return value,
 * and with question marks that are not parameters.
 */
class CallSyntaxTest {

    @ParameterizedTest(name = "{0} -> {1}({2} parameters, returns={3})")
    @CsvSource({
            "'{call p}',                       p,        0, false",
            "'{call p()}',                     p,        0, false",
            "'{call p(?)}',                    p,        1, false",
            "'{call p(?, ?)}',                 p,        2, false",
            "'call p(?)',                      p,        1, false",
            "'  {  call   p ( ? )  }  ',       p,        1, false",
            "'{call schema.pkg.p(?)}',         schema.pkg.p, 1, false",
            "'{? = call f(?)}',                f,        1, true",
            "'{?=call f()}',                   f,        0, true",
            "'{ ? = call f(?, ?) }',           f,        2, true",
            "'CALL P(?)',                      P,        1, false",
    })
    void takesTheCallApart(String sql, String name, int parameters, boolean returns)
            throws SQLException {
        CallSyntax call = CallSyntax.parse(sql);
        assertEquals(name, call.name());
        assertEquals(parameters, call.parameters());
        assertEquals(returns, call.returnsValue());
        assertEquals(parameters + (returns ? 1 : 0), call.totalParameters());
    }

    /**
     * A question mark inside a literal is not a parameter. Counting it would
     * shift the numbering of every parameter after it - the value set as 2
     * would land on 3 - which is a wrong answer rather than an error.
     *
     * <p>Written as a method source and not as CSV: these cases are made of
     * quotes, and expressing them in a comma-separated string is how a test
     * ends up checking something other than what it says.
     */
    static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> literals() {
        return java.util.stream.Stream.of(
                org.junit.jupiter.params.provider.Arguments.of("{call p('a?b')}", 0),
                org.junit.jupiter.params.provider.Arguments.of("{call p('a?b', ?)}", 1),
                org.junit.jupiter.params.provider.Arguments.of("{call p(?, 'it''s ?')}", 1),
                org.junit.jupiter.params.provider.Arguments.of("{call p(\"od?d\", ?)}", 1),
                org.junit.jupiter.params.provider.Arguments.of("{call p(`w?t`, ?)}", 1),
                org.junit.jupiter.params.provider.Arguments.of("{call p(?) /* ? */}", 1),
                org.junit.jupiter.params.provider.Arguments.of("{call p(? /* ? */, ?)}", 2),
                org.junit.jupiter.params.provider.Arguments.of("{call p(coalesce(?, 0), ?)}", 2));
    }

    @ParameterizedTest(name = "{0} has {1} parameters")
    @MethodSource("literals")
    void doesNotCountQuestionMarksThatAreNotParameters(String sql, int parameters)
            throws SQLException {
        assertEquals(parameters, CallSyntax.parse(sql).parameters());
    }

    @Test
    void keepsTheArgumentTextForWhoeverNeedsIt() throws SQLException {
        CallSyntax call = CallSyntax.parse("{call p(?, 42, 'x')}");
        assertEquals("?, 42, 'x'", call.arguments());
        assertEquals(1, call.parameters());
    }

    @Test
    void aCommentedCallStillFindsItsParameters() throws SQLException {
        CallSyntax call = CallSyntax.parse("{call p(? -- one\n, ?)}");
        assertEquals(2, call.parameters());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "   ",
        "select 1",
        "{select 1}",
        "{call}",
        "{call p(?}",
        "{call p(?)",
        "{? call f()}",
        "{?x = call f()}",
        "calls p(?)",
    })
    void refusesWhatIsNotACall(String sql) {
        assertThrows(SQLException.class, () -> CallSyntax.parse(sql));
    }

    @Test
    void theRefusalSaysWhatACallLooksLike() {
        SQLException refused = assertThrows(SQLException.class, () -> CallSyntax.parse("select 1"));
        assertTrue(refused.getMessage().contains("{call p(?)}"), refused.getMessage());
    }

    @Test
    void aReturnValueCountsTowardsTheTotalButNotTowardsTheArguments() throws SQLException {
        CallSyntax call = CallSyntax.parse("{? = call f(?, ?)}");
        assertTrue(call.returnsValue());
        assertEquals(2, call.parameters());
        assertEquals(3, call.totalParameters());

        CallSyntax plain = CallSyntax.parse("{call p(?, ?)}");
        assertFalse(plain.returnsValue());
        assertEquals(2, plain.totalParameters());
    }

    @Test
    void rewritesPlaceholdersAndLeavesLiteralsAlone() throws SQLException {
        CallSyntax call = CallSyntax.parse("{call p(?, 'a?b', ?)}");
        assertEquals("@out1, 'a?b', @out2",
                call.argumentsWith(number -> "@out" + number));
        assertEquals("?, 'a?b', ?", call.argumentsWith(number -> "?"),
                "returning a question mark has to leave the list as it was");
    }

    @Test
    void rewritingNumbersThePlaceholdersFromOne() throws SQLException {
        CallSyntax call = CallSyntax.parse("{call p(?, ?, ?)}");
        assertEquals("1, 2, 3", call.argumentsWith(String::valueOf));
    }
}
