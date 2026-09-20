package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The name-to-position rules, without a server.
 *
 * <p>Every one of the four drivers asks its catalog a question of its own and
 * then hands the answer here, so a fault in this class is a fault in all four
 * at once - which is the reason it is worth testing on its own rather than
 * only through the live tests that already cover the ordinary case.
 */
class ParameterNamesTest {

    @Test
    void countsFromOneAndIgnoresCase() throws SQLException {
        ParameterNames names = new ParameterNames(List.of("base", "less", "answer"), false);
        assertEquals(1, names.indexOf("BASE"));
        assertEquals(2, names.indexOf("less"));
        assertEquals(3, names.indexOf("Answer"));
    }

    /** A function's return value is parameter 1, so everything declared shifts by one. */
    @Test
    void aReturnValueShiftsEveryPosition() throws SQLException {
        ParameterNames names = new ParameterNames(List.of("n"), true);
        assertEquals(2, names.indexOf("n"));
    }

    /** Oracle writes a bind {@code :n} and SQL Server {@code @n}; both mean the name. */
    @Test
    void aLeadingMarkerIsNotPartOfTheName() throws SQLException {
        ParameterNames declared = new ParameterNames(List.of("@answer"), false);
        assertEquals(1, declared.indexOf("answer"));
        assertEquals(1, declared.indexOf(":answer"));
        assertEquals(1, new ParameterNames(List.of("answer"), false).indexOf("@answer"));
    }

    /** The message names what there is, because the reader would otherwise go to the catalog. */
    @Test
    void anUnknownNameIsRefusedWithTheNamesThatExist() {
        ParameterNames names = new ParameterNames(List.of("base", "answer"), false);
        SQLException refused = assertThrows(SQLException.class, () -> names.indexOf("nope"));
        assertTrue(refused.getMessage().contains("base at 1")
                && refused.getMessage().contains("answer at 2"), refused.getMessage());
    }

    @Test
    void aNameThatStandsForTwoParametersIsRefusedRatherThanGuessed() {
        ParameterNames names = new ParameterNames(List.of("n", "N"), false);
        SQLException refused = assertThrows(SQLException.class, () -> names.indexOf("n"));
        assertTrue(refused.getMessage().contains("twice"), refused.getMessage());
    }

    // ---- reading a catalog answer ------------------------------------------

    @Test
    void readsOneProceduresParametersInTheOrderTheyArrive() throws SQLException {
        ResultSet rows = catalog(new String[][] {
                {"p", "base"}, {"p", "less"}, {"p", "answer"}});
        ParameterNames names = ParameterNames.fromCatalog(rows, 3, false);
        assertEquals(3, names.size());
        assertEquals(2, names.indexOf("less"));
    }

    /**
     * Two procedures of one name: the one whose argument count fits the call
     * is meant. Reading both as one list is the silent way to get every
     * position wrong, which is why the key column exists.
     */
    @Test
    void picksTheOverloadWhoseArgumentCountFits() throws SQLException {
        ResultSet rows = catalog(new String[][] {
                {"p_1", "only"},
                {"p_2", "base"}, {"p_2", "less"}});
        assertEquals(1, ParameterNames.fromCatalog(catalog(new String[][] {
                {"p_1", "only"}, {"p_2", "base"}, {"p_2", "less"}}), 1, false).indexOf("only"));
        assertEquals(2, ParameterNames.fromCatalog(rows, 2, false).indexOf("less"));
    }

    @Test
    void refusesWhenTwoOverloadsFit() {
        SQLException refused = assertThrows(SQLException.class,
                () -> ParameterNames.fromCatalog(catalog(new String[][] {
                        {"p_1", "a"}, {"p_2", "b"}}), 1, false));
        assertTrue(refused.getMessage().contains("2 procedures"), refused.getMessage());
    }

    /**
     * One procedure whose count does not match is still the right one - a
     * declared default the call left out is the ordinary reason, and its
     * names are no less correct for it.
     */
    @Test
    void oneProcedureIsUsedEvenWhenTheCountDiffers() throws SQLException {
        ParameterNames names = ParameterNames.fromCatalog(catalog(new String[][] {
                {"p", "base"}, {"p", "less"}}), 1, false);
        assertEquals(1, names.indexOf("base"));
    }

    @Test
    void anEmptyAnswerSaysSoRatherThanAnsweringNothing() {
        SQLException refused = assertThrows(SQLException.class,
                () -> ParameterNames.fromCatalog(catalog(new String[0][]), 1, false));
        assertTrue(refused.getMessage().contains("catalog"), refused.getMessage());
    }

    /**
     * A {@code ResultSet} of the two columns that are read.
     *
     * <p>A proxy rather than a written-out stub: the interface has some two
     * hundred methods and only {@code next} and {@code getString} are used,
     * so anything else being called is a change worth failing on.
     */
    private static ResultSet catalog(String[][] rows) {
        int[] at = {-1};
        return (ResultSet) Proxy.newProxyInstance(ParameterNamesTest.class.getClassLoader(),
                new Class<?>[] {ResultSet.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "next" -> ++at[0] < rows.length;
                    case "getString" -> rows[at[0]][(Integer) arguments[0] - 1];
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
