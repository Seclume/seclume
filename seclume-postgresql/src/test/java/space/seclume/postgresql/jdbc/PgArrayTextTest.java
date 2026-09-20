package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * The array literal, taken apart without a server.
 *
 * <p>These are the cases where a {@code split(",")} gives a wrong answer
 * rather than an error, which is the dangerous kind: the value comes back, it
 * looks plausible, and it is not what is in the database.
 */
class PgArrayTextTest {

    private static List<Object> parse(String text) throws SQLException {
        return PgArrayText.parse(text, ',');
    }

    @Test
    void readsAFlatArray() throws Exception {
        assertEquals(List.of("1", "2", "3"), parse("{1,2,3}"));
    }

    @Test
    void anEmptyArrayHasNoElements() throws Exception {
        assertEquals(List.of(), parse("{}"));
    }

    /**
     * The distinction the whole parser exists for: an unquoted NULL is the
     * null element, a quoted one is the four-letter word.
     */
    @Test
    void tellsTheNullElementFromTheWordNull() throws Exception {
        List<Object> values = parse("{NULL,\"NULL\",null,\"null\"}");
        assertNull(values.get(0));
        assertEquals("NULL", values.get(1));
        assertNull(values.get(2));
        assertEquals("null", values.get(3));
    }

    /** A quoted element may contain the delimiter, and then it is not one. */
    @Test
    void aQuotedElementMayContainACommaOrABrace() throws Exception {
        assertEquals(List.of("a,b", "c}d", "e{f"), parse("{\"a,b\",\"c}d\",\"e{f\"}"));
    }

    /** Inside quotes a backslash escapes the next character, quote included. */
    @Test
    void readsTheEscapes() throws Exception {
        assertEquals(List.of("say \"hi\"", "back\\slash"),
                parse("{\"say \\\"hi\\\"\",\"back\\\\slash\"}"));
    }

    @Test
    void keepsWhitespaceInsideQuotesAndDropsItOutside() throws Exception {
        assertEquals(List.of("  padded  ", "trimmed"), parse("{\"  padded  \",  trimmed  }"));
    }

    @Test
    void readsTwoDimensions() throws Exception {
        List<Object> outer = parse("{{1,2},{3,4}}");
        assertEquals(2, outer.size());
        assertEquals(List.of("1", "2"), outer.get(0));
        assertEquals(List.of("3", "4"), outer.get(1));
    }

    @Test
    void readsThreeDimensions() throws Exception {
        List<Object> outer = parse("{{{1},{2}},{{3},{4}}}");
        assertEquals(2, outer.size());
        assertEquals(List.of(List.of("1"), List.of("2")), outer.get(0));
    }

    /**
     * An array with an explicit lower bound arrives with its dimensions in
     * front. JDBC cannot carry a lower bound, so the prefix is dropped - but
     * it must not be read as an element, which is the failure this catches.
     */
    @Test
    void dropsAnExplicitLowerBound() throws Exception {
        assertEquals(List.of("7", "8"), parse("[0:1]={7,8}"));
    }

    @Test
    void refusesSomethingThatIsNotAnArray() {
        assertThrows(SQLException.class, () -> parse("1,2,3"));
        assertThrows(SQLException.class, () -> parse("{1,2"));
        assertThrows(SQLException.class, () -> parse("{1,2} trailing"));
    }

    /** The decoded array, with the component type the oid calls for. */
    @Test
    void buildsTypedJavaArrays() throws Exception {
        PgArray integers = new PgArray(PgOids.INT4_ARRAY, "{1,2,NULL}");
        assertArrayEquals(new Integer[] {1, 2, null}, (Integer[]) integers.getArray());
        assertEquals("int4", integers.getBaseTypeName());
        assertEquals(java.sql.Types.INTEGER, integers.getBaseType());

        PgArray texts = new PgArray(PgOids.TEXT_ARRAY, "{\"a,b\",NULL}");
        assertArrayEquals(new String[] {"a,b", null}, (String[]) texts.getArray());

        PgArray empty = new PgArray(PgOids.INT8_ARRAY, "{}");
        assertArrayEquals(new Long[] {}, (Long[]) empty.getArray());
    }

    /**
     * An array of nothing but nulls still has the component type of its
     * column. An ORM reads that type, and deriving it from the values would
     * make the answer depend on the row.
     */
    @Test
    void keepsTheComponentTypeWhenEveryElementIsNull() throws Exception {
        Object value = new PgArray(PgOids.UUID_ARRAY, "{NULL,NULL}").getArray();
        assertEquals(java.util.UUID[].class, value.getClass());
    }

    @Test
    void slicesCountFromOne() throws Exception {
        PgArray array = new PgArray(PgOids.INT4_ARRAY, "{10,20,30,40}");
        assertArrayEquals(new Integer[] {10, 20}, (Integer[]) array.getArray(1, 2));
        assertArrayEquals(new Integer[] {30, 40}, (Integer[]) array.getArray(3, 9));
        assertThrows(SQLException.class, () -> array.getArray(0, 1));
    }

    @Test
    void servesTheElementsAsAResultSet() throws Exception {
        PgArray array = new PgArray(PgOids.TEXT_ARRAY, "{alpha,beta}");
        try (java.sql.ResultSet rows = array.getResultSet()) {
            java.util.List<String> read = new java.util.ArrayList<>();
            while (rows.next()) {
                read.add(rows.getLong("INDEX") + "=" + rows.getString("VALUE"));
            }
            assertEquals(List.of("1=alpha", "2=beta"), read);
        }
    }
}
