package space.seclume.internal.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The names a procedure gives its parameters, turned into JDBC positions.
 *
 * <p>{@code CallableStatement} lets an application address a parameter by the
 * name the procedure declared - {@code setInt("amount", 3)} instead of
 * {@code setInt(2, 3)}. No wire protocol of the four carries those names in
 * the call itself; they live in the server's catalog, and every driver has to
 * look them up. What the four then share is everything after the lookup, and
 * that is this class: the matching rules and the counting.
 *
 * <p>Three rules, each of which a driver would otherwise get subtly wrong on
 * its own:
 *
 * <ul>
 *   <li><b>A leading marker is not part of the name.</b> Oracle writes
 *       {@code :amount} in a block and SQL Server {@code @amount} in an RPC,
 *       and applications pass both spellings. One is stripped from either
 *       side, so all four accept all of them.</li>
 *   <li><b>Names match without regard to case.</b> The catalogs disagree on
 *       what they store - Oracle upper-cases an unquoted declaration,
 *       PostgreSQL lower-cases it - and an application that worked against
 *       one driver should not fail against another over that.</li>
 *   <li><b>The return value occupies position 1.</b> For
 *       {@code {? = call f(?)}} the first declared argument is JDBC index 2,
 *       because index 1 is what the function gives back. Counting from 1
 *       regardless is the classic off-by-one here.</li>
 * </ul>
 *
 * <p>A name that stands for two parameters is refused rather than guessed at,
 * and so is one that stands for none - with the names that do exist in the
 * message, because "no such parameter" without them sends the reader to the
 * catalog by hand.
 */
public final class ParameterNames {

    private final List<String> declared;
    private final boolean returnsValue;

    /**
     * @param declared     the parameter names in the order the procedure
     *                     declares them, excluding a function's return value;
     *                     a name may be null where the catalog has none
     * @param returnsValue whether JDBC index 1 is the return value
     */
    public ParameterNames(List<String> declared, boolean returnsValue) {
        this.declared = List.copyOf(declared);
        this.returnsValue = returnsValue;
    }

    /**
     * The names of one procedure, read from a catalog answer.
     *
     * <p>Three of the four servers answer this from
     * {@code information_schema.parameters} and Oracle from
     * {@code all_arguments}, with different column names and different ways
     * of spelling a return value - but all four can be asked for the same
     * three things in the same order, and then the rest is shared:
     *
     * <ol>
     *   <li>a key that tells one overload from another,</li>
     *   <li>the parameter's name, and</li>
     *   <li>its position, which the query sorts by - this reads the rows in
     *       the order they arrive and does not renumber them.</li>
     * </ol>
     *
     * <p><b>Overloads are the reason for the first column.</b> A name alone
     * can stand for several procedures, and reading their parameters as one
     * list would number them all wrong - silently, which is the worst way.
     * The overload whose argument count matches the call is the one meant; if
     * two do, or none does, this says so instead of picking.
     *
     * @param rows         the answer, positioned before the first row
     * @param arguments    how many arguments the call passes, excluding a
     *                     function's return value
     * @param returnsValue whether JDBC index 1 is the return value
     */
    public static ParameterNames fromCatalog(ResultSet rows, int arguments, boolean returnsValue)
            throws SQLException {
        Map<String, List<String>> byOverload = new LinkedHashMap<>();
        while (rows.next()) {
            String key = rows.getString(1);
            String name = rows.getString(2);
            byOverload.computeIfAbsent(key == null ? "" : key, k -> new ArrayList<>()).add(name);
        }
        if (byOverload.isEmpty()) {
            throw new SQLException("the catalog knows no procedure of that name, or none whose "
                    + "parameters it will name - address the parameters by index");
        }
        List<List<String>> fitting = byOverload.values().stream()
                .filter(names -> names.size() == arguments)
                .toList();
        if (fitting.size() == 1) {
            return new ParameterNames(fitting.getFirst(), returnsValue);
        }
        if (fitting.isEmpty() && byOverload.size() == 1) {
            // One procedure, and it declares a different number of arguments
            // than the call passes - defaults, most likely. Its names are
            // still the right ones; a position beyond the call is caught
            // where every other bad index is.
            return new ParameterNames(byOverload.values().iterator().next(), returnsValue);
        }
        throw new SQLException("the name stands for " + byOverload.size() + " procedures and "
                + fitting.size() + " of them take " + arguments + " arguments - address the "
                + "parameters by index");
    }

    /** How many names were found - zero means the catalog knew the procedure but named nothing. */
    public int size() {
        return declared.size();
    }

    /**
     * The JDBC position a name stands for.
     *
     * @throws SQLException if no parameter carries the name, or two do
     */
    public int indexOf(String wanted) throws SQLException {
        if (wanted == null || wanted.isBlank()) {
            throw new SQLException("a parameter name is needed, and this one is empty");
        }
        String needle = normalise(wanted);
        int found = -1;
        for (int i = 0; i < declared.size(); i++) {
            String name = declared.get(i);
            if (name == null || !normalise(name).equals(needle)) {
                continue;
            }
            if (found >= 0) {
                throw new SQLException("the procedure declares \"" + wanted + "\" twice, at "
                        + found + " and at " + position(i) + " - address it by index");
            }
            found = position(i);
        }
        if (found < 0) {
            throw new SQLException("the procedure has no parameter named \"" + wanted
                    + "\" - it declares " + known());
        }
        return found;
    }

    private int position(int declaredIndex) {
        return declaredIndex + 1 + (returnsValue ? 1 : 0);
    }

    private String known() {
        if (declared.isEmpty()) {
            return "none";
        }
        List<String> shown = new ArrayList<>(declared.size());
        for (int i = 0; i < declared.size(); i++) {
            shown.add((declared.get(i) == null ? "?" : declared.get(i)) + " at " + position(i));
        }
        return String.join(", ", shown);
    }

    private static String normalise(String name) {
        String text = name.trim();
        if (!text.isEmpty() && (text.charAt(0) == ':' || text.charAt(0) == '@')) {
            text = text.substring(1);
        }
        if (text.length() > 1 && text.charAt(0) == '"' && text.endsWith("\"")) {
            // A quoted declaration keeps its case in every one of the four
            // catalogs; the quotes themselves are punctuation, not name.
            return text.substring(1, text.length() - 1);
        }
        return text.toLowerCase(Locale.ROOT);
    }
}
