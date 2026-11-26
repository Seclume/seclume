package space.seclume.internal.jdbc;

/**
 * A number that is a number, and too large for what it is read as - a
 * BIGINT UNSIGNED above Long.MAX_VALUE, twenty digits for a long. JDBC owes
 * the caller SQLState 22003 (numeric value out of range) for it, not the
 * 22018 of text that is no number at all; both reach the result set as a
 * NumberFormatException, and this one says which it is.
 */
public final class NumberOutOfRange extends NumberFormatException {

    private static final long serialVersionUID = 1L;

    public NumberOutOfRange(String message) {
        super(message);
    }
}
