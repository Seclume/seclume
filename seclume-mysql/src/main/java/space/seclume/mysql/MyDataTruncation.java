package space.seclume.mysql;

import java.sql.DataTruncation;

/**
 * A value the server refused because it did not fit.
 *
 * <p>{@link DataTruncation} has no constructor for a message or an error
 * number - it was meant for a driver that noticed the truncation itself - so
 * both are carried here, and the state is its fixed 22001.
 */
public final class MyDataTruncation extends DataTruncation {

    private static final long serialVersionUID = 1L;

    private final String message;
    private final int errorNumber;

    MyDataTruncation(String message, int errorNumber) {
        super(-1, false, false, -1, -1);
        this.message = message;
        this.errorNumber = errorNumber;
    }

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public int getErrorCode() {
        return errorNumber;
    }
}
