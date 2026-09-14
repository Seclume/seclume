package space.seclume.mysql;

import java.util.List;

/**
 * Access to the raw bytes of a row, no matter where they come from.
 *
 * <p>Two things deliver cells: {@link MyRow} - a window onto the receive
 * buffer, valid until the next packet - and the result block of the JDBC layer,
 * which has taken the rows over. Reading the bytes is the same in both cases,
 * and {@link BinaryValues} should only have to know it once.
 */
public interface ValueCells {

    /** The column description - without it the bytes are meaningless. */
    List<MySession.Field> fields();

    /** Start of the cell within the underlying memory. */
    int offset(int column);

    /** Length of the cell; negative for SQL NULL. */
    int length(int column);

    /** A single byte at an absolute position. */
    byte byteAt(int at);

    /** An unsigned number from {@code length} bytes, least significant first. */
    long unsignedAt(int at, int length);

    /** A slice of text at an absolute position. */
    String textAt(int at, int length);
}
