package space.seclume.sqlserver.tds;

/**
 * One column of a result, as {@code COLMETADATA} describes it.
 *
 * <p>Without this description a row is a run of bytes with no meaning: the same
 * eight bytes are a {@code bigint} in one result and a length byte plus seven
 * bytes of text in the next. Everything the row parser and the value reader
 * need is in here - and nothing else, because the description arrives once per
 * result and is then consulted for every single cell.
 *
 * @param name      the column name; empty for a computed column without an alias
 * @param type      the TDS type, see {@link TdsTypes}
 * @param size      the declared maximum size; {@code 0xffff} means {@code MAX}
 * @param precision the total number of digits, for {@code decimal} only
 * @param scale     the decimal places - also the unit of the time types
 * @param nullable  whether the column may hold NULL
 * @param plp       whether values arrive in the chunked {@code MAX} framing
 */
public record TdsColumn(String name, int type, int size, int precision, int scale,
                        boolean nullable, boolean plp) {

    /** The declared size that means {@code varchar(max)} and its relatives. */
    public static final int MAX_SIZE = 0xffff;

    /** How many bytes the length field in front of a value takes. */
    public int lengthBytes() {
        if (plp) {
            return 8;
        }
        if (TdsTypes.fixedLength(type) >= 0) {
            return 0;
        }
        if (TdsTypes.hasFourByteLength(type)) {
            return 4;
        }
        return TdsTypes.hasTwoByteLength(type) ? 2 : 1;
    }
}
