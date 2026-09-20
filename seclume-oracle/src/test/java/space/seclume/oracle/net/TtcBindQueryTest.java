package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * Bind variables and DDL, byte for byte against a known answer.
 *
 * <p>The reference bytes are what {@code python-oracledb} 4.0.2 sent to Oracle
 * Free 23ai, lifted out of its packet log by a script - not copied by hand. A
 * hexdump that was once retyped had lost three bytes, and the test comparing
 * against it stayed green, which is worth one sentence of warning here.
 *
 * <p>Three shapes, and each of them says something:
 *
 * <ul>
 *   <li>A <b>query with a bind</b> sets the bind bit in the options, a pointer
 *       and the count in front of the text, and appends a description per
 *       variable and then the values.</li>
 *   <li>A <b>create table</b> looks like a statement without rows - and its
 *       {@code al8i4} vector says <b>one iteration</b>. With the query shape
 *       the server parses the text and runs it zero times, which is what
 *       {@code ORA-01003, no statement parsed} means.</li>
 *   <li>An <b>insert with two binds</b> combines both, and shows that a
 *       number and a string describe themselves differently: 22 bytes and no
 *       character set against four bytes per character and 873.</li>
 * </ul>
 */
class TtcBindQueryTest {

    /** {@code select username from all_users where user_id = :1}, bind 0. */
    private static final String QUERY_WITH_BIND =
            "035E04000280690001013101010D0000000102047FFFFFFF010101000000000000"
                    + "000000010000000000000000000000000000003173656C65637420757365726E61"
                    + "6D652066726F6D20616C6C5F757365727320776865726520757365725F6964203D"
                    + "203A31010100000000000001010002800000000002010000011600000000000000"
                    + "00070180";

    /** {@code create table zl_bind (n number(9), t varchar2(20), d date)}. */
    private static final String CREATE_TABLE =
            "035E09000280210001013A01010D0000000101047FFFFFFF000000000000000000"
                    + "0000010000000000000000000000000000003A637265617465207461626C65207A"
                    + "6C5F62696E6420286E206E756D6265722839292C20742076617263686172322832"
                    + "30292C20642064617465290101010100000000000000028000000000";

    /** {@code insert into zl_bind (n, t) values (:1, :2)}, binds 7 and "seven". */
    private static final String INSERT_WITH_BINDS =
            "035E0C000280290001012A01010D0000000101047FFFFFFF010102000000000000"
                    + "000000010000000000000000000000000000002A696E7365727420696E746F207A"
                    + "6C5F62696E6420286E2C2074292076616C75657320283A312C203A322901010101"
                    + "000000000000000280000000000201000001160000000000000000010100000114"
                    + "000000000203690100000702C10805736576656E";

    @Test
    void writesAQueryWithABind() throws Exception {
        TtcBinds binds = new TtcBinds();
        binds.set(1, 0);
        assertEquals(QUERY_WITH_BIND, written(4,
                "select username from all_users where user_id = :1", 2, true, binds));
    }

    @Test
    void writesACreateTable() throws Exception {
        assertEquals(CREATE_TABLE, written(9,
                "create table zl_bind (n number(9), t varchar2(20), d date)",
                0, false, null));
    }

    @Test
    void writesAnInsertWithTwoBinds() throws Exception {
        TtcBinds binds = new TtcBinds();
        binds.set(1, 7);
        binds.set(2, "seven");
        assertEquals(INSERT_WITH_BINDS, written(12,
                "insert into zl_bind (n, t) values (:1, :2)", 0, false, binds));
    }

    private static String written(int sequence, String sql, int prefetch, boolean query,
                                  TtcBinds binds) {
        try (WireBuffer out = new WireBuffer(512)) {
            TtcQuery.put(out, sequence, sql, prefetch, query, binds);
            StringBuilder text = new StringBuilder();
            for (int i = 0; i < out.position(); i++) {
                text.append(String.format("%02X", out.getByte(i)));
            }
            return text.toString();
        }
    }
}
