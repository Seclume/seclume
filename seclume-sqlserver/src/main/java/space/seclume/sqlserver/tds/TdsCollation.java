package space.seclume.sqlserver.tds;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * What a collation says about the bytes of a {@code char}, {@code varchar} or
 * {@code text}: which code page they are in.
 *
 * <p>SQL Server sends single-byte text as it stores it - in the code page of
 * the column's collation - and describes each column with that collation: a
 * locale id with flags, and a sort id that is non-zero for the older
 * {@code SQL_} collations. This driver read every such column as Latin-1,
 * which is right for plain ASCII and wrong for everything else: Cyrillic,
 * Greek, Chinese, Japanese, and even the default
 * {@code SQL_Latin1_General_CP1_CI_AS}, whose code page 1252 has the euro sign
 * and the typographic quotes where Latin-1 has control characters. Found by
 * {@code SqlServerCollationTest}: fifteen of seventeen collations came back
 * wrong.
 *
 * <p>The two tables are the server's own answer, not a list kept by hand:
 * {@code COLLATIONPROPERTY(name, 'SortId' | 'LCID' | 'CodePage')} over every
 * collation {@code sys.fn_helpcollations()} lists, identical on SQL Server
 * 2022 and 2025 - and the same test holds them to the server it runs
 * against, so a new collation shows up as a failure rather than as wrong text.
 */
public final class TdsCollation {

    /** The UTF-8 flag of the 2019 collations: bit 26 of the first four bytes. */
    private static final int UTF8 = 1 << 26;
    /** The locale id: the low 20 bits. */
    private static final int LCID_MASK = 0xfffff;

    /** Code page by sort id - the {@code SQL_} collations. */
    private static final Map<Integer, Integer> BY_SORT = table(
            30, 437,
            31, 437,
            32, 437,
            33, 437,
            34, 437,
            40, 850,
            41, 850,
            42, 850,
            43, 850,
            44, 850,
            49, 850,
            51, 1252,
            52, 1252,
            53, 1252,
            54, 1252,
            55, 850,
            56, 850,
            57, 850,
            58, 850,
            59, 850,
            60, 850,
            61, 850,
            81, 1250,
            82, 1250,
            83, 1250,
            84, 1250,
            85, 1250,
            86, 1250,
            87, 1250,
            88, 1250,
            89, 1250,
            90, 1250,
            91, 1250,
            92, 1250,
            93, 1250,
            94, 1250,
            95, 1250,
            96, 1250,
            105, 1251,
            106, 1251,
            107, 1251,
            108, 1251,
            113, 1253,
            114, 1253,
            120, 1253,
            122, 1253,
            124, 1253,
            129, 1254,
            130, 1254,
            137, 1255,
            138, 1255,
            145, 1256,
            146, 1256,
            153, 1257,
            154, 1257,
            155, 1257,
            156, 1257,
            157, 1257,
            158, 1257,
            159, 1257,
            160, 1257,
            183, 1252,
            184, 1252,
            185, 1252,
            186, 1252,
            210, 1252,
            211, 1252,
            212, 1252,
            213, 1252,
            214, 1252,
            215, 1252,
            216, 1252,
            217, 1252,
            218, 1252,
            219, 1252
    );

    /** Code page by locale id - the Windows collations (sort id 0). */
    private static final Map<Integer, Integer> BY_LCID = table(
            0x401, 1256,
            0x404, 950,
            0x405, 1250,
            0x406, 1252,
            0x408, 1253,
            0x409, 1252,
            0x40a, 1252,
            0x40b, 1252,
            0x40c, 1252,
            0x40d, 1255,
            0x40e, 1250,
            0x40f, 1252,
            0x411, 932,
            0x412, 949,
            0x414, 1252,
            0x415, 1250,
            0x417, 1252,
            0x418, 1250,
            0x419, 1251,
            0x41a, 1250,
            0x41b, 1250,
            0x41c, 1250,
            0x41e, 874,
            0x41f, 1254,
            0x420, 1256,
            0x422, 1251,
            0x424, 1250,
            0x425, 1257,
            0x426, 1257,
            0x427, 1257,
            0x429, 1256,
            0x42a, 1258,
            0x42c, 1254,
            0x42e, 1252,
            0x42f, 1251,
            0x439, 0,
            0x43a, 0,
            0x43b, 1252,
            0x43f, 1251,
            0x442, 1250,
            0x443, 1254,
            0x444, 1251,
            0x445, 0,
            0x44d, 0,
            0x451, 0,
            0x452, 1252,
            0x453, 0,
            0x454, 0,
            0x45a, 0,
            0x461, 0,
            0x462, 1252,
            0x463, 0,
            0x465, 0,
            0x46d, 1251,
            0x47a, 1252,
            0x47c, 1252,
            0x47e, 1252,
            0x480, 1256,
            0x481, 0,
            0x483, 1252,
            0x485, 1251,
            0x48c, 1256,
            0x804, 936,
            0x81a, 1250,
            0x82c, 1251,
            0x83b, 1252,
            0x85f, 1252,
            0xc04, 950,
            0xc0a, 1252,
            0xc1a, 1251,
            0x1404, 950,
            0x141a, 1250,
            0x201a, 1251,
            0x10407, 1252,
            0x1040e, 1250,
            0x10411, 932,
            0x10437, 1252,
            0x20804, 936,
            0x21404, 950,
            0x30404, 950,
            0x40411, 932
    );

    /** One charset per code page, found once. */
    private static final Map<Integer, Charset> CHARSETS = new java.util.concurrent.ConcurrentHashMap<>();

    private TdsCollation() {
    }

    /**
     * The code page of a collation, 0 when the collation is Unicode-only, or
     * 65001 for UTF-8.
     *
     * @param info   the first four bytes of the collation, little endian
     * @param sortId the fifth byte
     */
    public static int codePage(int info, int sortId) {
        if ((info & UTF8) != 0) {
            return 65001;
        }
        if (sortId != 0) {
            Integer page = BY_SORT.get(sortId);
            if (page != null) {
                return page;
            }
        }
        Integer page = BY_LCID.get(info & LCID_MASK);
        return page == null ? 1252 : page;
    }

    /** The charset for single-byte text in this collation. */
    public static Charset charset(int info, int sortId) {
        return charset(codePage(info, sortId));
    }

    /**
     * The JDK's name for a code page. Where this runtime lacks it - a jlinked
     * image without {@code jdk.charsets}, a native image without all charsets -
     * the answer is Latin-1, which is what this driver used for everything
     * before: no worse than it was, and ASCII still right.
     */
    static Charset charset(int codePage) {
        return CHARSETS.computeIfAbsent(codePage, page -> {
            String name = switch (page) {
                case 65001 -> "UTF-8";
                case 437 -> "IBM437";
                case 850 -> "IBM850";
                case 874 -> "x-windows-874";
                case 932 -> "windows-31j";
                case 936 -> "GBK";
                case 949 -> "x-windows-949";
                case 950 -> "x-windows-950";
                case 0 -> "ISO-8859-1";
                default -> "windows-" + page;
            };
            try {
                return Charset.forName(name);
            } catch (RuntimeException missing) {
                return StandardCharsets.ISO_8859_1;
            }
        });
    }

    private static Map<Integer, Integer> table(int... pairs) {
        Map<Integer, Integer> map = new HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put(pairs[i], pairs[i + 1]);
        }
        return Map.copyOf(map);
    }
}
