package space.seclume.oracle.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigDecimal;
import java.sql.Timestamp;
import java.util.HexFormat;
import java.util.SplittableRandom;
import java.util.TimeZone;

import org.junit.jupiter.api.Test;

import space.seclume.internal.WireBuffer;

/**
 * The fast ways a bind value is encoded, held against the slow ones they
 * replace: the same bytes for every decimal, the same fields for every
 * timestamp.
 */
class BindFastPathTest {

    @Test
    void aScaledDecimalEncodesAsItsTextDoes() {
        SplittableRandom random = new SplittableRandom(20260924);
        // A sample in every build, all of it under the fuzz profile: 300 000
        // took fifteen seconds of every build for a check that rarely changes.
        int cases = Boolean.getBoolean("seclume.fuzz.full") ? 300_000 : 30_000;
        for (int i = 0; i < cases; i++) {
            long unscaled = switch (i % 4) {
                case 0 -> random.nextLong();
                case 1 -> random.nextLong(-1_000_000, 1_000_000);
                case 2 -> random.nextLong(-100, 100);
                default -> random.nextLong() / (1L << random.nextInt(63));
            };
            int scale = random.nextInt(-4, 30);
            same(BigDecimal.valueOf(unscaled, scale));
        }
        for (String text : new String[] {"0", "0.00", "1", "-1", "12.50", "-12.5", "0.05",
                "0.000001", "100", "1E+3", "-1E+4", "9223372036854775807",
                "-9223372036854775807", "922337203685477580.7", "99.99", "-0.01"}) {
            same(new BigDecimal(text));
        }
    }

    private static void same(BigDecimal value) {
        try (WireBuffer fast = new WireBuffer(64); WireBuffer text = new WireBuffer(64)) {
            OracleNumber.encodeScaled(fast, value.unscaledValue().longValue(), value.scale());
            OracleNumber.encodeText(text, value.toPlainString());
            assertEquals(hex(text), hex(fast), value.toPlainString());
        }
    }

    private static String hex(WireBuffer buffer) {
        byte[] bytes = new byte[buffer.position()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = buffer.getByte(i);
        }
        return HexFormat.of().formatHex(bytes);
    }

    @Test
    void aTimestampHasTheFieldsToLocalDateTimeGivesIt() {
        TimeZone before = TimeZone.getDefault();
        try {
            for (String zone : new String[] {"Europe/Vienna", "America/New_York",
                    "Pacific/Chatham", "Asia/Kolkata", "UTC", "Australia/Lord_Howe"}) {
                TimeZone.setDefault(TimeZone.getTimeZone(zone));
                SplittableRandom random = new SplittableRandom(zone.hashCode());
                for (int i = 0; i < 100_000; i++) {
                    Timestamp stamp = new Timestamp(random.nextLong(-5_000_000_000_000L,
                            7_000_000_000_000L));
                    stamp.setNanos(random.nextInt(1_000_000_000));
                    assertEquals(stamp.toLocalDateTime(), TtcBinds.localFields(stamp),
                            zone + " " + stamp.getTime());
                }
            }
        } finally {
            TimeZone.setDefault(before);
        }
    }
}
