package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * A data source whose URL sets no result limit gets one: a runaway query ends
 * in an exception for that statement, not an OutOfMemoryError for the whole
 * application.
 */
class ResultLimitDefaultTest {

    private static final long GB = 1L << 30;

    @Test
    void aUrlWithoutALimitGetsAQuarterOfTheHeapAtMost256Mb() {
        assertEquals("jdbc:seclume:postgresql://db/app?user=u&maxResultBytes=268435456",
                SeclumeDataSources.withResultLimit("main", "jdbc:seclume:postgresql://db/app?user=u",
                        4 * GB));
        assertEquals("jdbc:seclume:mysql://db/app?maxResultBytes=134217728",
                SeclumeDataSources.withResultLimit("main", "jdbc:seclume:mysql://db/app",
                        512L << 20));
        assertEquals("jdbc:seclume:oracle://db/x?user=u&maxResultBytes=16777216",
                SeclumeDataSources.withResultLimit("main", "jdbc:seclume:oracle://db/x?user=u",
                        32L << 20), "a tiny heap still gets the floor of 16 MB");
    }

    @Test
    void aLimitTheUrlSetsIsKeptAndZeroSwitchesItOff() {
        String own = "jdbc:seclume:postgresql://db/app?maxResultRows=1000";
        assertEquals(own, SeclumeDataSources.withResultLimit("main", own, 4 * GB));
        String off = "jdbc:seclume:postgresql://db/app?maxResultBytes=0";
        assertEquals(off, SeclumeDataSources.withResultLimit("main", off, 4 * GB));
    }

    @Test
    void aFragmentStaysAtTheEnd() {
        assertEquals("jdbc:seclume:postgresql://db/app?user=u&maxResultBytes=268435456#x",
                SeclumeDataSources.withResultLimit("main",
                        "jdbc:seclume:postgresql://db/app?user=u#x", 4 * GB));
    }
}
