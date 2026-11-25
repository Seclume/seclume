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

    /**
     * The word in a path or in another option's value is no limit: the URL
     * gets one. A text search used to find it there and set none.
     */
    @Test
    void theWordElsewhereInTheUrlIsNoLimit() {
        assertEquals("jdbc:seclume:postgresql://db/app?applicationName=report-maxResultRows=5"
                        + "&maxResultBytes=268435456",
                SeclumeDataSources.withResultLimit("main",
                        "jdbc:seclume:postgresql://db/app?applicationName=report-maxResultRows=5",
                        4 * GB));
        assertEquals("jdbc:seclume:postgresql://db/maxResultBytes=1?user=u&maxResultBytes=268435456",
                SeclumeDataSources.withResultLimit("main",
                        "jdbc:seclume:postgresql://db/maxResultBytes=1?user=u", 4 * GB));
        String spelled = "jdbc:seclume:postgresql://db/app?max-result-bytes=1048576";
        assertEquals(spelled, SeclumeDataSources.withResultLimit("main", spelled, 4 * GB),
                "a key spelled as the drivers accept it is the limit");
    }

    @Test
    void aFragmentStaysAtTheEnd() {
        assertEquals("jdbc:seclume:postgresql://db/app?user=u&maxResultBytes=268435456#x",
                SeclumeDataSources.withResultLimit("main",
                        "jdbc:seclume:postgresql://db/app?user=u#x", 4 * GB));
    }
}
