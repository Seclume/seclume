package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The starter sets the configured result limit unless the URL sets its own.
 * Whether it did was asked with contains("maxResultRows"): an application
 * name or a search path holding the word turned the limit off.
 */
class ResultLimitTest {

    @Test
    void theLimitIsSetWhereTheWordIsOnlyInAValue() {
        assertFalse(SeclumeDataSources.hasOption(
                "jdbc:seclume:postgresql://db/app?applicationName=maxResultRows", "maxResultRows"));
        assertFalse(SeclumeDataSources.hasOption(
                "jdbc:seclume:postgresql://db/app?applicationName=x%26maxResultRows%3D0",
                "maxResultRows"), "an encoded & is part of the value");
        assertFalse(SeclumeDataSources.hasOption(
                "jdbc:seclume:postgresql://db/maxResultBytes", "maxResultBytes"),
                "the database name is no option");
        assertFalse(SeclumeDataSources.hasOption(
                "jdbc:seclume:postgresql://db/app#maxResultRows=1", "maxResultRows"));
    }

    @Test
    void anOptionOfItsOwnIsFoundInAnySpelling() {
        assertTrue(SeclumeDataSources.hasOption(
                "jdbc:seclume:postgresql://db/app?tls=verify-full&maxResultRows=10", "maxResultRows"));
        assertTrue(SeclumeDataSources.hasOption(
                "jdbc:seclume:postgresql://db/app?max-result-bytes=1024", "maxResultBytes"));
    }
}
