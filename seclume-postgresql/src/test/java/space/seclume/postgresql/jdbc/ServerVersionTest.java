package space.seclume.postgresql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * {@code server_version} as servers send it, into the major and minor number
 * {@code DatabaseMetaData} reports - which Flyway and Hibernate decide on. A
 * release candidate reported as 0.0 made Flyway refuse PostgreSQL 19rc1 as
 * "outdated".
 */
class ServerVersionTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "18.1|18|1",
        "15.10|15|10",
        "9.6.24|9|6",
        "19rc1|19|0",
        "19beta2|19|0",
        "19devel|19|0",
        "16.4 (Debian 16.4-1.pgdg120+1)|16|4",
        "17.2 (Ubuntu 17.2-1.pgdg24.04+1)|17|2",
        "  14.13  |14|13",
        "unknown|0|0",
        "''|0|0",
        ".5|0|0",
        "18.|18|0",
        "99999999999999|999999999|0",
    })
    void majorAndMinor(String version, int major, int minor) {
        assertEquals(major, PgDatabaseMetaData.versionPart(version, 0), version);
        assertEquals(minor, PgDatabaseMetaData.versionPart(version, 1), version);
    }

    @org.junit.jupiter.api.Test
    void nothingIsZero() {
        assertEquals(0, PgDatabaseMetaData.versionPart(null, 0));
        assertEquals(0, PgDatabaseMetaData.versionPart(null, 1));
    }
}
