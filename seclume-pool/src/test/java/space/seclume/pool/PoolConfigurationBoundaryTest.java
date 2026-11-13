package space.seclume.pool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The edges of the checks that keep a secret out of a pool's configuration
 * and out of what the pool prints about it.
 *
 * <p>{@code PoolConfigurationTest} covers the common URLs. These are the
 * shapes at the edges of each check - a URL that ends at its host, an empty
 * user name before a password, a query that starts the URL, a scheme of
 * exactly the longest length still shown - where a comparison one off or a
 * flipped condition let a secret through or into a message, and no test
 * noticed (run 43416680859, {@code mutation (pool)}: 13 survivors in
 * {@code PoolConfiguration}, 3 in {@code UrlDataSource.toString}).
 */
class PoolConfigurationBoundaryTest {

    @Test
    void eachKindOfInlineSecretIsNamedForWhatItIs() {
        assertEquals("password", PoolConfiguration.inlineSecret("jdbc:seclume:postgresql://db/app?password=x"));
        assertEquals("secret parameter", PoolConfiguration.inlineSecret("jdbc:seclume:mysql://db/app?secret=x"));
        assertEquals("value parameter", PoolConfiguration.inlineSecret("jdbc:seclume:mysql://db/app;value=x"));
        assertEquals("password in its user information (user:password@)",
                PoolConfiguration.inlineSecret("jdbc:seclume:postgresql://app:x@db/app"));
    }

    /** No path, no query: the user information runs to the very end of the URL. */
    @Test
    void aPasswordInAUrlThatEndsAtItsHostIsFound() {
        for (String url : List.of("jdbc:seclume:postgresql://app:zlEndCanary@db",
                "jdbc:seclume:postgresql://app:zlEndCanary@db:5432",
                "//app:zlEndCanary@db")) {
            assertEquals("password in its user information (user:password@)",
                    PoolConfiguration.inlineSecret(url), url);
        }
        assertNull(PoolConfiguration.inlineSecret("jdbc:seclume:postgresql://app@db"));
        assertNull(PoolConfiguration.inlineSecret("jdbc:seclume:postgresql://db"));
    }

    /** An empty user name does not make a password less of one. */
    @Test
    void aPasswordAfterAnEmptyUserNameIsFound() {
        assertEquals("password in its user information (user:password@)",
                PoolConfiguration.inlineSecret("jdbc:seclume:postgresql://:zlEmptyUser@db/app"));
    }

    /** The user information ends where the path, the query or SQL Server's settings begin. */
    @Test
    void anAtSignAfterTheHostIsNoUserInformation() {
        for (String url : List.of("jdbc:seclume:postgresql://db/app:x@y",
                "jdbc:seclume:postgresql://db?user=a&provider=file&path=/p:q@r",
                "jdbc:seclume:sqlserver://db;user=a;provider=file;path=x:y@z",
                "jdbc:seclume:postgresql://@db/app")) {
            assertNull(PoolConfiguration.inlineSecret(url), url);
        }
    }

    @Test
    void aSchemeIsShownUpToItsSecondColonAndOnlyWhenItIsShort() {
        assertEquals(":a:", PoolConfiguration.scheme(":a:b"), "a colon at the very start still counts");
        String thirtyOne = "x".repeat(31);
        String thirtyTwo = "x".repeat(32);
        assertEquals("jdbc:" + thirtyOne + ":", PoolConfiguration.scheme("jdbc:" + thirtyOne + ":secret"));
        assertEquals("something that is no JDBC URL", PoolConfiguration.scheme("jdbc:" + thirtyTwo + ":secret"),
                "a longer \"scheme\" may be the secret itself");
        String longFirst = "abcdefghijklmnopqrst";
        assertEquals(longFirst + ":x:", PoolConfiguration.scheme(longFirst + ":x:rest"),
                "measured between the colons, not from the start");
        assertEquals("something that is no JDBC URL", PoolConfiguration.scheme("one:colon"));
    }

    /** Nothing after a ? or a ; is shown - wherever in the URL it stands. */
    @Test
    void theDataSourcesNameStopsAtTheFirstQueryOrSettings() {
        assertEquals("UrlDataSource[]", new PoolConfiguration.UrlDataSource("?password=zlQ").toString());
        assertEquals("UrlDataSource[]", new PoolConfiguration.UrlDataSource(";password=zlS?a=b").toString());
        assertEquals("UrlDataSource[]", new PoolConfiguration.UrlDataSource("?a=b;password=zlQ").toString());
        assertEquals("UrlDataSource[jdbc:seclume:sqlserver://db]",
                new PoolConfiguration.UrlDataSource("jdbc:seclume:sqlserver://db;x=1?y=2").toString());
        assertEquals("UrlDataSource[jdbc:seclume:mysql://db/app]",
                new PoolConfiguration.UrlDataSource("jdbc:seclume:mysql://db/app?x=1;y=2").toString());
        assertEquals("UrlDataSource[jdbc:seclume:mysql://db/app]",
                new PoolConfiguration.UrlDataSource("jdbc:seclume:mysql://db/app").toString());
    }

    /** {@code PoolConfigurationTest} sets keepalive-time to 0, which is also the default. */
    @Test
    void keepaliveTimeReachesItsSetting() {
        PoolSettings settings = PoolConfiguration.settings("p", Map.of("keepalive-time", "45s"));
        assertEquals(Duration.ofSeconds(45), settings.getKeepaliveTime());
        assertEquals(17, PoolConfiguration.settings("p", Map.of("statement-cache-size", "17"))
                .getStatementCacheSize());
    }
}
