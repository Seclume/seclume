package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The wildcard rules, one line per case - this is where the known
 * vulnerabilities in hostname checking live, and every line here is a shape
 * that has been accepted by somebody's implementation when it should not
 * have been.
 */
class HostnameMatchTest {

    @ParameterizedTest(name = "\"{0}\" covers {1}")
    @CsvSource({
            "db.example.com,       db.example.com",
            "DB.Example.COM,       db.example.com",   // the pattern arrives lower-cased
            "*.example.com,        db.example.com",
            "*.example.com,        x.example.com",
            "*.sub.example.com,    db.sub.example.com",
    })
    void matches(String pattern, String host) {
        assertTrue(HostnameMatch.matchesPattern(pattern.trim().toLowerCase(java.util.Locale.ROOT),
                host.trim()));
    }

    @ParameterizedTest(name = "\"{0}\" does not cover {1}")
    @CsvSource({
            "db.example.com,       other.example.com",
            "db.example.com,       db.example.com.evil.test",
            "*.example.com,        a.b.example.com",      // a wildcard is one label, not several
            "*.example.com,        example.com",          // and not the bare domain
            "*.example.com,        .example.com",         // the label has to be a real one
            "*.com,                example.com",          // too broad to be allowed at all
            "*,                    example",
            "db*.example.com,      dbone.example.com",    // partial labels are not honoured
            "*b.example.com,       db.example.com",
            "*.example.com,        db.example.com.au",
            "example.com,          www.example.com",
    })
    void doesNotMatch(String pattern, String host) {
        assertFalse(HostnameMatch.matchesPattern(pattern.trim().toLowerCase(java.util.Locale.ROOT),
                host.trim()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " "})
    void emptyNamesNeverMatch(String empty) {
        assertFalse(HostnameMatch.matchesPattern(empty.trim(), "db.example.com"));
        assertFalse(HostnameMatch.matchesPattern("db.example.com", empty.trim()));
    }
}
