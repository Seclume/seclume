package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.ValueSource;

class PublicSuffixesTest {
    @ParameterizedTest
    @ValueSource(strings = {"com", "co.uk", "co.jp", "foo.ck", "foo.kawasaki.jp",
            "公司.cn", "xn--55qx5d.cn", "unknown", "", ".co.uk", "co..uk", "co.uk."})
    void publicSuffixesAndInvalidBasesCannotSupportACertificateWildcard(String domain) {
        assertTrue(PublicSuffixes.isPublicSuffix(domain));
    }

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "example.co.uk", "tenant.github.io", "www.ck",
            "city.kawasaki.jp", "db.city.kawasaki.jp", "internal.test", "example.公司.cn",
            "github.io", "appspot.com", "abc.eu-central-1.rds.amazonaws.com"})
    void registrableDomainsRemainAvailable(String domain) {
        assertFalse(PublicSuffixes.isPublicSuffix(domain));
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "", "// no rules\n", "invalid_underscored_rule",
            "// ===BEGIN ICANN DOMAINS===\ncom\n",
            "// ===BEGIN ICANN DOMAINS===\ninvalid_underscored_rule\n// ===END ICANN DOMAINS===\n"})
    void missingOrMalformedDataRefusesWildcards(String data) throws Exception {
        assertWildcardsRefused(data.equals("missing") ? null : data.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void invalidUtf8InAnOtherwiseCompleteListRefusesWildcards() throws Exception {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        data.write("// ===BEGIN ICANN DOMAINS===\ncom\n// ".getBytes(StandardCharsets.UTF_8));
        data.write(new byte[] {(byte) 0xc3, (byte) 0x28});
        data.write("\n// ===END ICANN DOMAINS===\n".getBytes(StandardCharsets.UTF_8));
        assertWildcardsRefused(data.toByteArray());
    }

    @Test
    void oversizedResourcesRefuseWildcards() throws Exception {
        String data = "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n"
                + " ".repeat(1024 * 1024);
        assertWildcardsRefused(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The list's own rules, read from a small list: only the ICANN section
     * counts, a comment after a rule is not part of it, blank and comment
     * lines are skipped, and wildcards and exceptions mean what they say.
     */
    @Test
    void theListsRulesAreReadAsWritten() throws Exception {
        String data = String.join("\n",
                "pre.zone",                                 // before the section
                "// ===BEGIN ICANN DOMAINS===",
                "",
                "// commented.zone",
                "  ex.zone  // a comment after the rule",
                "*.wild.zone",
                "!keep.wild.zone",
                "\ttab.zone\t",
                "// ===END ICANN DOMAINS===",
                "post.zone",                                // the private section
                "");
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        // A name of one label is a suffix whatever the list says, so every
        // rule here has two.
        assertTrue(isPublicSuffixWith(bytes, "ex.zone"), "a rule with a comment after it");
        assertTrue(isPublicSuffixWith(bytes, "tab.zone"), "a rule between tabs");
        assertTrue(isPublicSuffixWith(bytes, "any.wild.zone"), "a wildcard covers one label");
        assertFalse(isPublicSuffixWith(bytes, "keep.wild.zone"), "an exception overrides it");
        assertFalse(isPublicSuffixWith(bytes, "below.keep.wild.zone"));
        assertFalse(isPublicSuffixWith(bytes, "two.labels.wild.zone"), "and no more than one");
        assertFalse(isPublicSuffixWith(bytes, "a.ex.zone"));
        assertFalse(isPublicSuffixWith(bytes, "pre.zone"), "a rule before the section");
        assertFalse(isPublicSuffixWith(bytes, "post.zone"), "a rule after the section");
        assertFalse(isPublicSuffixWith(bytes, "commented.zone"), "a commented-out rule");
    }

    private static boolean isPublicSuffixWith(byte[] data, String domain) throws Exception {
        URL classes = PublicSuffixes.class.getProtectionDomain().getCodeSource().getLocation();
        try (URLClassLoader loader = new URLClassLoader(new URL[] {classes}, null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                if (name.endsWith("public_suffix_list.dat")) {
                    return new ByteArrayInputStream(data);
                }
                return super.getResourceAsStream(name);
            }
        }) {
            Class<?> suffixes = loader.loadClass("space.seclume.tls.PublicSuffixes");
            var check = suffixes.getDeclaredMethod("isPublicSuffix", String.class);
            check.setAccessible(true);
            return (boolean) check.invoke(null, domain);
        }
    }

    private static void assertWildcardsRefused(byte[] data) throws Exception {
        URL classes = PublicSuffixes.class.getProtectionDomain().getCodeSource().getLocation();
        // A separate loader gives each case its own lazy data holder, with no global mutation.
        try (URLClassLoader loader = new URLClassLoader(new URL[] {classes}, null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                if (name.endsWith("public_suffix_list.dat")) {
                    return data == null ? null : new ByteArrayInputStream(data);
                }
                return super.getResourceAsStream(name);
            }
        }) {
            Class<?> suffixes = loader.loadClass("space.seclume.tls.PublicSuffixes");
            var check = suffixes.getDeclaredMethod("isPublicSuffix", String.class);
            check.setAccessible(true);
            assertTrue((boolean) check.invoke(null, "example.com"));
        }
    }
}
