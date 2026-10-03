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
