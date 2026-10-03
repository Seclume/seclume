package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PublicSuffixesTest {
    @ParameterizedTest
    @ValueSource(strings = {"com", "co.uk", "github.io", "foo.ck", "foo.kawasaki.jp",
            "公司.cn", "xn--55qx5d.cn", "unknown", "", ".co.uk", "co..uk", "co.uk."})
    void publicSuffixesAndInvalidBasesCannotSupportACertificateWildcard(String domain) {
        assertTrue(PublicSuffixes.isPublicSuffix(domain));
    }

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "example.co.uk", "tenant.github.io", "www.ck",
            "city.kawasaki.jp", "db.city.kawasaki.jp", "internal.test", "example.公司.cn"})
    void registrableDomainsRemainAvailable(String domain) {
        assertFalse(PublicSuffixes.isPublicSuffix(domain));
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "", "// no rules\n", "invalid_underscored_rule"})
    void missingOrMalformedDataRefusesWildcards(String data) throws Exception {
        URL classes = PublicSuffixes.class.getProtectionDomain().getCodeSource().getLocation();
        // A separate loader gives each case its own lazy data holder, with no global mutation.
        try (URLClassLoader loader = new URLClassLoader(new URL[] {classes}, null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                if (name.endsWith("public_suffix_list.dat")) {
                    return data.equals("missing") ? null
                            : new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
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
