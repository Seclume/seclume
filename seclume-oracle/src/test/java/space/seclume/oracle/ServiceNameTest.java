package space.seclume.oracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.internal.jdbc.HostList;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.internal.jdbc.TlsMode;
import space.seclume.secret.NoSecretProvider;

/**
 * The service name goes into the connect descriptor as it is. A parenthesis,
 * an equals sign or a blank would add an entry of its own - another
 * SERVICE_NAME, an address - so only letters, digits and _ . $ # - pass, and
 * the descriptor then names exactly one service, the one given.
 */
class ServiceNameTest {

    private static OracleSession.Settings settings(String service) {
        return new OracleSession.Settings("db.example.com", 1521, service, "app",
                NoSecretProvider.INSTANCE, 5_000, HostList.of("db.example.com", 1521),
                ResultLimit.NONE, TlsMode.OFF);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"a(x", "a)x", "a=b", "a b", "a\tb", "a\nb", "",
        "FREEPDB1)(SERVICE_NAME=OTHER"})
    void aNameThatCouldAddAnEntryIsRefused(String service) {
        assertThrows(IllegalArgumentException.class, () -> settings(service));
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"SVC_1", "a-b", "X$Y#", "orcl.example.com", "FREEPDB1"})
    void aLegalNameIsTheOneServiceOfTheDescriptor(String service) {
        String descriptor = settings(service).connectString();
        int first = descriptor.indexOf("SERVICE_NAME=");
        assertTrue(first >= 0, descriptor);
        assertEquals(-1, descriptor.indexOf("SERVICE_NAME=", first + 1),
                "more than one service in " + descriptor);
        assertTrue(descriptor.contains("(SERVICE_NAME=" + service + ")"), descriptor);
    }
}
