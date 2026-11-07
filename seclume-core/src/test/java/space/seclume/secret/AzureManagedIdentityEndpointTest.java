package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import space.seclume.internal.Platform;

/**
 * Which endpoint the Azure managed identity asks, as the platform's
 * environment says: IMDS on a VM; App Service, Functions and Container Apps
 * with IDENTITY_ENDPOINT and IDENTITY_HEADER; Azure Arc with IDENTITY_ENDPOINT
 * and IMDS_ENDPOINT and no header. The choice used to be made from the
 * process's own variables only, so no test could reach it - ten of its
 * conditions survived every mutant run.
 */
class AzureManagedIdentityEndpointTest {

    private static final String RESOURCE = AzureManagedIdentitySecretProvider.OSSRDBMS_RESOURCE;

    private static String endpoint(Map<String, String> variables) {
        Map<String, String> environment = new HashMap<>(variables);
        return new AzureManagedIdentitySecretProvider(environment::get, RESOURCE, null, 8192)
                .endpointForTests();
    }

    @Test
    void withNothingSetItIsImdsOnAVm() {
        assertEquals("169.254.169.254:80", endpoint(Map.of()));
    }

    @Test
    void appServiceHasAnEndpointAndAHeader() {
        assertEquals("127.0.0.1:41741 app-service /msi/token header=true", endpoint(Map.of(
                "IDENTITY_ENDPOINT", "http://127.0.0.1:41741/msi/token",
                "IDENTITY_HEADER", "a-guard")));
        // Without a port, HTTP's.
        assertEquals("localhost:80 app-service /msi/token header=true", endpoint(Map.of(
                "IDENTITY_ENDPOINT", "http://localhost/msi/token",
                "IDENTITY_HEADER", "a-guard")));
    }

    @Test
    void anEndpointWithoutAHeaderIsNotAppServiceAndNotArcEither() {
        assertEquals("169.254.169.254:80", endpoint(Map.of(
                "IDENTITY_ENDPOINT", "http://127.0.0.1:41741/msi/token")));
        assertEquals("169.254.169.254:80", endpoint(Map.of(
                "IDENTITY_HEADER", "a-guard")));
    }

    @Test
    void arcHasAnEndpointAndImdsEndpointAndNoHeader() {
        String expected = "localhost:40342 arc /metadata/identity/oauth2/token tokens="
                + (Platform.isWindows()
                        ? Path.of("C:\\ProgramData", "AzureConnectedMachineAgent", "Tokens")
                        : Path.of("/var/opt/azcmagent/tokens"));
        assertEquals(expected, endpoint(Map.of(
                "IDENTITY_ENDPOINT", "http://localhost:40342/metadata/identity/oauth2/token",
                "IMDS_ENDPOINT", "http://localhost:40342")));
    }

    @Test
    void imdsEndpointWithAHeaderIsAppServiceNotArc() {
        assertEquals("127.0.0.1:41741 app-service /msi/token header=true", endpoint(Map.of(
                "IDENTITY_ENDPOINT", "http://127.0.0.1:41741/msi/token",
                "IDENTITY_HEADER", "a-guard",
                "IMDS_ENDPOINT", "http://localhost:40342")));
    }

    @Test
    void imdsEndpointAloneIsStillImds() {
        assertEquals("169.254.169.254:80", endpoint(Map.of(
                "IMDS_ENDPOINT", "http://localhost:40342")));
    }

    @Test
    void blankVariablesCountAsUnset() {
        assertEquals("169.254.169.254:80", endpoint(Map.of(
                "IDENTITY_ENDPOINT", "  ", "IDENTITY_HEADER", "")));
        assertEquals("127.0.0.1:41741 app-service /msi/token header=true", endpoint(Map.of(
                "IDENTITY_ENDPOINT", " http://127.0.0.1:41741/msi/token ",
                "IDENTITY_HEADER", " a-guard ")));
    }

    @Test
    void anEndpointThatIsNotPlainHttpIsRefused() {
        for (String wrong : new String[] {"https://127.0.0.1:41741/msi/token", "127.0.0.1:41741",
                "http:///no-host", "ht tp://x"}) {
            assertThrows(IllegalArgumentException.class, () -> endpoint(Map.of(
                    "IDENTITY_ENDPOINT", wrong, "IDENTITY_HEADER", "a-guard")), wrong);
        }
    }

    @Test
    void arcHasOneIdentityAndNoClientId() {
        Map<String, String> arc = Map.of(
                "IDENTITY_ENDPOINT", "http://localhost:40342/metadata/identity/oauth2/token",
                "IMDS_ENDPOINT", "http://localhost:40342");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new AzureManagedIdentitySecretProvider(arc::get, RESOURCE, "a-client", 8192));
        assertTrue(e.getMessage().contains("no client-id"), e.getMessage());
        // On App Service a user-assigned identity is fine.
        assertTrue(new AzureManagedIdentitySecretProvider(Map.of(
                "IDENTITY_ENDPOINT", "http://127.0.0.1:41741/msi/token",
                "IDENTITY_HEADER", "a-guard")::get, RESOURCE, "a-client", 8192)
                .endpointForTests().contains("app-service"));
    }

    @Test
    void aResourceIsRequired() {
        for (String missing : new String[] {null, "", "  "}) {
            assertThrows(IllegalArgumentException.class,
                    () -> new AzureManagedIdentitySecretProvider(Map.<String, String>of()::get,
                            missing, null, 8192));
        }
    }

    @Test
    void theProgramDataVariableMovesArcsTokensOnWindows() {
        org.junit.jupiter.api.Assumptions.assumeTrue(Platform.isWindows(), "Windows only");
        assertTrue(endpoint(Map.of(
                "IDENTITY_ENDPOINT", "http://localhost:40342/metadata/identity/oauth2/token",
                "IMDS_ENDPOINT", "http://localhost:40342",
                "ProgramData", "D:\\Data")).endsWith(
                Path.of("D:\\Data", "AzureConnectedMachineAgent", "Tokens").toString()));
    }
}
