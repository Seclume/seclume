package space.seclume.r2dbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactoryOptions;

/** The URL R2DBC users write, as the seclume JDBC URL underneath - and no password. */
class ProviderTest {

    @Test
    void anR2dbcUrlBecomesTheJdbcOneWithItsSecretProvider() {
        ConnectionFactoryOptions options = ConnectionFactoryOptions.parse(
                "r2dbc:seclume:postgresql://svc@db.example:5433/app?provider=file"
                        + "&path=/run/secrets/db&tlsRootCert=/etc/ca.pem");
        assertEquals("jdbc:seclume:postgresql://db.example:5433/app?user=svc&provider=file"
                        + "&path=%2Frun%2Fsecrets%2Fdb&tlsRootCert=%2Fetc%2Fca.pem",
                SeclumeConnectionFactoryProvider.jdbcUrl(options));
    }

    @Test
    void aPasswordOptionIsRefused() {
        ConnectionFactoryOptions options = ConnectionFactoryOptions.parse(
                "r2dbc:seclume:postgresql://svc:secret@db.example/app");
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> new SeclumeConnectionFactoryProvider().create(options));
        assertTrue(refused.getMessage().contains("secret provider"), refused.getMessage());
        assertFalse(refused.getMessage().contains("secret@"), "the message repeats the URL");
    }

    @Test
    void connectionFactoriesFindsIt() {
        assertInstanceOf(SeclumeConnectionFactory.class, ConnectionFactories.get(
                "r2dbc:seclume:mssql://svc@db.example/app?provider=env&key=DB_PASSWORD"));
        assertFalse(new SeclumeConnectionFactoryProvider().supports(
                ConnectionFactoryOptions.parse("r2dbc:postgresql://db.example/app")));
    }

    /**
     * The options option was appended to the JDBC URL as it came, so a
     * string meant for tuning could set the secret provider, its path or TLS.
     * Those are refused there; they have options of their own.
     */
    @org.junit.jupiter.api.Test
    void optionsCannotSetWhereTheSecretComesFromOrWhatIsTrusted() {
        for (String smuggled : new String[] {"provider=process&command=x", "path=/etc/shadow",
            "tls=off", "tlsRootCert=/tmp/ca.pem", "vault-address=https://evil", "user=postgres"}) {
            org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                    () -> SeclumeConnectionFactoryProvider.checkedOptions(smuggled), smuggled);
        }
        org.junit.jupiter.api.Assertions.assertEquals("fetchSize=500&maxResultRows=10",
                SeclumeConnectionFactoryProvider.checkedOptions("fetchSize=500&maxResultRows=10"));
    }
}
