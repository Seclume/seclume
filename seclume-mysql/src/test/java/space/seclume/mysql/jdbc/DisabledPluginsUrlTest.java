package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;
import java.util.Set;

import org.junit.jupiter.api.Test;

/** {@code disabledAuthenticationPlugins} from the URL and into the DataSource. */
class DisabledPluginsUrlTest {

    private static final String BASE = "jdbc:seclume:mysql://db.example.com/app?user=app&provider=none";

    @Test
    void theUrlCarriesThePluginNames() throws Exception {
        assertEquals(Set.of("mysql_native_password", "mysql_clear_password"),
                MyUrl.settings(BASE + "&disabledAuthenticationPlugins=Mysql_Native_Password,"
                        + " mysql_clear_password", null).disabledAuthenticationPlugins());
        assertEquals(Set.of(), MyUrl.settings(BASE, null).disabledAuthenticationPlugins());
    }

    @Test
    void aMisspeltPluginIsAnErrorNotANoOp() {
        assertThrows(SQLException.class, () -> MyUrl.settings(
                BASE + "&disabledAuthenticationPlugins=mysql_native_pasword", null));
        assertThrows(SQLException.class,
                () -> new MyDataSource().setDisabledAuthenticationPlugins("native"));
    }

    @Test
    void theDataSourceKeepsWhatTheUrlSaid() throws Exception {
        MyDataSource source = new MyDataSource();
        source.setUrl(BASE + "&disabledAuthenticationPlugins=mysql_native_password");
        assertEquals("mysql_native_password", source.getDisabledAuthenticationPlugins());
    }
}
