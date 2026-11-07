package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import space.seclume.mysql.MySession;

/** {@code allowCleartextOverUnverifiedTls} from the URL, the process default and the DataSource. */
class CleartextOptOutUrlTest {

    private static final String BASE = "jdbc:seclume:mysql://db/app?user=u&provider=file&path=/x";

    @Test
    void theUrlSaysItOrTheProcessDefaultDoes() throws Exception {
        assertEquals(MySession.Settings.cleartextByDefault(),
                MyUrl.settings(BASE, null).allowCleartextOverUnverifiedTls());
        assertTrue(MyUrl.settings(BASE + "&allowCleartextOverUnverifiedTls=true", null)
                .allowCleartextOverUnverifiedTls());
        assertFalse(MyUrl.settings(BASE + "&allowCleartextOverUnverifiedTls=false", null)
                .allowCleartextOverUnverifiedTls());
    }

    @Test
    void theDataSourceCarriesIt() throws Exception {
        MyDataSource source = new MyDataSource();
        source.setAllowCleartextOverUnverifiedTls(false);
        assertFalse(source.isAllowCleartextOverUnverifiedTls());
        source.setUrl(BASE + "&allowCleartextOverUnverifiedTls=true");
        assertTrue(source.isAllowCleartextOverUnverifiedTls());
    }

    @Test
    void theDriverNamesTheOption() throws Exception {
        boolean named = false;
        for (java.sql.DriverPropertyInfo info : new MyDriver().getPropertyInfo(BASE, null)) {
            named |= info.name.equals("allowCleartextOverUnverifiedTls");
        }
        assertTrue(named);
    }
}
