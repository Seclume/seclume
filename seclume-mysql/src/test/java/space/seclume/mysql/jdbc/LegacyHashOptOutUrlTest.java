package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import space.seclume.mysql.MySession;

/** {@code allowLegacyHashOverUnverifiedTls} from the URL, the process default and the DataSource. */
class LegacyHashOptOutUrlTest {

    private static final String BASE = "jdbc:seclume:mysql://db/app?user=u&provider=file&path=/x";

    @Test
    void theUrlSaysItOrTheProcessDefaultDoes() throws Exception {
        assertEquals(MySession.Settings.legacyHashByDefault(),
                MyUrl.settings(BASE, null).allowLegacyHashOverUnverifiedTls());
        assertTrue(MyUrl.settings(BASE + "&allowLegacyHashOverUnverifiedTls=true", null)
                .allowLegacyHashOverUnverifiedTls());
        assertFalse(MyUrl.settings(BASE + "&allowLegacyHashOverUnverifiedTls=false", null)
                .allowLegacyHashOverUnverifiedTls());
    }

    @Test
    void theDataSourceCarriesIt() throws Exception {
        MyDataSource source = new MyDataSource();
        source.setAllowLegacyHashOverUnverifiedTls(false);
        assertFalse(source.isAllowLegacyHashOverUnverifiedTls());
        source.setUrl(BASE + "&allowLegacyHashOverUnverifiedTls=true");
        assertTrue(source.isAllowLegacyHashOverUnverifiedTls());
    }

    @Test
    void theDriverNamesTheOption() throws Exception {
        boolean named = false;
        for (java.sql.DriverPropertyInfo info : new MyDriver().getPropertyInfo(BASE, null)) {
            named |= info.name.equals("allowLegacyHashOverUnverifiedTls");
        }
        assertTrue(named);
    }
}
