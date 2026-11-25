package space.seclume.mysql.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * MySQL has no dot in a user variable's name, so a context name's dots become
 * underscores: app.tenant_id and app_tenant.id were one @app_tenant_id, and
 * the second overwrote the first without a word. Two names for one variable
 * are refused.
 */
class ContextVariableTest {

    @Test
    void twoNamesForOneVariableAreRefused() throws SQLException {
        Map<String, String> names = new HashMap<>();
        assertEquals("@app_tenant_id", MyConnection.contextVariable(names, "app.tenant_id"));
        SQLException refused = assertThrows(SQLException.class,
                () -> MyConnection.contextVariable(names, "app_tenant.id"));
        assertEquals("22023", refused.getSQLState());
    }

    @Test
    void theSameNameAgainIsFine() throws SQLException {
        Map<String, String> names = new HashMap<>();
        MyConnection.contextVariable(names, "app.tenant_id");
        assertEquals("@app_tenant_id", MyConnection.contextVariable(names, "app.tenant_id"));
        assertEquals("@app_user", MyConnection.contextVariable(names, "app.user"));
    }
}
