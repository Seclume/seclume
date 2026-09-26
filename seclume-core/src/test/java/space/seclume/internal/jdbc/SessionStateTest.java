package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Which statements are noted as setting session state - and which are not. */
class SessionStateTest {

    @Test
    void whatSetsSessionStateIsNoted() {
        for (String sql : new String[] {
                "SET app.tenant_id = 42",
                "set search_path to tenant_7",
                "  /* a comment */ -- and another\n SET @tenant = 7",
                "select set_config('app.tenant_id', '42', false)",
                "SELECT pg_advisory_lock(1)",
                "create temporary table t (n int)",
                "CREATE TEMP TABLE t (n int)",
                "create local temporary table t (n int)",
                "create table #scratch (n int)",
                "select * into #copy from orders",
                "exec sp_set_session_context 'tenant', 42",
                "set context_info 0x01",
                "begin dbms_session.set_identifier('alice'); end;",
                "begin dbms_application_info.set_module('app', null); end;",
                "alter session set nls_date_format = 'YYYY'",
                "USE other_database",
                "prepare s as select 1",
                "listen channel",
                "select @n := 1",
                "declare c cursor with hold for select 1",
                // Found in review: impersonation, and a setting after the first statement.
                "EXECUTE AS USER = 'admin'",
                "exec as login = 'admin'",
                "setuser 'admin'",
                "select 1; set role admin",
                "select 1;\n  /* then */ SET app.tenant = 'A'",
        }) {
            assertTrue(SessionState.sets(sql), sql);
        }
    }

    @Test
    void ordinaryStatementsAreNot() {
        for (String sql : new String[] {
                "select * from settings where name = 'set'",
                "insert into t values (1)",
                "update t set n = 2",
                "delete from t",
                "create table t (n int)",
                "select set_count from reset_log",
                "with x as (select 1) select * from x",
                "call proc(?)",
                "select 'a; set role admin' from dual",
                "select 1; -- ; set role admin\nselect 2",
                "execute procedure_name",
        }) {
            assertFalse(SessionState.sets(sql), sql);
        }
    }

    @Test
    void onlyAlterSessionIsBeyondAReset() {
        SessionState state = new SessionState();
        state.note("set app.tenant_id = 1");
        assertTrue(state.changed());
        assertFalse(state.irreversible());
        state.note("alter session set nls_language = 'GERMAN'");
        assertTrue(state.irreversible());
        state.clear();
        assertFalse(state.changed());
        assertFalse(state.irreversible());
    }
}
