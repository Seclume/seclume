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

    /**
     * The filters in front of the two expressions change no verdict: every
     * statement is judged the same as by the expressions alone - the words
     * each alternative starts with, in any case, behind comments and
     * parentheses, in batches, and thousands of statements put together from
     * the pieces at random.
     */
    @Test
    void theFiltersChangeNoVerdict() {
        java.util.regex.Pattern leading = java.util.regex.Pattern.compile(
                "^(set|use|prepare|listen|alter\\s+session|exec(ute)?\\s+as\\s|setuser"
                        + "|create\\s+(local\\s+|global\\s+)?temp(orary)?\\s"
                        + "|create\\s+table\\s+#"
                        + "|declare\\s+\\S+\\s+(binary\\s+)?(insensitive\\s+)?(no\\s+)?(scroll\\s+)?"
                        + "cursor\\s+with\\s+hold)",
                java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Pattern anywhere = java.util.regex.Pattern.compile(
                "set_config\\s*\\(|dbms_session\\s*\\.|dbms_application_info\\s*\\."
                        + "|sp_setapprole|sp_set_session_context|context_info"
                        + "|pg_advisory_lock\\s*\\(|pg_try_advisory_lock\\s*\\(|get_lock\\s*\\("
                        + "|\\binto\\s+#|@\\w+\\s*:=",
                java.util.regex.Pattern.CASE_INSENSITIVE);
        String[] pieces = {"select 1", "SET search_path = x", "Use db", "prepare p as select 1",
            "LISTEN ch", "alter session set x", "Alter Table t", "exec as user = 'u'",
            "EXECUTE AS LOGIN = 'l'", "setuser 'u'", "create temp table t (a int)",
            "CREATE GLOBAL TEMPORARY TABLE t (a int)", "create table #t (a int)",
            "create table t (a int)", "declare c cursor with hold for select 1",
            "declare c binary insensitive no scroll cursor with hold for select 1",
            "select set_config('a', 'b', false)", "begin dbms_session.set_role('r'); end;",
            "call DBMS_APPLICATION_INFO.set_module('m', null)", "exec sp_setapprole 'r', 'p'",
            "exec sp_set_session_context 'k', 'v'", "set context_info 0x1",
            "select pg_advisory_lock(1)", "select pg_try_advisory_lock (1)",
            "select get_lock('l', 1)", "select a into #t from x", "select @a := 1",
            "select a_b from t", "select '#' from t", "select '@x' from t", "update t set a = 1",
            "insert into t values (1)", "delete from t", "  /* c */ ( set x = 1 )",
            "-- c\nuse db", "setting", "settle", "users", "execution", "select 1; set role admin"};
        java.util.Random random = new java.util.Random(46);
        for (int i = 0; i < 20_000; i++) {
            StringBuilder sql = new StringBuilder();
            int parts = 1 + random.nextInt(3);
            for (int p = 0; p < parts; p++) {
                sql.append(p > 0 ? "; " : "").append(pieces[random.nextInt(pieces.length)]);
            }
            String text = random.nextBoolean() ? sql.toString() : sql.toString().toUpperCase(
                    java.util.Locale.ROOT);
            SessionState state = new SessionState();
            state.note(text);
            assertTrue(state.changed() == reference(text, leading, anywhere), text);
        }
    }

    /** The expressions alone, on the same statement boundaries note() uses. */
    private static boolean reference(String sql, java.util.regex.Pattern leading,
            java.util.regex.Pattern anywhere) {
        if (anywhere.matcher(sql).find()) {
            return true;
        }
        for (String statement : sql.split(";")) {
            String start = statement.replaceAll("^(\\s|\\(|/\\*.*?\\*/|--[^\\n]*\\n)*", "");
            if (leading.matcher(start).find()) {
                return true;
            }
        }
        return false;
    }
}
