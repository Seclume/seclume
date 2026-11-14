"""Does Oracle's RESET_STATE clear a pooled session at the end of a request?

A probe, not a test of seclume: python-oracledb's thin driver marks request
boundaries (the TTC session-state piggyback) when it lends and takes back a
pooled connection. For services with reset_state NONE, LEVEL1 and LOGIN, a
session is given every kind of state the pool's relogin is checked against,
returned, lent again, and read back - and the cost of a borrow is timed.
"""
import os
import sys
import time

import oracledb

HOST = "127.0.0.1:1521"
PDB = "FREEPDB1"
SYS_PASSWORD = os.environ["ORACLE_PASSWORD"]
APP_PASSWORD = os.environ["APP_PASSWORD"]


def run(cur, sql):
    try:
        cur.execute(sql)
    except oracledb.DatabaseError as e:
        print(f"  ! {sql[:70]}: {e}")


def setup():
    with oracledb.connect(user="system", password=SYS_PASSWORD, dsn=f"{HOST}/{PDB}") as c:
        cur = c.cursor()
        print("server:", c.version)
        for grant in ("create any context", "alter session", "create sequence",
                      "select any dictionary"):
            run(cur, f"grant {grant} to seclume_test")
        for level in ("NONE", "LEVEL1", "LOGIN"):
            name = f"zl_reset_{level.lower()}"
            run(cur, f"""
                declare p dbms_service.svc_parameter_array;
                begin p('reset_state') := '{level}';
                  dbms_service.create_service('{name}', '{name}', p);
                end;""")
            run(cur, f"begin dbms_service.start_service('{name}'); end;")
        cur.execute("select name, reset_state from dba_services where name like 'zl_reset%' order by 1")
        print("services:", cur.fetchall())
    with oracledb.connect(user="seclume_test", password=APP_PASSWORD, dsn=f"{HOST}/{PDB}") as c:
        cur = c.cursor()
        run(cur, "create global temporary table zl_probe_gtt (n number) on commit preserve rows")
        run(cur, "create sequence zl_probe_seq")
        run(cur, "create or replace package zl_probe_pkg as n number := 0; "
                 "function get_n return number; procedure set_ctx(v varchar2); end;")
        run(cur, "create or replace package body zl_probe_pkg as "
                 "function get_n return number is begin return n; end; "
                 "procedure set_ctx(v varchar2) is begin "
                 "dbms_session.set_context('zl_probe_ctx', 'k', v); end; end;")
        run(cur, "create or replace context zl_probe_ctx using zl_probe_pkg")


STATE = [
    ("client identifier", "select nvl(sys_context('userenv','client_identifier'),'-') from dual"),
    ("application context", "select nvl(sys_context('zl_probe_ctx','k'),'-') from dual"),
    ("package variable", "select to_char(zl_probe_pkg.get_n) from dual"),
    ("NLS_DATE_FORMAT", "select value from nls_session_parameters where parameter = 'NLS_DATE_FORMAT'"),
    ("time zone", "select sessiontimezone from dual"),
    ("current schema", "select sys_context('userenv','current_schema') from dual"),
    ("roles", "select to_char(count(*)) from session_roles"),
    ("temporary table rows", "select to_char(count(*)) from seclume_test.zl_probe_gtt"),
    ("module", "select nvl(sys_context('userenv','module'),'-') from dual"),
    ("action", "select nvl(sys_context('userenv','action'),'-') from dual"),
    ("client info", "select nvl(sys_context('userenv','client_info'),'-') from dual"),
    ("optimizer_mode", "select value from v$parameter where name = 'optimizer_mode'"),
    ("sql_trace", "select value from v$parameter where name = 'sql_trace'"),
    ("sequence currval", "select to_char(seclume_test.zl_probe_seq.currval) from dual"),
    ("session id", "select sys_context('userenv','sid') || '/' || sys_context('userenv','sessionid') from dual"),
]

DIRTY = [
    "begin dbms_session.set_identifier('tenant-A'); end;",
    "begin seclume_test.zl_probe_pkg.set_ctx('tenant-A'); end;",
    "begin seclume_test.zl_probe_pkg.n := 42; end;",
    "alter session set nls_date_format = 'YYYY'",
    "alter session set time_zone = '+05:00'",
    "insert into seclume_test.zl_probe_gtt values (1)",
    "commit",
    "begin dbms_application_info.set_module('mod-A', 'act-A'); end;",
    "begin dbms_application_info.set_client_info('info-A'); end;",
    "alter session set optimizer_mode = first_rows_1",
    "alter session set sql_trace = true",
    "select seclume_test.zl_probe_seq.nextval from dual",
    "set role none",
    "alter session set current_schema = system",
]


def read(cur):
    out = {}
    for name, sql in STATE:
        try:
            cur.execute(sql)
            out[name] = str(cur.fetchone()[0])
        except oracledb.DatabaseError as e:
            out[name] = "error " + str(e).split(":")[0]
    return out


def probe(service):
    print(f"\n== service {service}")
    pool = oracledb.create_pool(user="seclume_test", password=APP_PASSWORD,
                                dsn=f"{HOST}/{service}", min=1, max=1, increment=0)
    with pool.acquire() as c:
        fresh = read(c.cursor())
    c = pool.acquire()
    cur = c.cursor()
    for sql in DIRTY:
        run(cur, sql)
    dirty = read(cur)
    pool.release(c)
    with pool.acquire() as c:
        after = read(c.cursor())
    print(f"  {'state':22} {'fresh':>16} {'set':>16} {'next borrow':>16}")
    for name, _ in STATE:
        flag = "" if name == "session id" else (
            "  CLEARED" if after[name] == fresh[name] and dirty[name] != fresh[name]
            else "  LEFT" if after[name] == dirty[name] and dirty[name] != fresh[name] else "")
        print(f"  {name:22} {fresh[name]:>16} {dirty[name]:>16} {after[name]:>16}{flag}")
    # The cost of a borrow: acquire, one query, release.
    for label, dirty_first in (("clean borrow", False), ("dirty borrow", True)):
        n = 500
        start = time.perf_counter()
        for _ in range(n):
            c = pool.acquire()
            cur = c.cursor()
            if dirty_first:
                cur.execute("begin dbms_session.set_identifier('x'); end;")
            cur.execute("select 1 from dual")
            cur.fetchone()
            pool.release(c)
        print(f"  {label}: {(time.perf_counter() - start) / n * 1e6:.0f} us per borrow, query and return")
    pool.close()


def relogin_cost():
    n = 100
    start = time.perf_counter()
    for _ in range(n):
        oracledb.connect(user="seclume_test", password=APP_PASSWORD, dsn=f"{HOST}/{PDB}").close()
    print(f"\n== a new connection with python-oracledb: {(time.perf_counter() - start) / n * 1e3:.2f} ms")


if __name__ == "__main__":
    setup()
    for service in (PDB, "zl_reset_none", "zl_reset_level1", "zl_reset_login"):
        try:
            probe(service)
        except oracledb.DatabaseError as e:
            print(f"  ! {service}: {e}")
    relogin_cost()
    sys.exit(0)
