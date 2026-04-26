"""
DB-API 2.0 호환 드라이버를 대상으로 쿼리 자동 감사 로그를 적용하는 패치 모듈.

AuditedDB 없이 기존 코드에서도 모든 DB 쿼리를 자동으로 로그에 기록한다.
install_patch() 한 번만 호출하면 이후 sqlite3.connect() 등 기존 코드가
그대로 동작하면서 execute() 호출마다 감사 로그가 자동 생성된다.

[사용법]

① 프로그램 시작 시 패치 설치 (1회):
    from audit_patch import install_patch, set_audit_context, audit_context
    install_patch()                                  # sqlite3 기본
    install_patch(["sqlite3", "cx_Oracle"])          # 여러 드라이버 동시 패치

② 방식 A — 컨텍스트 매니저 (with 블록 안에서만 해당 사용자로 기록):
    with audit_context(user_id="U001", user_name="홍길동", user_role="analyst",
                       purpose="신용조회", reference_no="CREDIT-001"):
        conn = sqlite3.connect("mydb.db")   # 기존 코드 그대로
        cur  = conn.cursor()
        cur.execute("SELECT * FROM customers")
        rows = cur.fetchall()               # 정상 동작, 로그도 자동 기록

③ 방식 B — 전역 설정 (이후 모든 쿼리에 적용):
    set_audit_context(user_id="U001", user_name="홍길동", user_role="analyst")
    conn = sqlite3.connect("mydb.db")
    cur  = conn.cursor()
    cur.execute("SELECT * FROM customers")
    rows = cur.fetchall()
"""

import importlib
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Optional

from config import DB_SERVER, DB_NAME, DB_SCHEMA
from query_logger import write_query_log


# ══════════════════════════════════════════════════════════════════
# 스레드 로컬 감사 컨텍스트
# ══════════════════════════════════════════════════════════════════

_ctx = threading.local()

_CTX_FIELDS: tuple = (
    ("user_id",          "UNKNOWN"),
    ("user_name",        "UNKNOWN"),
    ("user_role",        "UNKNOWN"),
    ("purpose",          ""),
    ("reference_no",     ""),
    ("client_ip",        None),
    ("execution_method", "애플리케이션"),
    ("session_id",       ""),
)


def set_audit_context(
    user_id:          str           = "UNKNOWN",
    user_name:        str           = "UNKNOWN",
    user_role:        str           = "UNKNOWN",
    purpose:          str           = "",
    reference_no:     str           = "",
    client_ip:        Optional[str] = None,
    execution_method: str           = "애플리케이션",
) -> None:
    """현재 스레드의 감사 컨텍스트(사용자 정보)를 설정한다."""
    _ctx.user_id          = user_id
    _ctx.user_name        = user_name
    _ctx.user_role        = user_role
    _ctx.purpose          = purpose
    _ctx.reference_no     = reference_no
    _ctx.client_ip        = client_ip
    _ctx.execution_method = execution_method
    if not getattr(_ctx, "session_id", ""):
        _ctx.session_id = str(uuid.uuid4())[:8]


def _get_ctx() -> dict:
    return {k: getattr(_ctx, k, d) for k, d in _CTX_FIELDS}


@contextmanager
def audit_context(
    user_id:          str,
    user_name:        str,
    user_role:        str,
    purpose:          str           = "",
    reference_no:     str           = "",
    client_ip:        Optional[str] = None,
    execution_method: str           = "애플리케이션",
):
    """
    with 블록 안에서만 해당 사용자로 감사 로그를 기록한다.
    블록을 벗어나면 이전 컨텍스트로 자동 복원된다.
    """
    saved     = _get_ctx()
    saved_sid = getattr(_ctx, "session_id", "")
    set_audit_context(user_id, user_name, user_role, purpose,
                      reference_no, client_ip, execution_method)
    _ctx.session_id = str(uuid.uuid4())[:8]   # with 블록마다 새 세션 ID
    try:
        yield
    finally:
        for k, v in saved.items():
            setattr(_ctx, k, v)
        _ctx.session_id = saved_sid


# ══════════════════════════════════════════════════════════════════
# 커서 래퍼
# ══════════════════════════════════════════════════════════════════

class _AuditCursor:
    """
    DB-API 2.0 Cursor 프록시.
    execute() 를 인터셉트해 실행 결과를 로그에 기록하고,
    결과 캐시를 통해 fetchall/fetchone/fetchmany/이터레이션을 정상 동작시킨다.
    """

    __slots__ = ("_cur", "_db", "_cache")

    def __init__(self, real_cursor, db_info: dict):
        object.__setattr__(self, "_cur",   real_cursor)
        object.__setattr__(self, "_db",    db_info)
        object.__setattr__(self, "_cache", None)

    # ── 인터셉트 대상 ──────────────────────────────────────────────

    def execute(self, sql: str, parameters=None):
        cur   = object.__getattribute__(self, "_cur")
        db    = object.__getattribute__(self, "_db")
        start = datetime.now()
        status, error, log_rows, affected = "SUCCESS", None, [], 0

        try:
            if parameters is not None:
                cur.execute(sql, parameters)
            else:
                cur.execute(sql)

            first_word = sql.strip().split()[0].upper() if sql.strip() else ""
            if first_word in ("SELECT", "WITH"):
                raw = cur.fetchall()            # 결과 전부 읽어 캐시에 보관
                if raw and hasattr(raw[0], "keys"):
                    log_rows = [dict(r) for r in raw]   # sqlite3.Row → dict
                elif raw:
                    log_rows = [list(r) for r in raw]   # tuple → list
                object.__setattr__(self, "_cache", raw)
            else:
                affected = cur.rowcount or 0
                object.__setattr__(self, "_cache", None)

        except Exception as exc:
            status, error = "FAILURE", str(exc)
            object.__setattr__(self, "_cache", None)
            raise
        finally:
            ctx = _get_ctx()
            write_query_log(
                user_id          = ctx["user_id"],
                user_name        = ctx["user_name"],
                user_role        = ctx["user_role"],
                client_ip        = ctx["client_ip"],
                db_server        = db["db_server"],
                db_name          = db["db_name"],
                db_schema        = db["db_schema"],
                sql              = sql,
                parameters       = (list(parameters)
                                    if isinstance(parameters, (list, tuple))
                                    else parameters),
                execution_method = ctx["execution_method"],
                session_id       = ctx["session_id"],
                purpose          = ctx["purpose"],
                reference_no     = ctx["reference_no"],
                start_time       = start,
                end_time         = datetime.now(),
                status           = status,
                affected_rows    = affected,
                result_data      = log_rows if log_rows else None,
                error_message    = error,
            )
        return self

    def executemany(self, sql: str, seq_of_parameters):
        """여러 파라미터 배치 실행 — 1건의 로그로 통합 기록."""
        cur   = object.__getattribute__(self, "_cur")
        db    = object.__getattribute__(self, "_db")
        start = datetime.now()
        status, error, affected = "SUCCESS", None, 0

        try:
            cur.executemany(sql, seq_of_parameters)
            affected = cur.rowcount or 0
        except Exception as exc:
            status, error = "FAILURE", str(exc)
            raise
        finally:
            ctx = _get_ctx()
            write_query_log(
                user_id          = ctx["user_id"],
                user_name        = ctx["user_name"],
                user_role        = ctx["user_role"],
                client_ip        = ctx["client_ip"],
                db_server        = db["db_server"],
                db_name          = db["db_name"],
                db_schema        = db["db_schema"],
                sql              = sql,
                parameters       = None,
                execution_method = ctx["execution_method"],
                session_id       = ctx["session_id"],
                purpose          = ctx["purpose"],
                reference_no     = ctx["reference_no"],
                start_time       = start,
                end_time         = datetime.now(),
                status           = status,
                affected_rows    = affected,
                result_data      = None,
                error_message    = error,
            )
        object.__setattr__(self, "_cache", None)
        return self

    # ── fetch 계열: 캐시에서 소비 ──────────────────────────────────

    def fetchall(self):
        cache = object.__getattribute__(self, "_cache")
        if cache is not None:
            object.__setattr__(self, "_cache", None)
            return cache
        return object.__getattribute__(self, "_cur").fetchall()

    def fetchone(self):
        cache = object.__getattribute__(self, "_cache")
        if cache is not None:
            if cache:
                row = cache[0]
                object.__setattr__(self, "_cache", cache[1:])
                return row
            return None
        return object.__getattribute__(self, "_cur").fetchone()

    def fetchmany(self, size=None):
        cache = object.__getattribute__(self, "_cache")
        if cache is not None:
            sz     = size if size is not None else self.arraysize
            result = cache[:sz]
            object.__setattr__(self, "_cache", cache[sz:])
            return result
        cur = object.__getattribute__(self, "_cur")
        return cur.fetchmany() if size is None else cur.fetchmany(size)

    def __iter__(self):
        cache = object.__getattribute__(self, "_cache")
        if cache is not None:
            object.__setattr__(self, "_cache", None)
            return iter(cache)
        return iter(object.__getattribute__(self, "_cur"))

    # ── 나머지 속성·메서드는 실제 커서에 위임 ─────────────────────

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_cur"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_cur"), name, value)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        object.__getattribute__(self, "_cur").close()

    def close(self):
        object.__getattribute__(self, "_cur").close()


# ══════════════════════════════════════════════════════════════════
# 연결 래퍼
# ══════════════════════════════════════════════════════════════════

class _AuditConnection:
    """
    DB-API 2.0 Connection 프록시.
    cursor() 호출 시 _AuditCursor를 반환한다.
    commit/rollback/close/row_factory 등 나머지는 실제 연결에 위임한다.
    """

    __slots__ = ("_conn", "_db")

    def __init__(self, real_conn, db_info: dict):
        object.__setattr__(self, "_conn", real_conn)
        object.__setattr__(self, "_db",   db_info)

    def cursor(self, *args, **kwargs):
        conn = object.__getattribute__(self, "_conn")
        db   = object.__getattribute__(self, "_db")
        return _AuditCursor(conn.cursor(*args, **kwargs), db)

    def execute(self, sql, parameters=None):
        """sqlite3 등이 제공하는 connection-level execute 단축키 지원."""
        cur = self.cursor()
        cur.execute(sql, parameters)
        return cur

    def executemany(self, sql, seq_of_parameters):
        cur = self.cursor()
        cur.executemany(sql, seq_of_parameters)
        return cur

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_conn"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_conn"), name, value)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        object.__getattribute__(self, "_conn").__exit__(exc_type, exc_val, exc_tb)

    def close(self):
        object.__getattribute__(self, "_conn").close()


# ══════════════════════════════════════════════════════════════════
# 패치 설치 / 제거
# ══════════════════════════════════════════════════════════════════

_originals: dict[str, tuple] = {}   # {모듈명: (모듈객체, 원본 connect)}


def _extract_db_name(module_name: str, args, kwargs) -> str:
    """드라이버별로 DB 식별 이름을 추출한다."""
    if module_name == "sqlite3":
        return str(args[0]) if args else kwargs.get("database", "sqlite_db")
    if module_name in ("cx_Oracle", "oracledb"):
        return kwargs.get("dsn", str(args[0]) if args else "oracle_db")
    if module_name == "pyodbc":
        import re as _re
        s = str(args[0]) if args else kwargs.get("dsn", "")
        m = _re.search(r"(?i)(?:DATABASE|DBQ|DSN)=([^;]+)", s)
        return m.group(1) if m else (s[:40] or "mssql_db")
    if module_name in ("psycopg2", "psycopg"):
        return kwargs.get("dbname", kwargs.get("database",
               str(args[0]) if args else "postgres_db"))
    if module_name == "pymysql":
        return kwargs.get("db", kwargs.get("database", "mysql_db"))
    return str(args[0]) if args else module_name


def _make_patched_connect(module_name: str, original_connect):
    def patched_connect(*args, **kwargs):
        conn    = original_connect(*args, **kwargs)
        db_info = {
            "db_server": DB_SERVER,
            "db_name":   DB_NAME or _extract_db_name(module_name, args, kwargs),
            "db_schema": DB_SCHEMA,
        }
        return _AuditConnection(conn, db_info)
    return patched_connect


def install_patch(modules: Optional[list[str]] = None) -> None:
    """
    지정 드라이버의 connect()를 패치한다. modules 생략 시 sqlite3만 패치.
    설치되지 않은 드라이버는 조용히 건너뛴다.

    지원 드라이버: sqlite3, cx_Oracle, oracledb, pyodbc, psycopg2, psycopg, pymysql
    예) install_patch(["sqlite3", "cx_Oracle", "pyodbc"])
    """
    if modules is None:
        modules = ["sqlite3"]

    for mod_name in modules:
        if mod_name in _originals:
            continue
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:
            continue
        orig                 = mod.connect
        _originals[mod_name] = (mod, orig)
        mod.connect          = _make_patched_connect(mod_name, orig)


def uninstall_patch() -> None:
    """설치된 패치를 모두 제거하고 원래 connect()로 복원한다."""
    for mod, orig in _originals.values():
        mod.connect = orig
    _originals.clear()
