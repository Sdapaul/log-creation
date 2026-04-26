"""
DB 연결 래퍼 - 쿼리 수행 시 감사 로그를 자동으로 생성한다.

사용 예)
    db = AuditedDB(user_id="U001", user_name="홍길동", user_role="analyst",
                   purpose="고객 신용정보 조회", reference_no="TKT-001")
    rows = db.execute("SELECT * FROM customers WHERE id = ?", (1,))
    db.close()
"""

import sqlite3
import uuid
from datetime import datetime
from typing import Any, Optional

from config import DEMO_DB_PATH, DB_SERVER, DB_NAME, DB_SCHEMA
from query_logger import write_query_log


class AuditedDB:
    """쿼리 자동 감사 로그가 붙는 DB 연결 객체."""

    def __init__(
        self,
        *,
        user_id: str,
        user_name: str,
        user_role: str,
        purpose: str = "",
        reference_no: str = "",
        client_ip: Optional[str] = None,
        db_path: str = DEMO_DB_PATH,
        execution_method: str = "애플리케이션",
    ):
        self.user_id          = user_id
        self.user_name        = user_name
        self.user_role        = user_role
        self.purpose          = purpose
        self.reference_no     = reference_no
        self.client_ip        = client_ip
        self.execution_method = execution_method
        self.session_id       = str(uuid.uuid4())[:8]

        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row   # 컬럼명 포함 결과 반환

    # ── 단일 쿼리 수행 ──────────────────────────

    def execute(
        self,
        sql: str,
        parameters: Any = None,
        purpose_override: Optional[str] = None,
    ) -> list[dict]:
        """
        SQL을 수행하고 결과를 list[dict] 형태로 반환한다.
        수행 내역과 결과는 자동으로 감사 로그에 기록된다.
        """
        start = datetime.now()
        status, error, rows, affected = "SUCCESS", None, [], 0

        try:
            cursor = self._conn.cursor()
            if parameters:
                cursor.execute(sql, parameters)
            else:
                cursor.execute(sql)

            if sql.strip().upper().startswith("SELECT"):
                raw = cursor.fetchall()
                rows = [dict(r) for r in raw]
            else:
                self._conn.commit()
                affected = cursor.rowcount
                rows = []

        except Exception as exc:
            status = "FAILURE"
            error  = str(exc)
            try:
                self._conn.rollback()
            except Exception:
                pass

        end = datetime.now()

        write_query_log(
            user_id          = self.user_id,
            user_name        = self.user_name,
            user_role        = self.user_role,
            client_ip        = self.client_ip,
            db_server        = DB_SERVER,
            db_name          = DB_NAME,
            db_schema        = DB_SCHEMA,
            sql              = sql,
            parameters       = list(parameters) if parameters else None,
            execution_method = self.execution_method,
            session_id       = self.session_id,
            purpose          = purpose_override or self.purpose,
            reference_no     = self.reference_no,
            start_time       = start,
            end_time         = end,
            status           = status,
            affected_rows    = affected,
            result_data      = rows if rows else None,
            error_message    = error,
        )

        if status == "FAILURE":
            raise RuntimeError(f"쿼리 수행 실패: {error}")
        return rows

    # ── 트랜잭션 헬퍼 ──────────────────────────

    def execute_many(self, queries: list[tuple[str, Any]]) -> list[list[dict]]:
        """여러 쿼리를 순차 수행하고 각 결과를 반환한다. 하나라도 실패하면 전체 롤백."""
        results = []
        try:
            for sql, params in queries:
                results.append(self.execute(sql, params))
        except Exception:
            self._conn.rollback()
            raise
        return results

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
