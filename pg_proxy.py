"""
PostgreSQL 감사 프록시 — Superset ↔ PostgreSQL 쿼리 자동 감사 로그

[구성]
  Superset ──TCP(평문)──▶  PgProxy :5433  ──TCP──▶  PostgreSQL :5432 (Azure/RedHat9.7)

[Superset 설정 변경]
  Settings → Database Connections → SQLAlchemy URI 를 프록시 주소로 변경:
    postgresql+psycopg2://user:pass@<프록시IP>:5433/dbname?sslmode=disable
  Superset 와 DB 서버 간 암호화가 없으므로(sslmode=disable) 정상 동작.

[Oracle 프록시와 비교]
    oracle_proxy.py : Oracle TNS 프로토콜 (포트 1521/1522)
    pg_proxy.py     : PostgreSQL Wire Protocol v3 (포트 5432/5433)

[제약]
  · SSL/TLS 연결(sslmode=require/verify-*): SQL 추출 불가
  · 평문 연결(sslmode=disable) 전용 — 현재 Superset ↔ Azure PG 구성과 일치
  · root 권한 불필요 (pg_sniffer.py 와 달리 일반 사용자로 실행 가능)
  · 프록시가 재시작되면 기존 Superset 연결이 끊김 (재접속 필요)

[구동]
  python pg_proxy.py
  python pg_proxy.py --pg-host 10.0.0.1 --pg-port 5432 --listen-port 5433
  python pg_proxy.py --pg-host azure-pg.internal --db-name superset --db-schema public
"""

import asyncio
import argparse
import logging
import struct
import uuid
from datetime import datetime
from typing import Optional

from config import PG_HOST as _CFG_PG_HOST, PG_PORT as _CFG_PG_PORT
from config import PG_DB as _CFG_PG_DB, PG_SCHEMA as _CFG_PG_SCHEMA
from query_logger import write_query_log

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PgProxy] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
_log = logging.getLogger("pg_proxy")

_PG_SSL_REQUEST_CODE = 80877103     # 0x04D2162F
_MAX_MSG_SIZE        = 16_777_216   # 16 MB


# ══════════════════════════════════════════════════════════════════
# PostgreSQL Wire Protocol 스트림 버퍼
# (pg_sniffer.py 와 동일 구조 — 프록시는 TCP 스트림을 직접 수신하므로
#  raw socket/IP 파싱 없이 메시지 단위 분리만 수행)
# ══════════════════════════════════════════════════════════════════

class _ClientBuffer:
    """클라이언트→서버 스트림을 PostgreSQL 메시지 단위로 분리한다."""

    _ST_STARTUP = 0
    _ST_NORMAL  = 1
    _ST_SSL     = 2

    def __init__(self):
        self._buf   = bytearray()
        self._state = self._ST_STARTUP

    def feed(self, data: bytes) -> list[tuple[str, bytes]]:
        if self._state == self._ST_SSL:
            return []
        self._buf.extend(data)
        out: list[tuple[str, bytes]] = []

        while True:
            if self._state == self._ST_STARTUP:
                if len(self._buf) < 8:
                    break
                msg_len = struct.unpack_from(">I", self._buf, 0)[0]
                if msg_len < 8 or msg_len > _MAX_MSG_SIZE:
                    self._buf.clear()
                    break
                if len(self._buf) < msg_len:
                    break
                code    = struct.unpack_from(">I", self._buf, 4)[0]
                payload = bytes(self._buf[8:msg_len])
                del self._buf[:msg_len]
                if code == _PG_SSL_REQUEST_CODE:
                    out.append(('ssl_request', b''))
                else:
                    out.append(('startup', payload))
                    self._state = self._ST_NORMAL

            elif self._state == self._ST_NORMAL:
                if len(self._buf) < 5:
                    break
                mtype = chr(self._buf[0])
                mlen  = struct.unpack_from(">I", self._buf, 1)[0]
                total = 1 + mlen
                if mlen < 4 or total > _MAX_MSG_SIZE:
                    self._buf.clear()
                    break
                if len(self._buf) < total:
                    break
                payload = bytes(self._buf[5:total])
                del self._buf[:total]
                out.append((mtype, payload))
            else:
                break

        return out

    def set_ssl(self):
        self._state = self._ST_SSL


class _ServerBuffer:
    """서버→클라이언트 스트림을 PostgreSQL 메시지 단위로 분리한다."""

    _ST_SSL_RESPONSE = 0
    _ST_NORMAL       = 1
    _ST_SSL          = 2

    def __init__(self):
        self._buf   = bytearray()
        self._state = self._ST_NORMAL

    def expect_ssl_response(self):
        self._state = self._ST_SSL_RESPONSE

    def feed(self, data: bytes) -> list[tuple[str, bytes]]:
        if self._state == self._ST_SSL:
            return []
        self._buf.extend(data)
        out: list[tuple[str, bytes]] = []

        while True:
            if self._state == self._ST_SSL_RESPONSE:
                if len(self._buf) < 1:
                    break
                resp = chr(self._buf[0])
                del self._buf[:1]
                if resp == 'S':
                    self._state = self._ST_SSL
                    out.append(('ssl_active', b''))
                else:
                    self._state = self._ST_NORMAL
                    out.append(('ssl_rejected', b''))

            elif self._state == self._ST_NORMAL:
                if len(self._buf) < 5:
                    break
                mtype = chr(self._buf[0])
                mlen  = struct.unpack_from(">I", self._buf, 1)[0]
                total = 1 + mlen
                if mlen < 4 or total > _MAX_MSG_SIZE:
                    self._buf.clear()
                    break
                if len(self._buf) < total:
                    break
                payload = bytes(self._buf[5:total])
                del self._buf[:total]
                out.append((mtype, payload))
            else:
                break

        return out


# ══════════════════════════════════════════════════════════════════
# 세션 상태 관리
# ══════════════════════════════════════════════════════════════════

class _PgSession:
    """
    Superset ↔ PostgreSQL 세션의 쿼리 실행 상태를 추적한다.

    Simple Query 흐름:
      클라이언트 'Q' → SQL 기록 시작
      서버 'C'(CommandComplete) → 로그 기록

    Extended Query 흐름 (Superset/SQLAlchemy가 주로 사용):
      클라이언트 'P'(Parse) → prepared statement SQL 저장
      클라이언트 'E'(Execute) → SQL 실행 시작
      서버 'C'(CommandComplete) → 로그 기록
    """

    def __init__(self, client_ip: str, pg_host: str, db_name: str, db_schema: str):
        self.client_ip  = client_ip
        self.pg_host    = pg_host
        self.db_name    = db_name
        self.db_schema  = db_schema
        self.session_id = str(uuid.uuid4())[:8]
        self.pg_user    = "UNKNOWN"
        self._ssl_active = False

        self._sql:         Optional[str]      = None
        self._start:       Optional[datetime] = None
        self._status:      str                = "SUCCESS"
        self._error:       Optional[str]      = None
        self._row_count:   int                = 0
        self._result_data: list[str]          = []

        # Extended Query: prepared statement 이름 → SQL
        self._named_stmts: dict[str, str] = {}
        self._unnamed_sql: str            = ""

    # ── 클라이언트 메시지 처리 ────────────────────────────────────

    def on_client(self, mtype: str, payload: bytes) -> None:
        if self._ssl_active:
            return

        if mtype == 'startup':
            self._parse_startup(payload)

        elif mtype == 'Q':                          # Simple Query
            sql = payload.rstrip(b'\x00').decode('utf-8', errors='ignore').strip()
            if sql:
                self._begin(sql)

        elif mtype == 'P':                          # Parse (Extended Query)
            null1 = payload.find(b'\x00')
            if null1 < 0:
                return
            name = payload[:null1].decode('utf-8', errors='ignore')
            rest = payload[null1 + 1:]
            null2 = rest.find(b'\x00')
            if null2 < 0:
                return
            sql = rest[:null2].decode('utf-8', errors='ignore').strip()
            if name:
                self._named_stmts[name] = sql
            else:
                self._unnamed_sql = sql

        elif mtype == 'E':                          # Execute
            null1 = payload.find(b'\x00')
            portal = payload[:null1].decode('utf-8', errors='ignore') if null1 >= 0 else ''
            sql = self._named_stmts.get(portal) or self._unnamed_sql
            if sql:
                self._begin(sql)

        elif mtype == 'X':                          # Terminate
            self.flush()

    # ── 서버 메시지 처리 ──────────────────────────────────────────

    def on_server(self, mtype: str, payload: bytes) -> None:
        if mtype == 'ssl_active':
            self._ssl_active = True
            _log.warning(
                "[%s/%s] SSL 암호화 연결 — SQL 캡처 불가 "
                "(Superset DB URI 에 sslmode=disable 추가 필요)",
                self.client_ip, self.session_id,
            )
            return

        if self._ssl_active:
            return

        if mtype == 'D':                            # DataRow
            self._on_datarow(payload)

        elif mtype == 'C':                          # CommandComplete
            tag = payload.rstrip(b'\x00').decode('utf-8', errors='ignore')
            self._on_complete(tag)

        elif mtype == 'E':                          # ErrorResponse
            fields = _parse_error_response(payload)
            self._status = "FAILURE"
            self._error  = fields.get('M', 'PostgreSQL error')
            if self._sql:
                self._write_log()

    # ── 내부 ──────────────────────────────────────────────────────

    def _parse_startup(self, payload: bytes) -> None:
        """Startup 메시지에서 pg_user, db_name 을 추출한다."""
        parts = payload.split(b'\x00')
        i = 0
        while i + 1 < len(parts):
            key = parts[i].decode('utf-8', errors='ignore')
            val = parts[i + 1].decode('utf-8', errors='ignore')
            if key == 'user' and val:
                self.pg_user = val
            elif key == 'database' and val:
                self.db_name = val
            i += 2

    def _begin(self, sql: str) -> None:
        if self._sql:
            self._write_log()
        self._sql         = sql
        self._start       = datetime.now()
        self._status      = "SUCCESS"
        self._error       = None
        self._row_count   = 0
        self._result_data = []

    def _on_datarow(self, payload: bytes) -> None:
        """DataRow 메시지에서 셀 값을 추출해 누적한다."""
        if len(payload) < 2:
            return
        num_cols = struct.unpack_from(">H", payload, 0)[0]
        off = 2
        for _ in range(num_cols):
            if off + 4 > len(payload):
                break
            col_len = struct.unpack_from(">i", payload, off)[0]   # signed; NULL = -1
            off += 4
            if col_len < 0:
                continue
            if off + col_len > len(payload):
                break
            val = payload[off: off + col_len].decode('utf-8', errors='ignore')
            if len(self._result_data) < 500:
                self._result_data.append(val)
            off += col_len
        self._row_count += 1

    def _on_complete(self, tag: str) -> None:
        # tag 예: "SELECT 10" / "INSERT 0 1" / "UPDATE 3"
        parts = tag.split()
        if not parts:
            return
        cmd = parts[0].upper()
        if cmd in ("BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "SET", "SHOW"):
            return

        if len(parts) >= 2:
            try:
                n = int(parts[-1])
                if self._row_count == 0:
                    self._row_count = n
            except ValueError:
                pass

        if self._sql:
            self._write_log()

    def _write_log(self) -> None:
        if not self._sql or not self._start:
            return
        end = datetime.now()
        is_select = self._sql.strip().split()[0].upper() == "SELECT" if self._sql.strip() else False

        try:
            write_query_log(
                user_id          = self.pg_user,
                user_name        = self.pg_user,
                user_role        = "SupersetUser",
                client_ip        = self.client_ip,
                db_server        = self.pg_host,
                db_name          = self.db_name,
                db_schema        = self.db_schema,
                sql              = self._sql,
                parameters       = None,
                execution_method = "PG Proxy",
                session_id       = self.session_id,
                purpose          = "",
                reference_no     = "",
                start_time       = self._start,
                end_time         = end,
                status           = self._status,
                affected_rows    = 0 if is_select else self._row_count,
                result_data      = self._result_data if is_select else None,
                error_message    = self._error,
            )
        except Exception as exc:
            _log.error("로그 기록 실패: %s", exc)

        self._sql         = None
        self._start       = None
        self._status      = "SUCCESS"
        self._error       = None
        self._row_count   = 0
        self._result_data = []

    def flush(self) -> None:
        """세션 종료 시 미완료 쿼리를 로그에 기록한다."""
        if self._sql:
            self._write_log()


# ══════════════════════════════════════════════════════════════════
# 공유 유틸
# ══════════════════════════════════════════════════════════════════

def _parse_error_response(payload: bytes) -> dict[str, str]:
    """PostgreSQL ErrorResponse 메시지에서 필드 코드→값 딕셔너리를 추출한다."""
    fields: dict[str, str] = {}
    off = 0
    while off < len(payload):
        code = payload[off]
        if code == 0:
            break
        off += 1
        null = payload.find(b'\x00', off)
        if null < 0:
            break
        fields[chr(code)] = payload[off:null].decode('utf-8', errors='ignore')
        off = null + 1
    return fields


# ══════════════════════════════════════════════════════════════════
# 프록시 서버
# ══════════════════════════════════════════════════════════════════

class PgProxy:
    """
    Superset → PostgreSQL 감사 프록시 서버.

    oracle_proxy.py 와 동일한 asyncio 비동기 TCP 프록시 구조.
    클라이언트(Superset) 연결 1개당 2개의 coroutine(C→PG, PG→C)이 동시 실행된다.

    raw socket 없이 TCP 스트림을 직접 수신하므로 root 권한이 불필요하다.
    """

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 5433,
        pg_host:     str = "localhost",
        pg_port:     int = 5432,
        db_name:     str = "",
        db_schema:   str = "",
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.pg_host     = pg_host
        self.pg_port     = pg_port
        self.db_name     = db_name   or _CFG_PG_DB    or "postgres"
        self.db_schema   = db_schema or _CFG_PG_SCHEMA or "public"

    async def start(self) -> None:
        server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port,
        )
        addrs = [str(s.getsockname()) for s in server.sockets]
        _log.info("PG 프록시 시작: %s → %s:%d", addrs, self.pg_host, self.pg_port)
        _log.info(
            "Superset DB URI 예시: "
            "postgresql+psycopg2://user:pass@<프록시IP>:%d/%s?sslmode=disable",
            self.listen_port, self.db_name,
        )
        async with server:
            await server.serve_forever()

    async def _handle_client(
        self,
        c_reader: asyncio.StreamReader,
        c_writer: asyncio.StreamWriter,
    ) -> None:
        """Superset 클라이언트 연결 1개를 처리한다."""
        peer      = c_writer.get_extra_info('peername')
        client_ip = peer[0] if peer else "UNKNOWN"
        session   = _PgSession(client_ip, self.pg_host, self.db_name, self.db_schema)
        c_buf     = _ClientBuffer()
        s_buf     = _ServerBuffer()
        _log.info("[%s] Superset 연결 수립", client_ip)

        try:
            pg_reader, pg_writer = await asyncio.open_connection(self.pg_host, self.pg_port)
        except Exception as exc:
            _log.error("[%s] PostgreSQL(%s:%d) 연결 실패: %s",
                       client_ip, self.pg_host, self.pg_port, exc)
            c_writer.close()
            return

        async def _c2pg() -> None:
            """Superset → PostgreSQL 방향: 클라이언트 메시지 파싱 후 전달."""
            try:
                while True:
                    data = await c_reader.read(65536)
                    if not data:
                        break
                    for mtype, payload in c_buf.feed(data):
                        if mtype == 'ssl_request':
                            s_buf.expect_ssl_response()
                        session.on_client(mtype, payload)
                    pg_writer.write(data)
                    await pg_writer.drain()
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as exc:
                _log.debug("[%s] C→PG 오류: %s", client_ip, exc)
            finally:
                try:
                    pg_writer.close()
                    await pg_writer.wait_closed()
                except Exception:
                    pass

        async def _pg2c() -> None:
            """PostgreSQL → Superset 방향: 서버 메시지 파싱 후 전달."""
            try:
                while True:
                    data = await pg_reader.read(65536)
                    if not data:
                        break
                    for mtype, payload in s_buf.feed(data):
                        if mtype == 'ssl_active':
                            c_buf.set_ssl()
                        session.on_server(mtype, payload)
                    c_writer.write(data)
                    await c_writer.drain()
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as exc:
                _log.debug("[%s] PG→C 오류: %s", client_ip, exc)
            finally:
                try:
                    c_writer.close()
                    await c_writer.wait_closed()
                except Exception:
                    pass

        t_c2pg = asyncio.create_task(_c2pg())
        t_pg2c = asyncio.create_task(_pg2c())

        try:
            done, pending = await asyncio.wait(
                [t_c2pg, t_pg2c],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        finally:
            session.flush()
            _log.info("[%s] 연결 종료 (세션 %s, 사용자 %s)",
                      client_ip, session.session_id, session.pg_user)


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "PostgreSQL 감사 프록시 — Superset 쿼리 자동 로깅\n"
            "암호화 없는 연결(sslmode=disable) 전용 | root 권한 불필요"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--listen-host", default="0.0.0.0",
                        help="프록시 바인딩 주소 (기본: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=5433,
                        help="Superset이 연결할 프록시 포트 (기본: 5433)")
    parser.add_argument("--pg-host", default=_CFG_PG_HOST or "localhost",
                        help="실제 PostgreSQL 서버 호스트 (config.py PG_HOST)")
    parser.add_argument("--pg-port", type=int, default=_CFG_PG_PORT or 5432,
                        help="실제 PostgreSQL 서버 포트 (기본: 5432)")
    parser.add_argument("--db-name",   default=_CFG_PG_DB or "postgres",
                        help="로그에 기록할 DB 이름 (기본: Startup 메시지에서 자동 추출)")
    parser.add_argument("--db-schema", default=_CFG_PG_SCHEMA or "public",
                        help="로그에 기록할 스키마 (기본: public)")
    args = parser.parse_args()

    proxy = PgProxy(
        listen_host = args.listen_host,
        listen_port = args.listen_port,
        pg_host     = args.pg_host,
        pg_port     = args.pg_port,
        db_name     = args.db_name,
        db_schema   = args.db_schema,
    )

    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        _log.info("프록시 종료")


if __name__ == "__main__":
    main()
