"""
PostgreSQL Wire Protocol 패킷 스니퍼 - 원시 소켓(Raw Socket) 기반 감사 로그

포트 5432 의 PostgreSQL Frontend/Backend Protocol v3 를 OS 레벨에서 수동 감청해
실행된 SQL 을 감사 로그로 기록한다. 앱과 PostgreSQL 서버 설정을 전혀 변경하지 않아도 된다.

[제약]
  · SSL/TLS 암호화 연결(sslmode=require/verify-*): SQL 추출 불가
  · 비암호화 연결(sslmode=disable 또는 서버가 ssl=off) 에서만 동작
  · Linux: root 또는 CAP_NET_RAW 권한 필요
  · Windows: 관리자 권한 필요

[구동]
  Linux : sudo python3 pg_sniffer.py --pg-port 5432
  Windows: (관리자 CMD) python pg_sniffer.py --pg-port 5432 --bind-ip 0.0.0.0

[oracle_proxy.py 와 달리 독립 모듈]
  pg_sniffer.py 는 oracle_proxy.py 를 import 하지 않는다.
  PostgreSQL Wire Protocol 파서를 내부에 자체 구현한다.
"""

import argparse
import logging
import socket
import struct
import sys
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Optional

from config import PG_HOST as _CFG_SERVER, PG_DB as _CFG_DBNAME, PG_SCHEMA as _CFG_SCHEMA
from query_logger import write_query_log

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PgSniffer] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
_log = logging.getLogger("pg_sniffer")

# PostgreSQL SSLRequest 코드 (protocol version 필드에 들어오는 특수값)
_PG_SSL_REQUEST_CODE = 80877103    # 0x04D2162F
_MAX_MSG_SIZE        = 16_777_216  # 16 MB (PostgreSQL 단일 메시지 최대)


# ══════════════════════════════════════════════════════════════════
# 스트림 버퍼 — 클라이언트→서버 방향
# ══════════════════════════════════════════════════════════════════

class _ClientBuffer:
    """
    PostgreSQL 클라이언트→서버 스트림을 메시지 단위로 분리한다.

    시작 메시지(Startup / SSLRequest): Int32 length + body  (type byte 없음)
    이후 메시지: Byte1 type + Int32 length (포함) + body
    """

    _ST_STARTUP = 0
    _ST_NORMAL  = 1
    _ST_SSL     = 2   # SSL 암호화 진행 중 — 파싱 불가

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
                    # state 변경은 서버 'S' 응답 수신 시 set_ssl() 호출
                else:
                    out.append(('startup', payload))
                    self._state = self._ST_NORMAL

            elif self._state == self._ST_NORMAL:
                if len(self._buf) < 5:
                    break
                mtype = chr(self._buf[0])
                mlen  = struct.unpack_from(">I", self._buf, 1)[0]  # length includes itself
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


# ══════════════════════════════════════════════════════════════════
# 스트림 버퍼 — 서버→클라이언트 방향
# ══════════════════════════════════════════════════════════════════

class _ServerBuffer:
    """
    PostgreSQL 서버→클라이언트 스트림을 메시지 단위로 분리한다.

    SSLRequest 에 대한 응답은 단일 바이트 'N'(거부) 또는 'S'(수락).
    이후 모든 메시지: Byte1 type + Int32 length (포함) + body
    """

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
    하나의 PostgreSQL TCP 연결(세션)에 대한 상태를 관리한다.

    Simple Query 흐름:
      클라이언트 'Q' → SQL 기록 시작
      서버 'C'(CommandComplete) → 로그 기록

    Extended Query 흐름:
      클라이언트 'P'(Parse) → SQL 저장 (prepared statement)
      클라이언트 'E'(Execute) → SQL 기록 시작
      서버 'C'(CommandComplete) → 로그 기록
    """

    def __init__(self, client_ip: str, db_server: str, db_name: str, db_schema: str):
        self.client_ip  = client_ip
        self.db_server  = db_server
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

    # ── 클라이언트 메시지 처리 ───────────────────────────────────

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

    # ── 서버 메시지 처리 ─────────────────────────────────────────

    def on_server(self, mtype: str, payload: bytes) -> None:
        if mtype == 'ssl_active':
            self._ssl_active = True
            _log.warning("[%s:%s] SSL 암호화 연결 — SQL 캡처 불가", self.client_ip, self.session_id)
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

    # ── 내부 ────────────────────────────────────────────────────

    def _parse_startup(self, payload: bytes) -> None:
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
        if len(payload) < 2:
            return
        num_cols = struct.unpack_from(">H", payload, 0)[0]
        off = 2
        for _ in range(num_cols):
            if off + 4 > len(payload):
                break
            col_len = struct.unpack_from(">i", payload, off)[0]  # signed; NULL = -1
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
        # tag 예: "SELECT 10" / "INSERT 0 1" / "UPDATE 3" / "DELETE 2"
        # BEGIN / COMMIT / ROLLBACK 은 로그 불필요
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
        sql = self._sql
        is_select = sql.strip().split()[0].upper() == "SELECT" if sql.strip() else False

        try:
            write_query_log(
                user_id          = self.pg_user,
                user_name        = self.pg_user,
                user_role        = "SupersetUser",
                client_ip        = self.client_ip,
                db_server        = self.db_server,
                db_name          = self.db_name,
                db_schema        = self.db_schema,
                sql              = sql,
                parameters       = None,
                execution_method = "PG Sniffer",
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
# 원시 소켓 생성  (packet_sniffer.py 와 동일 방식)
# ══════════════════════════════════════════════════════════════════

def _create_raw_socket(bind_ip: str = "") -> socket.socket:
    if sys.platform == "linux":
        try:
            return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        except PermissionError:
            _log.error("root 권한이 필요합니다. sudo 로 실행하세요.")
            sys.exit(1)
    elif sys.platform == "win32":
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            ip = bind_ip or socket.gethostbyname(socket.gethostname())
            sock.bind((ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            _log.info("바인딩 주소: %s", ip)
            return sock
        except PermissionError:
            _log.error("관리자 권한으로 실행하세요.")
            sys.exit(1)
    else:
        _log.error("지원하지 않는 플랫폼: %s", sys.platform)
        sys.exit(1)


def _parse_packet(data: bytes) -> Optional[tuple]:
    """raw 패킷 → (src_ip, src_port, dst_ip, dst_port, tcp_flags, payload) 또는 None"""
    off = 0
    if sys.platform == "linux":
        if len(data) < 14:
            return None
        if struct.unpack_from("!H", data, 12)[0] != 0x0800:  # IPv4 만
            return None
        off = 14

    if len(data) - off < 20:
        return None
    ip0    = data[off]
    ip_ver = (ip0 >> 4) & 0xF
    ip_ihl = (ip0 & 0xF) * 4
    if ip_ver != 4 or data[off + 9] != 6:   # IPv4 + TCP
        return None

    src_ip = socket.inet_ntoa(data[off + 12: off + 16])
    dst_ip = socket.inet_ntoa(data[off + 16: off + 20])
    tcp_off = off + ip_ihl
    if len(data) - tcp_off < 20:
        return None

    src_port    = struct.unpack_from("!H", data, tcp_off)[0]
    dst_port    = struct.unpack_from("!H", data, tcp_off + 2)[0]
    data_offset = ((data[tcp_off + 12] >> 4) & 0xF) * 4
    tcp_flags   = data[tcp_off + 13]
    payload     = data[tcp_off + data_offset:]

    return src_ip, src_port, dst_ip, dst_port, tcp_flags, payload


# ══════════════════════════════════════════════════════════════════
# PostgreSQL 패킷 스니퍼 메인 클래스
# ══════════════════════════════════════════════════════════════════

class PgSniffer:
    """
    원시 소켓으로 PostgreSQL Wire Protocol 패킷을 수동 수신해 감사 로그를 기록한다.

    세션 관리:
      · 세션 키: (client_ip, client_port)
      · 각 세션은 C→S(_ClientBuffer), S→C(_ServerBuffer) 두 방향 버퍼를 가진다
      · FIN/RST 수신 시 해당 세션을 정리하고 미완료 로그를 기록
    """

    def __init__(
        self,
        pg_port:   int = 5432,
        db_server: str = "",
        db_name:   str = "",
        db_schema: str = "",
        bind_ip:   str = "",
    ):
        self._pg_port   = pg_port
        self._db_server = db_server or _CFG_SERVER or "localhost"
        self._db_name   = db_name   or _CFG_DBNAME or "postgres"
        self._db_schema = db_schema or _CFG_SCHEMA or "public"
        self._bind_ip   = bind_ip

        self._sessions: dict[tuple, _PgSession]    = {}
        self._c_bufs:   dict[tuple, _ClientBuffer] = defaultdict(_ClientBuffer)
        self._s_bufs:   dict[tuple, _ServerBuffer] = defaultdict(_ServerBuffer)

    def start(self) -> None:
        sock = _create_raw_socket(self._bind_ip)
        _log.info("PostgreSQL 스니퍼 시작 (포트 %d 감청 중)", self._pg_port)
        _log.info("종료: Ctrl+C")
        try:
            while True:
                try:
                    data, _ = sock.recvfrom(65535)
                    self._process(data)
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    _log.debug("패킷 처리 오류: %s", exc)
        except KeyboardInterrupt:
            _log.info("종료 — 미완료 세션 로그 기록 중...")
            self._flush_all()
        finally:
            if sys.platform == "win32":
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            sock.close()

    def _process(self, data: bytes) -> None:
        parsed = _parse_packet(data)
        if not parsed:
            return
        src_ip, src_port, dst_ip, dst_port, flags, payload = parsed

        if dst_port == self._pg_port:
            key, direction, client_ip = (src_ip, src_port), "c2s", src_ip
        elif src_port == self._pg_port:
            key, direction, client_ip = (dst_ip, dst_port), "s2c", dst_ip
        else:
            return

        # FIN / RST → 세션 종료
        if flags & 0x01 or flags & 0x04:
            if key in self._sessions:
                self._sessions[key].flush()
                del self._sessions[key]
            self._c_bufs.pop(key, None)
            self._s_bufs.pop(key, None)
            return

        if not payload:
            return

        if key not in self._sessions:
            self._sessions[key] = _PgSession(
                client_ip = client_ip,
                db_server = self._db_server,
                db_name   = self._db_name,
                db_schema = self._db_schema,
            )
            _log.info("[%s:%d] 새 PostgreSQL 연결 감지", *key)

        session = self._sessions[key]

        if direction == "c2s":
            for mtype, mpayload in self._c_bufs[key].feed(payload):
                if mtype == 'ssl_request':
                    self._s_bufs[key].expect_ssl_response()
                session.on_client(mtype, mpayload)
        else:
            for mtype, mpayload in self._s_bufs[key].feed(payload):
                if mtype == 'ssl_active':
                    self._c_bufs[key].set_ssl()
                session.on_server(mtype, mpayload)

    def _flush_all(self) -> None:
        for s in self._sessions.values():
            s.flush()
        self._sessions.clear()
        self._c_bufs.clear()
        self._s_bufs.clear()


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PostgreSQL Wire Protocol 패킷 스니퍼 — 앱·서버 수정 없이 쿼리 감사 로그 수집",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--pg-port",   type=int, default=5432,
                        help="감청할 PostgreSQL 리스너 포트")
    parser.add_argument("--db-server", default=_CFG_SERVER or "localhost",
                        help="로그에 기록할 PostgreSQL 서버 명칭")
    parser.add_argument("--db-name",   default=_CFG_DBNAME or "postgres",
                        help="로그에 기록할 DB 이름")
    parser.add_argument("--db-schema", default=_CFG_SCHEMA or "public",
                        help="로그에 기록할 스키마")
    parser.add_argument("--bind-ip",   default="",
                        help="Windows 전용: 바인딩할 인터페이스 IP")
    args = parser.parse_args()

    PgSniffer(
        pg_port   = args.pg_port,
        db_server = args.db_server,
        db_name   = args.db_name,
        db_schema = args.db_schema,
        bind_ip   = args.bind_ip,
    ).start()


if __name__ == "__main__":
    main()
