"""
Oracle TNS 프록시 - Java/JDBC, .NET/ODP.NET, C/C++/OCI 쿼리 감사 로그

원리:
  모든 Oracle 클라이언트(언어 무관)는 TCP로 Oracle 서버에 TNS 프로토콜을 사용한다.
  이 프록시가 그 사이에 끼어들어 패킷을 복사·검사하므로 애플리케이션 수정 없이
  모든 쿼리를 가로챈다.

    [기존]  앱(JDBC/ODP.NET/OCI) ──TCP──▶  Oracle :1521
    [변경]  앱  ──TCP──▶  이 프록시 :1522  ──TCP──▶  Oracle :1521

구동:
    python oracle_proxy.py
    python oracle_proxy.py --listen-port 1522 --oracle-host 10.0.0.1 --oracle-port 1521

애플리케이션 접속 설정 변경 (코드 수정 없음, 연결 문자열만):
    JDBC     : jdbc:oracle:thin:@프록시IP:1522/ORCL
    ODP.NET  : Data Source=프록시IP:1522/ORCL
    SQLPlus  : scott/tiger@프록시IP:1522/ORCL
    tnsnames : HOST=프록시IP, PORT=1522

result_data 추출 원리:
    Oracle FETCH RESPONSE 패킷의 TTC 인코딩 규칙을 이용한다.
      · VARCHAR2/CHAR/NVARCHAR2: [1바이트 길이][UTF-8 평문] → UTF-8 디코딩 성공 → 추출
      · NUMBER/DATE/RAW        : 바이너리 인코딩 → UTF-8 디코딩 실패 또는 비출력문자 → 제외
    컬럼명은 알 수 없으므로 추출된 문자열 값의 리스트로 저장된다.
    개인정보 패턴(주민번호·카드번호·계좌번호·전화번호·이메일)은 이 리스트에서 자동 탐지된다.

제약:
    - Oracle Advanced Security(ASO) 암호화 환경에서는 SQL 및 결과 데이터 추출 불가
    - NUMBER/DATE/RAW 컬럼 값은 바이너리 인코딩이므로 result_data에 포함되지 않음
    - DML affected_rows는 근사치
"""

import asyncio
import argparse
import logging
import re
import uuid
from datetime import datetime
from typing import Optional

from config import DB_SERVER as _CFG_SERVER, DB_NAME as _CFG_DBNAME, DB_SCHEMA as _CFG_SCHEMA
from query_logger import write_query_log


# ══════════════════════════════════════════════════════════════════
# 로깅
# ══════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [TNSProxy] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
_log = logging.getLogger("oracle_proxy")


# ══════════════════════════════════════════════════════════════════
# TNS 프로토콜 상수
# ══════════════════════════════════════════════════════════════════

_HDR = 8                    # TNS 헤더 길이 (바이트)
_MAX_PKT = 65535            # TNS 최대 패킷 크기

# TNS 패킷 타입 (packet[4])
_T_CONNECT = 1
_T_ACCEPT  = 2
_T_DATA    = 6
_T_MARKER  = 12

# TTC 함수 코드 (DATA 패킷의 packet[10]):  클라이언트 → Oracle, SQL 포함
_TTC_SQL = frozenset({
    0x03,   # Protocol negotiation (초기)
    0x04,   # OSQL     – 구형 Parse+Execute 통합
    0x1D,   # PARSE    – SQL 파싱 요청 (Oracle 9i+)
    0x1E,   # EXECUTE  – 파싱된 커서 실행
    0x5E,   # OSQL_V3  – 신형 Execute (Oracle 11g+)
    0x73,   # BEXEC    – Batch execute
})

# TTC 함수 코드: Oracle → 클라이언트, 응답
_TTC_RPC_RESP  = 0x08   # Execute/DML 응답 (affected_rows 포함 가능)
_TTC_FETCH_RSP = 0x06   # SELECT Fetch 응답

# result_data 수집 제한
_MAX_RESULT_VALS = 500   # 쿼리당 최대 추출 문자열 수 (메모리·로그 크기 방어)
_MAX_VAL_LEN     = 500   # 단일 값 최대 길이 (바이트)


# ══════════════════════════════════════════════════════════════════
# SQL 추출 패턴
# ══════════════════════════════════════════════════════════════════

# Oracle 클라이언트는 SQL을 UTF-8/ASCII 평문으로 TNS DATA 패킷에 담아 전송한다.
# NUL 바이트 2개 이상(x00x00)이 SQL 뒤쪽 경계로 자주 쓰인다.
_SQL_RE = re.compile(
    r'(?<![A-Za-z0-9_"\'])'
    r'('
    r'(?:SELECT|INSERT(?:\s+INTO)?|UPDATE|DELETE(?:\s+FROM)?|'
    r'MERGE(?:\s+INTO)?|CALL|EXEC(?:UTE)?|'
    r'CREATE(?:\s+OR\s+REPLACE)?(?:\s+TABLE|\s+VIEW|\s+PROCEDURE|\s+FUNCTION|'
    r'\s+PACKAGE|\s+TRIGGER|\s+INDEX)?|'
    r'DROP\s+(?:TABLE|VIEW|PROCEDURE|FUNCTION|PACKAGE|TRIGGER|INDEX)|'
    r'ALTER\s+(?:TABLE|SESSION|SYSTEM|PROCEDURE|FUNCTION)|'
    r'TRUNCATE\s+TABLE|'
    r'WITH\s+\w+\s+AS\s*\(|'
    r'BEGIN|DECLARE\b'
    r')'
    r'\b[\s\S]{3,8000}?'
    r')'
    r'(?=\x00{2,}|\Z)',
    re.IGNORECASE,
)

# Oracle 오류 메시지 패턴
_ORA_ERR_RE = re.compile(r'ORA-(\d{4,5})(?:[:\s]+(.{0,200}))?', re.IGNORECASE)


# ══════════════════════════════════════════════════════════════════
# TNS 패킷 읽기
# ══════════════════════════════════════════════════════════════════

async def _read_tns_packet(reader: asyncio.StreamReader) -> Optional[bytes]:
    """
    TNS 패킷 하나를 완전히 읽어 반환한다.

    TNS 패킷 구조:
      [0:2] 전체 패킷 길이 (big-endian uint16, 헤더 포함)
      [2:4] 체크섬
      [4]   패킷 타입
      [5]   플래그
      [6:8] 헤더 체크섬
      [8:]  페이로드 (DATA 패킷의 경우 TTC 메시지)
    """
    try:
        header = await reader.readexactly(_HDR)
    except Exception:
        return None

    pkt_len = int.from_bytes(header[0:2], 'big')

    if pkt_len < _HDR or pkt_len > _MAX_PKT:
        # 비정상 길이: 헤더만 반환하고 계속 진행
        return header

    body_len = pkt_len - _HDR
    if body_len == 0:
        return header

    try:
        body = await reader.readexactly(body_len)
        return header + body
    except asyncio.IncompleteReadError as e:
        return header + e.partial
    except Exception:
        return header


# ══════════════════════════════════════════════════════════════════
# 세션 상태 추적
# ══════════════════════════════════════════════════════════════════

class _TnsSession:
    """
    하나의 TCP 연결(= Oracle 세션)에 대한 상태를 관리한다.

    패킷 흐름:
      클라이언트 → 프록시 → on_client_packet() → SQL 추출 → Oracle
      Oracle     → 프록시 → on_server_packet() → 오류 감지 → 클라이언트

    로그 기록 시점:
      - DML(INSERT/UPDATE/DELETE/MERGE): Oracle 응답(RPC RESP) 수신 즉시
      - SELECT: 다음 쿼리 시작 시 또는 세션 종료 시 (fetch 완료 후)
    """

    def __init__(self, client_ip: str, db_server: str, db_name: str, db_schema: str,
                 exec_method: str = "TNS Proxy"):
        self.client_ip   = client_ip
        self.db_server   = db_server
        self.db_name     = db_name
        self.db_schema   = db_schema
        self.session_id  = str(uuid.uuid4())[:8]
        self._exec_method = exec_method   # "TNS Proxy" or "TNS Sniffer"

        # Oracle 로그온 패킷에서 추출
        self.ora_user = "UNKNOWN"

        # 진행 중인 쿼리
        self._sql:            Optional[str]      = None
        self._start:          Optional[datetime] = None
        self._status:         str                = "SUCCESS"
        self._error:          Optional[str]      = None
        self._aff_rows:       int                = 0
        self._fetches:        int                = 0     # SELECT fetch 배치 수
        self._result_strings: list[str]          = []    # FETCH에서 추출한 문자열 값

    # ── 클라이언트 → Oracle 방향 ──────────────────────────────────

    def on_client_packet(self, packet: bytes) -> None:
        if len(packet) <= _HDR:
            return
        ptype = packet[4]

        if ptype == _T_CONNECT:
            self._parse_connect(packet)
        elif ptype == _T_DATA and len(packet) > 11:
            ttc = packet[10]
            if ttc in _TTC_SQL:
                self._on_sql_packet(packet)

    def _parse_connect(self, packet: bytes) -> None:
        """
        CONNECT 패킷의 CONNECT DATA 문자열에서 사용자명·서비스명을 추출한다.

        JDBC thin / OCI가 전송하는 CONNECT DATA 예:
          (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)...)
            (CONNECT_DATA=(SERVER=DEDICATED)(SERVICE_NAME=ORCL)
              (CID=(PROGRAM=JDBC...)(HOST=...)(USER=scott))))
        """
        text = packet.decode('ascii', errors='ignore')

        m = re.search(r'\(USER=([^)]+)\)', text, re.IGNORECASE)
        if m:
            self.ora_user = m.group(1).strip()

        m = re.search(r'\(SERVICE_NAME=([^)]+)\)', text, re.IGNORECASE)
        if m:
            svc = m.group(1).strip()
            if svc:
                self.db_name = svc

    def _on_sql_packet(self, packet: bytes) -> None:
        """
        TTC Parse/Execute 패킷에서 SQL을 추출한다.
        새 SQL이 시작되면 이전 쿼리(SELECT)의 로그를 먼저 완료한다.
        """
        if self._sql:
            # 이전 SELECT가 완료되지 않은 상태 → 지금 완료
            self._write_log()

        sql = self._extract_sql(packet[11:])   # TNS 헤더 8B + dataflags 2B + funccode 1B
        if sql:
            self._sql             = sql
            self._start           = datetime.now()
            self._status          = "SUCCESS"
            self._error           = None
            self._aff_rows        = 0
            self._fetches         = 0
            self._result_strings  = []

    def _extract_sql(self, payload: bytes) -> Optional[str]:
        """
        페이로드 바이트에서 SQL 텍스트를 휴리스틱하게 추출한다.

        Oracle 클라이언트는 SQL을 NUL로 구분된 UTF-8 평문으로 전송한다.
        (Oracle Advanced Security 비암호화 환경 기준)
        """
        try:
            text = payload.decode('utf-8', errors='ignore')
        except Exception:
            text = payload.decode('latin-1', errors='ignore')

        m = _SQL_RE.search(text)
        if not m:
            return None

        sql = m.group(1).strip()
        # 제어 문자 정리 (NUL, BS 등)
        sql = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', ' ', sql)
        sql = re.sub(r' {2,}', ' ', sql).strip()
        return sql if len(sql) >= 6 else None

    # ── Oracle → 클라이언트 방향 ──────────────────────────────────

    def on_server_packet(self, packet: bytes) -> None:
        if len(packet) <= 11 or packet[4] != _T_DATA:
            return
        ttc = packet[10]

        if ttc == _TTC_RPC_RESP:
            self._on_rpc_response(packet)
        elif ttc == _TTC_FETCH_RSP:
            self._fetches += 1
            self._collect_fetch_data(packet)

    def _on_rpc_response(self, packet: bytes) -> None:
        """
        Execute 응답을 처리한다.

        Oracle 응답 패킷에 ORA-XXXXX 에러 문자열이 있으면 FAILURE로 기록.
        DML이면 즉시 로그 완료 (SELECT는 fetch가 끝날 때까지 보류).
        """
        if not self._sql:
            return

        text = packet.decode('latin-1', errors='ignore')
        err_m = _ORA_ERR_RE.search(text)
        if err_m:
            self._status = "FAILURE"
            msg = (err_m.group(2) or "").strip()
            self._error  = f"ORA-{err_m.group(1)}" + (f": {msg}" if msg else "")
        else:
            # DML affected_rows 추출 (근사치)
            aff = self._parse_affected_rows(packet)
            if aff is not None:
                self._aff_rows = aff

        # DML은 RPC RESP 수신 시 즉시 로그 완료
        # SELECT는 다음 쿼리 시작 시(or 세션 종료) 로그 완료
        first_word = self._sql.strip().split()[0].upper()
        if first_word not in ("SELECT", "WITH"):
            self._write_log()
        elif self._status == "FAILURE":
            # SELECT 오류는 즉시 기록
            self._write_log()

    def _collect_fetch_data(self, packet: bytes) -> None:
        """
        FETCH RESPONSE 패킷에서 문자열 컬럼 값을 추출해 _result_strings에 누적한다.

        Oracle TTC FETCH 인코딩 규칙:
          0x00        → NULL (건너뜀)
          0x01-0xFD   → 1바이트 길이 + 데이터 (VARCHAR2/CHAR/NUMBER/DATE 등 공통)
          0xFE        → 2바이트 big-endian 길이 + 데이터
          0xFF        → LOB 스트리밍 등 복잡 포맷 (지원 안 함, 중단)

        VARCHAR2/CHAR: UTF-8 평문 → decode 성공 + isprintable() → _result_strings 추가
        NUMBER/DATE  : 바이너리 인코딩 → decode 실패 또는 비출력 문자 → 제외
        """
        if len(self._result_strings) >= _MAX_RESULT_VALS:
            return

        payload = packet[11:]   # TNS 헤더 8B + data flags 2B + func code 1B
        i = 0

        while i < len(payload) and len(self._result_strings) < _MAX_RESULT_VALS:
            b = payload[i]

            if b == 0x00:                   # NULL 값
                i += 1
                continue

            if b == 0xFE:                   # 2바이트 확장 길이
                if i + 2 >= len(payload):
                    break
                ln         = int.from_bytes(payload[i + 1:i + 3], 'big')
                data_start = i + 3
            elif b == 0xFF:                 # LOB 스트리밍 — 파싱 중단
                break
            else:                           # 1바이트 길이 (0x01–0xFD)
                ln         = b
                data_start = i + 1

            data_end = data_start + ln
            if data_end > len(payload):
                break

            if 1 <= ln <= _MAX_VAL_LEN:
                chunk = payload[data_start:data_end]
                try:
                    text = chunk.decode('utf-8', errors='strict')
                    # isprintable(): NUMBER/DATE의 바이너리 바이트는 여기서 걸러짐
                    if text.isprintable() and text.strip():
                        self._result_strings.append(text.strip())
                except (UnicodeDecodeError, ValueError):
                    pass    # NUMBER, DATE, RAW 등 바이너리 타입은 제외

            i = data_end

    def _parse_affected_rows(self, packet: bytes) -> Optional[int]:
        """
        RPC 응답 패킷에서 affected rows를 추출한다 (근사치).

        Oracle TTC 인코딩: 1바이트 값 0x01–0xFE = 값, 0xFF = 이후 4바이트 big-endian.
        정확한 오프셋은 Oracle 버전·커서 옵션에 따라 다르므로 짧은 범위를 스캔한다.
        """
        payload = packet[11:]   # TNS 헤더 + data flags + func code 이후
        if len(payload) < 5:
            return None

        for idx in range(3, min(14, len(payload))):
            b = payload[idx]
            if b == 0xFF and idx + 4 < len(payload):
                return int.from_bytes(payload[idx + 1:idx + 5], 'big')
            if 0 < b < 0xFF:
                return b
        return None

    # ── 로그 기록 ─────────────────────────────────────────────────

    def _write_log(self) -> None:
        if not self._sql or not self._start:
            return
        # FETCH에서 추출한 문자열 값을 result_data 포맷으로 변환
        # 컬럼명을 알 수 없으므로 {"value": "..."} 리스트로 저장
        # json.dumps 시 PI 패턴(주민번호·카드번호 등)이 이 문자열에서 탐지됨
        result_data = (
            [{"value": s} for s in self._result_strings]
            if self._result_strings else None
        )

        try:
            write_query_log(
                user_id          = self.ora_user,
                user_name        = self.ora_user,
                user_role        = "OracleUser",
                client_ip        = self.client_ip,
                db_server        = self.db_server,
                db_name          = self.db_name,
                db_schema        = self.db_schema,
                sql              = self._sql,
                parameters       = None,
                execution_method = self._exec_method,
                session_id       = self.session_id,
                purpose          = "",
                reference_no     = "",
                start_time       = self._start,
                end_time         = datetime.now(),
                status           = self._status,
                affected_rows    = self._aff_rows,
                result_data      = result_data,
                error_message    = self._error,
            )
        except Exception as exc:
            _log.warning("로그 기록 실패: %s", exc)

        self._sql             = None
        self._start           = None
        self._status          = "SUCCESS"
        self._error           = None
        self._aff_rows        = 0
        self._fetches         = 0
        self._result_strings  = []

    def flush(self) -> None:
        """세션 종료 시 미완료 쿼리(SELECT 등)를 로그에 기록한다."""
        self._write_log()


# ══════════════════════════════════════════════════════════════════
# 프록시 서버
# ══════════════════════════════════════════════════════════════════

class OracleProxy:
    """
    Oracle TNS 감사 프록시 서버.

    asyncio 기반의 비동기 TCP 프록시.
    클라이언트 1개 연결당 2개의 coroutine(C→Oracle, Oracle→C)이 동시 실행된다.
    """

    def __init__(
        self,
        listen_host: str  = "0.0.0.0",
        listen_port: int  = 1522,
        oracle_host: str  = "localhost",
        oracle_port: int  = 1521,
        db_server:   str  = "",
        db_name:     str  = "",
        db_schema:   str  = "",
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.oracle_host = oracle_host
        self.oracle_port = oracle_port
        self.db_server   = db_server or _CFG_SERVER or oracle_host
        self.db_name     = db_name   or _CFG_DBNAME or "ORACLE_DB"
        self.db_schema   = db_schema or _CFG_SCHEMA or ""
        self._server     = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port,
        )
        addrs = [str(s.getsockname()) for s in self._server.sockets]
        _log.info("TNS 프록시 시작: %s → %s:%d",
                  addrs, self.oracle_host, self.oracle_port)
        _log.info("애플리케이션 접속 주소를 %s:%d 로 변경하세요.",
                  self.listen_host, self.listen_port)
        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(
        self,
        c_reader: asyncio.StreamReader,
        c_writer: asyncio.StreamWriter,
    ) -> None:
        """새 클라이언트 연결 1개를 처리한다."""
        peer      = c_writer.get_extra_info('peername')
        client_ip = peer[0] if peer else "UNKNOWN"
        session   = _TnsSession(
            client_ip,
            self.db_server,
            self.db_name,
            self.db_schema,
        )
        _log.info("[%s] 연결 수립", client_ip)

        # 실제 Oracle 서버에 연결
        try:
            o_reader, o_writer = await asyncio.open_connection(
                self.oracle_host, self.oracle_port
            )
        except Exception as exc:
            _log.error("[%s] Oracle 연결 실패: %s", client_ip, exc)
            c_writer.close()
            return

        async def _pipe(
            src: asyncio.StreamReader,
            dst: asyncio.StreamWriter,
            on_pkt,
            label: str,
        ) -> None:
            """
            단방향 파이프: src에서 패킷을 읽어 on_pkt()로 검사한 뒤 dst로 전달.
            src가 끊기면 dst도 닫는다.
            """
            try:
                while True:
                    pkt = await _read_tns_packet(src)
                    if pkt is None:
                        break
                    on_pkt(pkt)
                    dst.write(pkt)
                    await dst.drain()
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as exc:
                _log.debug("[%s] %s 오류: %s", client_ip, label, exc)
            finally:
                try:
                    dst.close()
                    await dst.wait_closed()
                except Exception:
                    pass

        t_c2o = asyncio.create_task(
            _pipe(c_reader, o_writer, session.on_client_packet, "C→Oracle")
        )
        t_o2c = asyncio.create_task(
            _pipe(o_reader, c_writer, session.on_server_packet, "Oracle→C")
        )

        # 어느 한 쪽이 끊기면 나머지도 취소
        try:
            done, pending = await asyncio.wait(
                [t_c2o, t_o2c],
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
            _log.info("[%s] 연결 종료 (세션 %s)", client_ip, session.session_id)


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Oracle TNS 감사 프록시 — Java/JDBC, .NET, C/C++ 쿼리 자동 로깅",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--listen-host", default="0.0.0.0",
                        help="프록시 바인딩 주소")
    parser.add_argument("--listen-port", type=int, default=1522,
                        help="프록시 리슨 포트")
    parser.add_argument("--oracle-host", default=_CFG_SERVER or "localhost",
                        help="실제 Oracle 서버 호스트")
    parser.add_argument("--oracle-port", type=int, default=1521,
                        help="실제 Oracle 서버 포트")
    parser.add_argument("--db-name",   default=_CFG_DBNAME,
                        help="로그에 기록할 DB/서비스 이름")
    parser.add_argument("--db-schema", default=_CFG_SCHEMA,
                        help="로그에 기록할 스키마")
    args = parser.parse_args()

    proxy = OracleProxy(
        listen_host = args.listen_host,
        listen_port = args.listen_port,
        oracle_host = args.oracle_host,
        oracle_port = args.oracle_port,
        db_server   = args.oracle_host,
        db_name     = args.db_name,
        db_schema   = args.db_schema,
    )

    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        _log.info("프록시 종료")


if __name__ == "__main__":
    main()
