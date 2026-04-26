"""
Oracle TNS 패킷 스니퍼 - 원시 소켓(Raw Socket) 기반 감사 로그

oracle_proxy.py 가 TCP 중간자(Man-in-the-Middle) 방식인 반면,
이 프로그램은 OS 네트워크 스택에서 패킷을 수동적으로 '복사'해 분석한다.
애플리케이션과 Oracle 서버 설정을 전혀 변경하지 않아도 된다.

[oracle_proxy.py vs packet_sniffer.py]
  항목              proxy (중간자)          sniffer (수동 감청)
  ──────────────────────────────────────────────────────────────
  앱 변경           포트 변경 필요          없음 (기존 1521 그대로)
  서버 변경         없음                    없음
  권한              일반 사용자             root / 관리자
  패킷 원본 보장    프록시가 전달           OS 네트워크 스택 직접 복사
  가로채기 방식     TCP 스트림 교체         TCP 패킷 복사 (원본 영향 없음)
  SQL 탐지 완전성   높음                    TCP 재조합 한계로 낮을 수 있음

[상호 검증]
  두 프로그램의 로그를 log_cross_validator.py로 비교한다.
  · 같은 SQL이 두 로그 모두에 있으면 → 검증 완료
  · 스니퍼에만 있고 프록시에 없으면 → 앱이 프록시를 우회한 가능성
  · 프록시에만 있고 스니퍼에 없으면 → 스니퍼가 해당 패킷을 놓침

[구동]
  Linux  : sudo python packet_sniffer.py --oracle-port 1521
  Windows: (관리자 CMD) python packet_sniffer.py --oracle-port 1521 --bind-ip 0.0.0.0
"""

import argparse
import logging
import re
import socket
import struct
import sys
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Optional

# oracle_proxy._TnsSession 을 재사용 (exec_method 만 "TNS Sniffer"로 변경)
from oracle_proxy import (
    _TnsSession,
    _HDR,
    _T_CONNECT,
    _T_DATA,
    _TTC_SQL,
    _TTC_RPC_RESP,
    _TTC_FETCH_RSP,
)
from config import DB_SERVER as _CFG_SERVER, DB_NAME as _CFG_DBNAME, DB_SCHEMA as _CFG_SCHEMA

# ══════════════════════════════════════════════════════════════════
# 로깅
# ══════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Sniffer] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
_log = logging.getLogger("packet_sniffer")


# ══════════════════════════════════════════════════════════════════
# TCP 스트림 버퍼  (TNS 패킷 경계 복원)
# ══════════════════════════════════════════════════════════════════

class _StreamBuffer:
    """
    TCP 는 스트림 프로토콜이라 패킷 경계가 없다.
    TNS 헤더의 길이 필드를 이용해 완전한 TNS 패킷 단위로 분리한다.
    """

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        """데이터를 추가하고 완성된 TNS 패킷 목록을 반환한다."""
        self._buf.extend(data)
        packets: list[bytes] = []

        while len(self._buf) >= _HDR:
            pkt_len = int.from_bytes(self._buf[0:2], 'big')

            if pkt_len < _HDR or pkt_len > 65535:
                self._buf.clear()   # 동기화 깨짐 → 버퍼 리셋
                break

            if len(self._buf) < pkt_len:
                break               # 아직 완전하지 않음

            packets.append(bytes(self._buf[:pkt_len]))
            del self._buf[:pkt_len]

        return packets


# ══════════════════════════════════════════════════════════════════
# 원시 소켓 생성
# ══════════════════════════════════════════════════════════════════

def _create_raw_socket(bind_ip: str = "") -> socket.socket:
    """
    플랫폼별 원시 소켓을 생성한다.

    Linux : AF_PACKET — 모든 이더넷 프레임 수신 (송수신 모두 가능)
    Windows: AF_INET + IPPROTO_IP + SIO_RCVALL — IP 패킷 수신
    """
    if sys.platform == "linux":
        try:
            # ETH_P_ALL = 0x0003 : 모든 이더넷 프레임
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0003))
            return sock
        except PermissionError:
            _log.error("root 권한이 필요합니다. sudo 로 실행하세요.")
            sys.exit(1)

    elif sys.platform == "win32":
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_IP)
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


# ══════════════════════════════════════════════════════════════════
# 패킷 파싱 (Ethernet → IP → TCP → payload)
# ══════════════════════════════════════════════════════════════════

def _parse_packet(data: bytes) -> Optional[tuple]:
    """
    원시 소켓 데이터를 파싱해 TCP 정보를 반환한다.

    Returns: (src_ip, src_port, dst_ip, dst_port, tcp_flags, payload) 또는 None

    TCP flags (byte):
      bit0=FIN  bit1=SYN  bit2=RST  bit3=PSH  bit4=ACK
    """
    offset = 0

    # ── Linux: 이더넷 헤더 14바이트 건너뜀 ──────────────────────────
    if sys.platform == "linux":
        if len(data) < 14:
            return None
        eth_type = struct.unpack_from("!H", data, 12)[0]
        if eth_type != 0x0800:     # IPv4 아님 (IPv6, ARP 등)
            return None
        offset = 14

    # ── IP 헤더 파싱 ─────────────────────────────────────────────────
    if len(data) - offset < 20:
        return None

    ip0      = data[offset]
    ip_ver   = (ip0 >> 4) & 0xF
    ip_ihl   = (ip0 & 0xF) * 4
    ip_proto = data[offset + 9]

    if ip_ver != 4 or ip_proto != 6:    # IPv4 + TCP 만 처리
        return None

    src_ip = socket.inet_ntoa(data[offset + 12: offset + 16])
    dst_ip = socket.inet_ntoa(data[offset + 16: offset + 20])
    tcp_off = offset + ip_ihl

    # ── TCP 헤더 파싱 ─────────────────────────────────────────────────
    if len(data) - tcp_off < 20:
        return None

    src_port     = struct.unpack_from("!H", data, tcp_off)[0]
    dst_port     = struct.unpack_from("!H", data, tcp_off + 2)[0]
    data_offset  = ((data[tcp_off + 12] >> 4) & 0xF) * 4
    tcp_flags    = data[tcp_off + 13]
    payload      = data[tcp_off + data_offset:]

    return src_ip, src_port, dst_ip, dst_port, tcp_flags, payload


# ══════════════════════════════════════════════════════════════════
# 패킷 스니퍼
# ══════════════════════════════════════════════════════════════════

class PacketSniffer:
    """
    원시 소켓으로 Oracle TNS 패킷을 수동 수신해 감사 로그를 기록한다.

    세션 관리:
      · 세션 키: (client_ip, client_port) — 한 Oracle 연결을 식별
      · 각 세션은 C→S, S→C 두 방향의 _StreamBuffer 를 가진다
      · FIN/RST 수신 시 해당 세션을 정리하고 미완료 로그를 기록
    """

    def __init__(
        self,
        oracle_port: int = 1521,
        db_server:   str = "",
        db_name:     str = "",
        db_schema:   str = "",
        bind_ip:     str = "",
    ):
        self._oracle_port = oracle_port
        self._db_server   = db_server or _CFG_SERVER or "localhost"
        self._db_name     = db_name   or _CFG_DBNAME or "ORACLE_DB"
        self._db_schema   = db_schema or _CFG_SCHEMA or ""
        self._bind_ip     = bind_ip

        # (client_ip, client_port) → _TnsSession
        self._sessions:  dict[tuple, _TnsSession]  = {}
        # (client_ip, client_port) → _StreamBuffer (C→S 방향)
        self._c2s_bufs:  dict[tuple, _StreamBuffer] = defaultdict(_StreamBuffer)
        # (client_ip, client_port) → _StreamBuffer (S→C 방향)
        self._s2c_bufs:  dict[tuple, _StreamBuffer] = defaultdict(_StreamBuffer)

    def start(self) -> None:
        sock = _create_raw_socket(self._bind_ip)
        _log.info("Oracle TNS 스니퍼 시작 (포트 %d 감청 중)", self._oracle_port)
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
            _log.info("스니퍼 종료 — 미완료 세션 로그 기록 중...")
            self._flush_all()
        finally:
            if sys.platform == "win32":
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            sock.close()

    def _process(self, data: bytes) -> None:
        """원시 패킷 하나를 분석해 해당 세션의 스트림 버퍼에 전달한다."""
        parsed = _parse_packet(data)
        if not parsed:
            return

        src_ip, src_port, dst_ip, dst_port, flags, payload = parsed

        # ── 방향 판별 및 세션 키 결정 ────────────────────────────────
        if dst_port == self._oracle_port:
            key       = (src_ip, src_port)
            direction = "c2s"
            client_ip = src_ip
        elif src_port == self._oracle_port:
            key       = (dst_ip, dst_port)
            direction = "s2c"
            client_ip = dst_ip
        else:
            return

        # ── TCP FIN/RST: 세션 종료 처리 ──────────────────────────────
        is_fin = bool(flags & 0x01)
        is_rst = bool(flags & 0x04)
        if is_fin or is_rst:
            if key in self._sessions:
                self._sessions[key].flush()
                del self._sessions[key]
            self._c2s_bufs.pop(key, None)
            self._s2c_bufs.pop(key, None)
            return

        if not payload:
            return

        # ── 세션 생성 (최초 패킷) ─────────────────────────────────────
        if key not in self._sessions:
            self._sessions[key] = _TnsSession(
                client_ip    = client_ip,
                db_server    = self._db_server,
                db_name      = self._db_name,
                db_schema    = self._db_schema,
                exec_method  = "TNS Sniffer",
            )
            _log.info("[%s:%d] 새 Oracle 연결 감지", *key)

        session = self._sessions[key]

        # ── 스트림 버퍼 → 완성된 TNS 패킷 처리 ──────────────────────
        if direction == "c2s":
            for pkt in self._c2s_bufs[key].feed(payload):
                session.on_client_packet(pkt)
        else:
            for pkt in self._s2c_bufs[key].feed(payload):
                session.on_server_packet(pkt)

    def _flush_all(self) -> None:
        """모든 활성 세션의 미완료 쿼리를 로그에 기록한다."""
        for session in self._sessions.values():
            session.flush()
        self._sessions.clear()
        self._c2s_bufs.clear()
        self._s2c_bufs.clear()


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Oracle TNS 패킷 스니퍼 — 앱·서버 수정 없이 쿼리 감사 로그 수집",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--oracle-port", type=int, default=1521,
                        help="감청할 Oracle 리스너 포트")
    parser.add_argument("--db-server",  default=_CFG_SERVER or "localhost",
                        help="로그에 기록할 DB 서버 명칭")
    parser.add_argument("--db-name",    default=_CFG_DBNAME,
                        help="로그에 기록할 DB/서비스 이름")
    parser.add_argument("--db-schema",  default=_CFG_SCHEMA,
                        help="로그에 기록할 스키마")
    parser.add_argument("--bind-ip",    default="",
                        help="Windows 전용: 바인딩할 인터페이스 IP")
    args = parser.parse_args()

    sniffer = PacketSniffer(
        oracle_port = args.oracle_port,
        db_server   = args.db_server,
        db_name     = args.db_name,
        db_schema   = args.db_schema,
        bind_ip     = args.bind_ip,
    )
    sniffer.start()


if __name__ == "__main__":
    main()
