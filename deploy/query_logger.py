"""
쿼리 감사 로그 모듈
6하원칙(누가/언제/어디서/무엇을/어떻게/왜)에 따라 쿼리 수행 내역과 결과를 기록한다.
로그는 JSON Lines 형식(.jsonl)으로 일별 파일에 저장되며, 각 항목에 무결성 해시가 포함된다.
"""

import json
import hashlib
import socket
import uuid
import re
from datetime import datetime, date
from pathlib import Path
from typing import Any, Iterator, Optional

from config import LOG_DIR, LOG_FILE_PREFIX, LOG_ENCODING, LOG_DATE_FORMAT, LOG_MAX_SIZE_MB
from config import APP_NAME, APP_VERSION


# ──────────────────────────────────────────────
# SQL 업무 유형 한글 매핑
# ──────────────────────────────────────────────
OPERATION_TYPE_MAP: dict[str, str] = {
    "SELECT"  : "조회",
    "INSERT"  : "생성",
    "UPDATE"  : "변경",
    "DELETE"  : "삭제",
    "MERGE"   : "병합",
    "UPSERT"  : "병합",
    "CREATE"  : "DDL-생성",
    "DROP"    : "DDL-삭제",
    "ALTER"   : "DDL-변경",
    "TRUNCATE": "삭제(전체)",
    "CALL"    : "프로시저",
    "EXEC"    : "프로시저",
    "EXECUTE" : "프로시저",
}

# ──────────────────────────────────────────────
# 개인정보 패턴 정의 (이름 포함)
#   각 튜플: (한글유형명, compiled_pattern, masking_replacer)
# ──────────────────────────────────────────────
_PI_PATTERN_DEFS: list[tuple[str, re.Pattern, Any]] = [
    ("주민등록번호",
     re.compile(r"\b(\d{6})-?(\d{7})\b"),
     lambda m: m.group(1) + "-*******"),

    ("카드번호",
     re.compile(r"\b(\d{4})[- ]?(\d{4})[- ]?(\d{4})[- ]?(\d{4})\b"),
     lambda m: m.group(1) + "-****-****-" + m.group(4)),

    ("계좌번호",
     re.compile(r"\b(\d{3,6})-?(\d{4,6})-?(\d{2,6})\b"),
     lambda m: m.group(1) + "-****-" + m.group(3)),

    ("전화번호",
     re.compile(r"\b(01[016789]|02|0[3-9]\d)-?(\d{3,4})-?(\d{4})\b"),
     lambda m: m.group(1) + "-****-" + m.group(3)),

    ("이메일",
     re.compile(r"\b([a-zA-Z0-9._%+\-]{1,3})[a-zA-Z0-9._%+\-]*"
                r"@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"),
     lambda m: m.group(1) + "***@" + m.group(2)),
]

# 하위 호환용 (pattern, replacer) 리스트
_PI_PATTERNS = [(pat, repl) for _, pat, repl in _PI_PATTERN_DEFS]

# 외부에서 import 가능한 유형명 목록
PI_TYPE_NAMES: list[str] = [name for name, _, _ in _PI_PATTERN_DEFS]


# ──────────────────────────────────────────────
# 개인정보 마스킹 유틸
# ──────────────────────────────────────────────

def mask_personal_info(text: str) -> str:
    """문자열 내 개인정보 패턴을 마스킹하여 반환한다."""
    for pattern, replacer in _PI_PATTERNS:
        text = pattern.sub(replacer, text)
    return text


def mask_value(value: Any) -> Any:
    """값(문자열·리스트·딕셔너리)을 재귀적으로 마스킹한다."""
    if isinstance(value, str):
        return mask_personal_info(value)
    if isinstance(value, dict):
        return {k: mask_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_value(item) for item in value]
    return value


def _count_personal_info(data: Optional[list]) -> dict[str, int]:
    """결과 데이터에서 개인정보 유형별 패턴 매치 건수를 집계한다."""
    base = {name: 0 for name, _, _ in _PI_PATTERN_DEFS}
    if not data:
        return base
    text = json.dumps(data, ensure_ascii=False)
    return {name: len(pattern.findall(text)) for name, pattern, _ in _PI_PATTERN_DEFS}


def _contains_personal_info(data: Optional[list]) -> bool:
    return any(v > 0 for v in _count_personal_info(data).values())


# ──────────────────────────────────────────────
# 로그 파일 경로 결정
# ──────────────────────────────────────────────

def _log_file_path(dt: datetime) -> Path:
    """날짜 기준 로그 파일 경로를 반환한다. 크기 초과 시 분할 번호를 붙인다."""
    base = LOG_DIR / f"{LOG_FILE_PREFIX}_{dt.strftime(LOG_DATE_FORMAT)}.jsonl"
    if not base.exists() or base.stat().st_size < LOG_MAX_SIZE_MB * 1024 * 1024:
        return base
    idx = 1
    while True:
        candidate = LOG_DIR / f"{LOG_FILE_PREFIX}_{dt.strftime(LOG_DATE_FORMAT)}_{idx:03d}.jsonl"
        if not candidate.exists() or candidate.stat().st_size < LOG_MAX_SIZE_MB * 1024 * 1024:
            return candidate
        idx += 1


# ──────────────────────────────────────────────
# 핵심 로그 기록 함수
# ──────────────────────────────────────────────

def write_query_log(
    *,
    # 누가(WHO)
    user_id: str,
    user_name: str,
    user_role: str,
    # 어디서(WHERE)
    client_ip: Optional[str] = None,
    hostname: Optional[str] = None,
    db_server: str,
    db_name: str,
    db_schema: str = "",
    # 무엇을(WHAT)
    sql: str,
    parameters: Optional[Any] = None,
    # 어떻게(HOW)
    execution_method: str = "직접 입력",
    session_id: Optional[str] = None,
    # 왜(WHY)
    purpose: str = "",
    reference_no: str = "",
    # 수행 결과
    start_time: datetime,
    end_time: datetime,
    status: str,              # "SUCCESS" | "FAILURE"
    affected_rows: int = 0,
    result_data: Optional[list] = None,
    error_message: Optional[str] = None,
) -> dict:
    """6하원칙 구조의 감사 로그 한 건을 파일에 기록하고 로그 딕셔너리를 반환한다."""

    duration_ms    = int((end_time - start_time).total_seconds() * 1000)
    query_type     = sql.strip().split()[0].upper() if sql.strip() else "UNKNOWN"
    operation_type = OPERATION_TYPE_MAP.get(query_type, "기타")
    auto_purpose   = purpose if purpose else operation_type

    pi_counts      = _count_personal_info(result_data)

    # SELECT는 result_data 건수, DML은 affected_rows
    row_count = len(result_data) if result_data else affected_rows

    log_entry = {
        "log_id": str(uuid.uuid4()),
        # ── 언제(WHEN) ──
        "when": {
            "start_time" : start_time.isoformat(timespec="microseconds"),
            "end_time"   : end_time.isoformat(timespec="microseconds"),
            "duration_ms": duration_ms,
        },
        # ── 누가(WHO) ──
        "who": {
            "user_id"  : user_id,
            "user_name": user_name,
            "user_role": user_role,
        },
        # ── 어디서(WHERE) ──
        "where": {
            "client_ip": client_ip or _local_ip(),
            "hostname" : hostname  or socket.gethostname(),
            "db_server": db_server,
            "db_name"  : db_name,
            "db_schema": db_schema,
        },
        # ── 무엇을(WHAT) ──
        "what": {
            "query_type"    : query_type,
            "operation_type": operation_type,
            "sql"           : sql,
            "parameters"    : parameters,
            "row_count"     : row_count,      # 조회/변경 결과 건수
            "affected_rows" : affected_rows,  # DML 영향 행수
        },
        # ── 어떻게(HOW) ──
        "how": {
            "execution_method": execution_method,
            "application"     : f"{APP_NAME} v{APP_VERSION}",
            "session_id"      : session_id or "",
        },
        # ── 왜(WHY) ──
        "why": {
            "purpose"     : auto_purpose,
            "reference_no": reference_no,
        },
        # ── 결과 ──
        "result": {
            "status"               : status,
            "error_message"        : error_message,
            "has_personal_info"    : any(v > 0 for v in pi_counts.values()),
            "personal_info_counts" : pi_counts,   # 유형별 건수
            "result_count"         : len(result_data) if result_data else 0,
            "result_data"          : result_data,
        },
    }

    # 무결성 해시
    raw = f"{log_entry['log_id']}{log_entry['when']['start_time']}{sql}{status}"
    log_entry["integrity_hash"] = hashlib.sha256(raw.encode()).hexdigest()

    _append_log(log_entry, start_time)
    return log_entry


def _local_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def _append_log(entry: dict, dt: datetime) -> None:
    path = _log_file_path(dt)
    with open(path, "a", encoding=LOG_ENCODING) as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ──────────────────────────────────────────────
# 로그 무결성 검증
# ──────────────────────────────────────────────

def verify_entry(entry: dict) -> bool:
    """로그 항목의 무결성 해시가 올바른지 검증한다."""
    raw = (
        entry["log_id"]
        + entry["when"]["start_time"]
        + entry["what"]["sql"]
        + entry["result"]["status"]
    )
    return entry.get("integrity_hash") == hashlib.sha256(raw.encode()).hexdigest()


# ──────────────────────────────────────────────
# 로그 파일 읽기 (CLI·웹 뷰어 공용)
# ──────────────────────────────────────────────

def log_files_in_range(from_dt: date, to_dt: date) -> list[Path]:
    files = sorted(LOG_DIR.glob(f"{LOG_FILE_PREFIX}_*.jsonl"))
    result = []
    for f in files:
        parts = f.stem.split("_")
        date_part = next((p for p in parts if len(p) == 8 and p.isdigit()), None)
        if not date_part:
            continue
        try:
            file_date = datetime.strptime(date_part, "%Y%m%d").date()
        except ValueError:
            continue
        if from_dt <= file_date <= to_dt:
            result.append(f)
    return result


def iter_logs(from_dt: date, to_dt: date) -> Iterator[dict]:
    for path in log_files_in_range(from_dt, to_dt):
        with open(path, encoding=LOG_ENCODING) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def filter_logs(
    entries,
    *,
    user_id: Optional[str] = None,
    status: Optional[str] = None,
    operation_type: Optional[str] = None,
    keyword: Optional[str] = None,
    has_pi: Optional[bool] = None,
    reference_no: Optional[str] = None,
    execution_method: Optional[str] = None,
):
    for e in entries:
        if user_id and e["who"]["user_id"].upper() != user_id.upper():
            continue
        if status and e["result"]["status"].upper() != status.upper():
            continue
        if operation_type and e["what"].get("operation_type") != operation_type:
            continue
        if has_pi is not None and e["result"]["has_personal_info"] != has_pi:
            continue
        if reference_no and reference_no not in e["why"].get("reference_no", ""):
            continue
        if execution_method and e["how"].get("execution_method") != execution_method:
            continue
        if keyword:
            raw = json.dumps(e, ensure_ascii=False).lower()
            if keyword.lower() not in raw:
                continue
        yield e
