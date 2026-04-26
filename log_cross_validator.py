"""
감사 로그 상호 검증 도구

oracle_proxy.py (execution_method="TNS Proxy") 와
packet_sniffer.py (execution_method="TNS Sniffer") 가 기록한 로그를 비교해
두 방식이 동일한 쿼리를 포착했는지 검증한다.

[검증 원리]
  SQL 정규화 해시 + 시간 오차(±N초) 로 두 로그를 매칭한다.

  MATCHED     : 양쪽 모두 기록 → 로그 신뢰도 높음
  PROXY_ONLY  : 프록시에만 있음 → 스니퍼가 놓쳤거나 앱이 직접 연결 후 프록시 경유
  SNIFFER_ONLY: 스니퍼에만 있음 → 앱이 프록시를 우회해 Oracle에 직접 접속한 의심

[구동]
  python log_cross_validator.py
  python log_cross_validator.py --date 20260426 --window 30
  python log_cross_validator.py --from-date 20260420 --to-date 20260426
"""

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Optional

from query_logger import iter_logs, filter_logs


# ══════════════════════════════════════════════════════════════════
# SQL 정규화
# ══════════════════════════════════════════════════════════════════

def _normalize_sql(sql: str) -> str:
    """
    SQL 을 정규화한다.
    대소문자·공백·바인드 변수·리터럴 값 차이를 무시하고 구조만 비교한다.
    """
    sql = sql.strip().upper()
    sql = re.sub(r'\s+', ' ', sql)               # 공백 통일
    sql = re.sub(r':\w+',   ':?', sql)           # :name 바인드 변수
    sql = re.sub(r"'[^']*'", "'?'", sql)         # 문자열 리터럴
    sql = re.sub(r'\b\d+\b', '?', sql)           # 숫자 리터럴
    return sql


def _sql_hash(sql: str) -> str:
    return hashlib.sha256(_normalize_sql(sql).encode()).hexdigest()[:16]


def _parse_time(entry: dict) -> datetime:
    return datetime.fromisoformat(entry["when"]["start_time"])


# ══════════════════════════════════════════════════════════════════
# 상호 검증 핵심 로직
# ══════════════════════════════════════════════════════════════════

def validate(
    from_dt:    date,
    to_dt:      date,
    window_sec: int = 30,
) -> dict:
    """
    지정 기간의 로그를 읽어 Proxy 로그 vs Sniffer 로그를 비교한다.

    Returns:
        {
          "matched":      [(proxy_entry, sniffer_entry), ...],
          "proxy_only":   [proxy_entry, ...],
          "sniffer_only": [sniffer_entry, ...],
          "summary":      {...}
        }
    """
    all_entries = list(iter_logs(from_dt, to_dt))

    proxy_entries   = [e for e in all_entries
                       if e["how"].get("execution_method") == "TNS Proxy"]
    sniffer_entries = [e for e in all_entries
                       if e["how"].get("execution_method") == "TNS Sniffer"]

    # 스니퍼 항목을 sql_hash → [(time, entry)] 역인덱스로 구성
    sniffer_idx: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)
    for e in sniffer_entries:
        sniffer_idx[_sql_hash(e["what"]["sql"])].append((_parse_time(e), e))

    matched:      list[tuple[dict, dict]] = []
    proxy_only:   list[dict]              = []
    matched_sids: set[str]               = set()

    for pe in proxy_entries:
        h  = _sql_hash(pe["what"]["sql"])
        pt = _parse_time(pe)

        best: Optional[dict] = None
        for st, se in sniffer_idx.get(h, []):
            if se["log_id"] in matched_sids:
                continue
            if abs((pt - st).total_seconds()) <= window_sec:
                best = se
                break

        if best:
            matched.append((pe, best))
            matched_sids.add(best["log_id"])
        else:
            proxy_only.append(pe)

    sniffer_only = [e for e in sniffer_entries if e["log_id"] not in matched_sids]

    total_proxy   = len(proxy_entries)
    total_sniffer = len(sniffer_entries)
    match_rate    = (len(matched) / max(total_proxy, 1)) * 100

    return {
        "matched":      matched,
        "proxy_only":   proxy_only,
        "sniffer_only": sniffer_only,
        "summary": {
            "proxy_total":    total_proxy,
            "sniffer_total":  total_sniffer,
            "matched":        len(matched),
            "proxy_only":     len(proxy_only),
            "sniffer_only":   len(sniffer_only),
            "match_rate_pct": round(match_rate, 1),
        },
    }


# ══════════════════════════════════════════════════════════════════
# 보고서 출력
# ══════════════════════════════════════════════════════════════════

def _shorten(sql: str, n: int = 80) -> str:
    sql = re.sub(r'\s+', ' ', sql.strip())
    return (sql[:n] + "...") if len(sql) > n else sql


def print_report(result: dict, verbose: bool = False) -> None:
    s = result["summary"]
    w = 62

    print("=" * w)
    print("  감사 로그 상호 검증 보고서")
    print("=" * w)
    print(f"  프록시 로그 (TNS Proxy)   : {s['proxy_total']:>6} 건")
    print(f"  스니퍼 로그 (TNS Sniffer) : {s['sniffer_total']:>6} 건")
    print("-" * w)
    print(f"  [MATCHED]      양쪽 일치  : {s['matched']:>6} 건")
    print(f"  [PROXY_ONLY]   프록시만   : {s['proxy_only']:>6} 건")
    print(f"  [SNIFFER_ONLY] 스니퍼만   : {s['sniffer_only']:>6} 건")
    print(f"  매칭률                    : {s['match_rate_pct']:>5.1f} %")
    print("=" * w)

    # ── PROXY_ONLY: 앱이 프록시를 우회했을 가능성 ─────────────────────
    if result["proxy_only"]:
        print(f"\n[PROXY_ONLY] 스니퍼 미탐지 목록 ({len(result['proxy_only'])}건)")
        print("  스니퍼가 해당 패킷을 놓쳤거나 앱→Oracle 경로가 다를 수 있음")
        for e in result["proxy_only"][:20]:
            t  = _parse_time(e).strftime("%H:%M:%S")
            u  = e["who"]["user_id"]
            st = e["result"]["status"]
            print(f"  {t}  [{u}]  {st}  {_shorten(e['what']['sql'])}")
        if len(result["proxy_only"]) > 20:
            print(f"  ... 외 {len(result['proxy_only']) - 20}건")

    # ── SNIFFER_ONLY: 앱이 프록시를 우회해 직접 접속한 의심 ─────────────
    if result["sniffer_only"]:
        print(f"\n[SNIFFER_ONLY] ★ 프록시 미기록 목록 ({len(result['sniffer_only'])}건)")
        print("  ★ 앱이 프록시를 우회해 Oracle 에 직접 접속한 의심 있음")
        for e in result["sniffer_only"][:20]:
            t  = _parse_time(e).strftime("%H:%M:%S")
            u  = e["who"]["user_id"]
            st = e["result"]["status"]
            print(f"  {t}  [{u}]  {st}  {_shorten(e['what']['sql'])}")
        if len(result["sniffer_only"]) > 20:
            print(f"  ... 외 {len(result['sniffer_only']) - 20}건")

    # ── MATCHED: 일치 목록 (verbose 모드) ────────────────────────────────
    if verbose and result["matched"]:
        print(f"\n[MATCHED] 양쪽 일치 목록 ({len(result['matched'])}건)")
        for pe, se in result["matched"][:20]:
            pt = _parse_time(pe).strftime("%H:%M:%S")
            st = _parse_time(se).strftime("%H:%M:%S")
            u  = pe["who"]["user_id"]
            diff = abs((_parse_time(pe) - _parse_time(se)).total_seconds())
            print(f"  proxy={pt}  sniffer={st}  diff={diff:.1f}s  [{u}]  "
                  f"{_shorten(pe['what']['sql'], 60)}")

    # ── 검증 결론 ─────────────────────────────────────────────────────────
    print()
    if s["sniffer_only"] == 0 and s["proxy_only"] == 0:
        print("  결론: 완전 일치 — 모든 쿼리가 프록시를 통해 기록됨 (이상 없음)")
    elif s["sniffer_only"] > 0:
        print("  결론: ★ 우회 접속 의심 — SNIFFER_ONLY 항목 확인 필요")
    else:
        print("  결론: 스니퍼 미탐지 존재 — 스니퍼 권한·포트 설정 확인 권고")
    print("=" * w)


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    today_str = date.today().strftime("%Y%m%d")

    parser = argparse.ArgumentParser(
        description="oracle_proxy.py vs packet_sniffer.py 감사 로그 상호 검증",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--date",
                        help="검증 날짜 (YYYYMMDD). 생략 시 오늘")
    parser.add_argument("--from-date", default=today_str,
                        help="검증 시작 날짜 (YYYYMMDD)")
    parser.add_argument("--to-date",   default=today_str,
                        help="검증 종료 날짜 (YYYYMMDD)")
    parser.add_argument("--window",    type=int, default=30,
                        help="매칭 허용 시간 오차 (초)")
    parser.add_argument("--verbose",   action="store_true",
                        help="MATCHED 항목도 출력")
    args = parser.parse_args()

    if args.date:
        from_dt = to_dt = datetime.strptime(args.date, "%Y%m%d").date()
    else:
        from_dt = datetime.strptime(args.from_date, "%Y%m%d").date()
        to_dt   = datetime.strptime(args.to_date,   "%Y%m%d").date()

    result = validate(from_dt, to_dt, window_sec=args.window)
    print_report(result, verbose=args.verbose)


if __name__ == "__main__":
    main()
