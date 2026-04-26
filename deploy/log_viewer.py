"""
쿼리 감사 로그 CLI 조회 프로그램

실행)
    python log_viewer.py                       # 대화형 메뉴
    python log_viewer.py --date 20260425       # 특정 날짜 전체 조회
    python log_viewer.py --user U001           # 특정 사용자 로그
    python log_viewer.py --status FAILURE      # 실패 로그만
    python log_viewer.py --op 조회             # 업무유형 필터 (조회/생성/변경/삭제)
    python log_viewer.py --keyword 홍길동      # 키워드 검색
    python log_viewer.py --from 20260401 --to 20260425  # 기간 조회
    python log_viewer.py --verify              # 무결성 검증
    python log_viewer.py --export result.csv   # CSV 내보내기
"""

import sys
import csv
import argparse
from datetime import datetime, date

from config import MASK_PERSONAL_INFO
from query_logger import (
    verify_entry, mask_value,
    iter_logs, filter_logs, OPERATION_TYPE_MAP, PI_TYPE_NAMES,
)

# ──────────────────────────────────────────────
# ANSI 색상 (Windows 터미널 지원)
# ──────────────────────────────────────────────
try:
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(
        ctypes.windll.kernel32.GetStdHandle(-11), 7
    )
except Exception:
    pass

C = {
    "reset" : "\033[0m",  "bold"  : "\033[1m",
    "red"   : "\033[91m", "green" : "\033[92m",
    "yellow": "\033[93m", "cyan"  : "\033[96m",
    "gray"  : "\033[90m", "orange": "\033[33m",
    "blue"  : "\033[94m", "white" : "\033[97m",
}

def c(color: str, text: str) -> str:
    return f"{C.get(color,'')}{text}{C['reset']}"

OP_COLORS = {
    "조회": "blue", "생성": "green", "변경": "orange", "삭제": "red",
}

def op_colored(op: str) -> str:
    return c(OP_COLORS.get(op, "gray"), f"[{op}]")


# ──────────────────────────────────────────────
# 단일 항목 출력
# ──────────────────────────────────────────────

def display_entry(entry: dict, mask: bool = MASK_PERSONAL_INFO, detail: bool = False):
    w    = entry["who"]
    when = entry["when"]
    whr  = entry["where"]
    wht  = entry["what"]
    how  = entry["how"]
    why  = entry["why"]
    res  = entry["result"]

    op_type      = wht.get("operation_type", wht.get("query_type", "?"))
    status_color = "green" if res["status"] == "SUCCESS" else "red"
    pi_tag       = c("yellow", "[개인정보]") if res["has_personal_info"] else ""

    print(c("bold", "─" * 72))
    print(f"  {c('cyan','로그 ID')}  : {entry['log_id']}")
    print(f"  {c('cyan','언제')}     : {when['start_time']}  ({when['duration_ms']} ms)")
    print(f"  {c('cyan','누가')}     : {w['user_name']} ({w['user_id']}) / {w['user_role']}")
    print(f"  {c('cyan','어디서')}   : {whr['client_ip']} ({whr['hostname']}) "
          f"→ {whr['db_server']}/{whr['db_name']}.{whr['db_schema']}")

    sql_preview = wht["sql"].replace("\n", " ").replace("  ", " ").strip()
    if len(sql_preview) > 80:
        sql_preview = sql_preview[:77] + "..."
    print(f"  {c('cyan','무엇을')}   : {op_colored(op_type)} {sql_preview}")
    if wht.get("parameters"):
        print(f"             파라미터: {wht['parameters']}")

    print(f"  {c('cyan','어떻게')}   : {how['execution_method']} | {how['application']} | 세션: {how['session_id']}")
    print(f"  {c('cyan','왜')}       : {why.get('purpose','—')}  [참조번호: {why.get('reference_no') or '—'}]")

    row_count = wht.get("row_count") or res.get("result_count") or 0
    print(f"  {c('cyan','결과')}     : {c(status_color, res['status'])} {pi_tag} | {row_count:,}건")
    if res.get("error_message"):
        print(f"  {c('red','오류')}     : {res['error_message']}")

    # 개인정보 항목별 건수
    pi_counts = res.get("personal_info_counts", {})
    if pi_counts and any(v > 0 for v in pi_counts.values()):
        detail_parts = [f"{k}: {pi_counts[k]}건" for k in PI_TYPE_NAMES if pi_counts.get(k, 0) > 0]
        print(f"  {c('yellow','개인정보 건수')}: {', '.join(detail_parts)}")

    if detail and res.get("result_data"):
        data = mask_value(res["result_data"]) if mask else res["result_data"]
        print(f"\n  {c('bold','결과 데이터')} ({len(data)}건):")
        for i, row in enumerate(data[:20], 1):
            print(f"    [{i:02d}] {row}")
        if len(data) > 20:
            print(f"         ... 외 {len(data)-20}건 생략")

    valid = verify_entry(entry)
    integrity = c("green", "✔ 무결성 정상") if valid else c("red", "✘ 무결성 위반!")
    print(f"  {c('gray','무결성')}   : {integrity}")


# ──────────────────────────────────────────────
# 통계 요약
# ──────────────────────────────────────────────

def print_summary(entries: list[dict]):
    total    = len(entries)
    success  = sum(1 for e in entries if e["result"]["status"] == "SUCCESS")
    failure  = total - success
    pi_count = sum(1 for e in entries if e["result"]["has_personal_info"])
    users, ops = {}, {}
    for e in entries:
        uid = e["who"]["user_id"]
        op  = e["what"].get("operation_type", e["what"]["query_type"])
        users[uid] = users.get(uid, 0) + 1
        ops[op]    = ops.get(op, 0) + 1

    print(c("bold", "\n  ── 통계 요약 ──"))
    print(f"  전체 쿼리     : {total}건")
    print(f"  성공 / 실패   : {c('green', str(success))} / {c('red', str(failure))}")
    print(f"  개인정보 포함 : {c('yellow', str(pi_count))}건")
    print(f"  업무 유형     : {dict(sorted(ops.items(), key=lambda x:-x[1]))}")
    print(f"  사용자별      :")
    for uid, cnt in sorted(users.items(), key=lambda x: -x[1]):
        print(f"    {uid}: {cnt}건")


# ──────────────────────────────────────────────
# CSV 내보내기
# ──────────────────────────────────────────────

def export_csv(entries: list[dict], path: str, mask: bool = True):
    import json as _json
    fieldnames = [
        "log_id", "start_time", "duration_ms",
        "user_id", "user_name", "user_role",
        "client_ip", "hostname", "db_server", "db_name",
        "operation_type", "query_type", "sql", "parameters",
        "execution_method", "session_id",
        "purpose", "reference_no",
        "status", "affected_rows", "result_count",
        "has_personal_info", "error_message", "integrity_ok",
    ]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            writer.writerow({
                "log_id"          : e["log_id"],
                "start_time"      : e["when"]["start_time"],
                "duration_ms"     : e["when"]["duration_ms"],
                "user_id"         : e["who"]["user_id"],
                "user_name"       : e["who"]["user_name"],
                "user_role"       : e["who"]["user_role"],
                "client_ip"       : e["where"]["client_ip"],
                "hostname"        : e["where"]["hostname"],
                "db_server"       : e["where"]["db_server"],
                "db_name"         : e["where"]["db_name"],
                "operation_type"  : e["what"].get("operation_type", ""),
                "query_type"      : e["what"]["query_type"],
                "sql"             : e["what"]["sql"],
                "parameters"      : _json.dumps(e["what"].get("parameters"), ensure_ascii=False),
                "execution_method": e["how"]["execution_method"],
                "session_id"      : e["how"]["session_id"],
                "purpose"         : e["why"].get("purpose", ""),
                "reference_no"    : e["why"].get("reference_no", ""),
                "status"          : e["result"]["status"],
                "affected_rows"   : e["what"].get("affected_rows", 0),
                "result_count"    : e["result"].get("result_count", 0),
                "has_personal_info": e["result"]["has_personal_info"],
                "error_message"   : e["result"].get("error_message", ""),
                "integrity_ok"    : verify_entry(e),
            })
    print(c("green", f"CSV 내보내기 완료: {path}  ({len(entries)}건)"))


# ──────────────────────────────────────────────
# 무결성 검증
# ──────────────────────────────────────────────

def run_verify(from_dt: date, to_dt: date):
    total, ok, fail = 0, 0, 0
    for e in iter_logs(from_dt, to_dt):
        total += 1
        if verify_entry(e):
            ok += 1
        else:
            fail += 1
            print(c("red", f"  [무결성 위반] log_id={e['log_id']}  time={e['when']['start_time']}"))
    if fail == 0:
        print(c("green", f"\n  무결성 검증 완료: {total}건 모두 정상 ✔"))
    else:
        print(c("red", f"\n  경고: {total}건 중 {fail}건 위반 발견!"))


# ──────────────────────────────────────────────
# 대화형 메뉴
# ──────────────────────────────────────────────

def _today() -> str:
    return date.today().strftime("%Y%m%d")

def _parse_date(s: str) -> date:
    return datetime.strptime(s.strip(), "%Y%m%d").date()

def _ask(prompt: str, default: str = "") -> str:
    val = input(f"  {prompt}").strip()
    return val if val else default


def _query_and_show(d_fr, d_to, *, user_id=None, status=None,
                    operation_type=None, keyword=None, has_pi=None):
    entries = list(filter_logs(
        iter_logs(_parse_date(d_fr), _parse_date(d_to)),
        user_id=user_id, status=status,
        operation_type=operation_type, keyword=keyword, has_pi=has_pi,
    ))
    if not entries:
        print(c("gray", "\n  조회 결과가 없습니다."))
        return
    print(c("bold", f"\n  총 {len(entries)}건 조회됨"))
    detail_ans = _ask("결과 데이터도 표시할까요? (y/N): ").lower() == "y"
    do_mask    = _ask("개인정보 마스킹 (Y=마스킹 / n=원문) [Y]: ").lower() != "n"
    for e in entries:
        display_entry(e, mask=do_mask, detail=detail_ans)
    print_summary(entries)


def interactive_menu():
    ops_list = "조회/생성/변경/삭제"
    while True:
        print(c("bold", "\n  ════════════════════════════════════"))
        print(c("bold", "    쿼리 감사 로그 조회 (CLI)"))
        print(c("bold", "  ════════════════════════════════════"))
        print("  1. 날짜 조회")
        print("  2. 사용자 조회")
        print("  3. 업무유형 조회  (조회/생성/변경/삭제)")
        print("  4. 실패 로그 조회")
        print("  5. 개인정보 포함 로그 조회")
        print("  6. 키워드 검색")
        print("  7. 기간 + 복합 조건 조회")
        print("  8. 무결성 전체 검증")
        print("  9. CSV 내보내기")
        print("  0. 종료")
        choice = _ask("선택 > ")

        today = _today()

        if choice == "1":
            d = _ask(f"날짜 (YYYYMMDD, 엔터=오늘): ", today)
            _query_and_show(d, d)

        elif choice == "2":
            uid  = _ask("사용자 ID: ")
            d_fr = _ask(f"시작일 (YYYYMMDD, 엔터=오늘): ", today)
            d_to = _ask(f"종료일 (YYYYMMDD, 엔터=오늘): ", today)
            _query_and_show(d_fr, d_to, user_id=uid)

        elif choice == "3":
            op   = _ask(f"업무유형 ({ops_list}): ")
            d_fr = _ask(f"시작일 (YYYYMMDD, 엔터=오늘): ", today)
            d_to = _ask(f"종료일 (YYYYMMDD, 엔터=오늘): ", today)
            _query_and_show(d_fr, d_to, operation_type=op)

        elif choice == "4":
            d_fr = _ask(f"시작일 (YYYYMMDD, 엔터=오늘): ", today)
            d_to = _ask(f"종료일 (YYYYMMDD, 엔터=오늘): ", today)
            _query_and_show(d_fr, d_to, status="FAILURE")

        elif choice == "5":
            d_fr = _ask(f"시작일 (YYYYMMDD, 엔터=오늘): ", today)
            d_to = _ask(f"종료일 (YYYYMMDD, 엔터=오늘): ", today)
            _query_and_show(d_fr, d_to, has_pi=True)

        elif choice == "6":
            kw   = _ask("검색 키워드: ")
            d_fr = _ask(f"시작일 (YYYYMMDD, 엔터=오늘): ", today)
            d_to = _ask(f"종료일 (YYYYMMDD, 엔터=오늘): ", today)
            _query_and_show(d_fr, d_to, keyword=kw)

        elif choice == "7":
            d_fr = _ask("시작일 (YYYYMMDD): ")
            d_to = _ask("종료일 (YYYYMMDD): ")
            uid  = _ask("사용자 ID (엔터=전체): ") or None
            st   = _ask("상태 SUCCESS/FAILURE (엔터=전체): ").upper() or None
            op   = _ask(f"업무유형 ({ops_list}, 엔터=전체): ") or None
            kw   = _ask("키워드 (엔터=없음): ") or None
            _query_and_show(d_fr, d_to, user_id=uid, status=st,
                            operation_type=op, keyword=kw)

        elif choice == "8":
            d_fr = _ask(f"시작일 (YYYYMMDD, 엔터=오늘): ", today)
            d_to = _ask(f"종료일 (YYYYMMDD, 엔터=오늘): ", today)
            run_verify(_parse_date(d_fr), _parse_date(d_to))

        elif choice == "9":
            d_fr = _ask(f"시작일 (YYYYMMDD, 엔터=오늘): ", today)
            d_to = _ask(f"종료일 (YYYYMMDD, 엔터=오늘): ", today)
            out  = _ask("저장 파일명 [audit_export.csv]: ") or "audit_export.csv"
            entries = list(iter_logs(_parse_date(d_fr), _parse_date(d_to)))
            export_csv(entries, out)

        elif choice == "0":
            print("  종료합니다.")
            break
        else:
            print(c("red", "  잘못된 선택입니다."))


# ──────────────────────────────────────────────
# CLI 진입점
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="쿼리 감사 로그 CLI 조회 프로그램")
    parser.add_argument("--date",    help="특정 날짜 (YYYYMMDD)")
    parser.add_argument("--from",    dest="from_dt", help="시작일 (YYYYMMDD)")
    parser.add_argument("--to",      dest="to_dt",   help="종료일 (YYYYMMDD)")
    parser.add_argument("--user",    help="사용자 ID 필터")
    parser.add_argument("--status",  help="SUCCESS / FAILURE")
    parser.add_argument("--op",      help="업무유형: 조회/생성/변경/삭제")
    parser.add_argument("--keyword", help="키워드 검색")
    parser.add_argument("--pi",      action="store_true", help="개인정보 포함 로그만")
    parser.add_argument("--verify",  action="store_true", help="무결성 검증")
    parser.add_argument("--export",  help="CSV 내보내기 경로")
    parser.add_argument("--detail",  action="store_true", help="결과 데이터 출력")
    parser.add_argument("--no-mask", action="store_true", help="개인정보 마스킹 해제")
    parser.add_argument("--summary", action="store_true", help="통계 요약만 표시")
    args = parser.parse_args()

    today = date.today()
    if args.date:
        fr = to = _parse_date(args.date)
    elif args.from_dt or args.to_dt:
        fr = _parse_date(args.from_dt) if args.from_dt else today
        to = _parse_date(args.to_dt)   if args.to_dt   else today
    else:
        if len(sys.argv) == 1:
            interactive_menu()
            return
        fr = to = today

    if args.verify:
        run_verify(fr, to)
        return

    entries = list(filter_logs(
        iter_logs(fr, to),
        user_id=args.user,
        status=args.status,
        operation_type=args.op,
        keyword=args.keyword,
        has_pi=True if args.pi else None,
    ))

    if args.export:
        export_csv(entries, args.export, mask=not args.no_mask)
        return

    print(c("bold", f"\n총 {len(entries)}건 조회됨  ({fr} ~ {to})"))
    if args.summary:
        if entries:
            print_summary(entries)
        return

    do_mask = not args.no_mask
    for e in entries:
        display_entry(e, mask=do_mask, detail=args.detail)
    if entries:
        print_summary(entries)


if __name__ == "__main__":
    main()
