"""
샘플 감사 로그 생성 스크립트

테스트용 로그를 생성한다. write_query_log()를 직접 호출해
무결성 해시가 올바르게 계산된 로그 파일을 만든다.

실행:
    python generate_sample_logs.py
    python generate_sample_logs.py --days 5   # 최근 N일치
    python generate_sample_logs.py --clear    # 기존 로그 삭제 후 재생성
"""

import argparse
import sys
from datetime import datetime, timedelta, date
from pathlib import Path
from unittest.mock import patch

from config import LOG_DIR
from query_logger import write_query_log


# ── 테스트 픽스처 ──────────────────────────────────────────────────

USERS = [
    {"user_id": "U001", "user_name": "홍길동",  "user_role": "analyst"},
    {"user_id": "U002", "user_name": "김영희",  "user_role": "teller"},
    {"user_id": "U003", "user_name": "이철수",  "user_role": "auditor"},
    {"user_id": "U004", "user_name": "박민준",  "user_role": "analyst"},
    {"user_id": "U005", "user_name": "최수진",  "user_role": "teller"},
    {"user_id": "U006", "user_name": "정다은",  "user_role": "admin"},
    {"user_id": "BATCH", "user_name": "배치시스템", "user_role": "system"},
]

CUSTOMERS = [
    {"id": 1,  "name": "홍길동", "ssn": "800101-1234567", "phone": "010-1234-5678",
     "card": "1234-5678-9012-3456", "account": "110-123-456789",
     "email": "hong@finance.co.kr", "credit_score": 850},
    {"id": 2,  "name": "김영희", "ssn": "900215-2345678", "phone": "010-2345-6789",
     "card": "2345-6789-0123-4567", "account": "110-234-567890",
     "email": "kim@finance.co.kr",  "credit_score": 720},
    {"id": 3,  "name": "이철수", "ssn": "751130-1456789", "phone": "010-3456-7890",
     "card": "3456-7890-1234-5678", "account": "110-345-678901",
     "email": "lee@finance.co.kr",  "credit_score": 910},
    {"id": 4,  "name": "박민준", "ssn": "851020-1567890", "phone": "010-4567-8901",
     "card": "4567-8901-2345-6789", "account": "110-456-789012",
     "email": "park@finance.co.kr", "credit_score": 680},
    {"id": 5,  "name": "최수진", "ssn": "920308-2678901", "phone": "010-5678-9012",
     "card": "5678-9012-3456-7890", "account": "110-567-890123",
     "email": "choi@finance.co.kr", "credit_score": 760},
]

ACCOUNTS = [
    {"account_no": "110-123-456789", "customer_id": 1, "balance": 15_000_000, "type": "입출금"},
    {"account_no": "110-234-567890", "customer_id": 2, "balance":  8_500_000, "type": "입출금"},
    {"account_no": "110-345-678901", "customer_id": 3, "balance": 32_000_000, "type": "정기예금"},
    {"account_no": "110-456-789012", "customer_id": 4, "balance":  3_200_000, "type": "입출금"},
    {"account_no": "110-567-890123", "customer_id": 5, "balance": 12_800_000, "type": "입출금"},
    {"account_no": "110-678-901234", "customer_id": 1, "balance": 50_000_000, "type": "정기예금"},
]

TRANSACTIONS = [
    {"id": 101, "account_no": "110-123-456789", "name": "홍길동", "amount":  500_000, "type": "입금",  "date": "2026-04-24"},
    {"id": 102, "account_no": "110-234-567890", "name": "김영희", "amount": -300_000, "type": "출금",  "date": "2026-04-24"},
    {"id": 103, "account_no": "110-345-678901", "name": "이철수", "amount": 5_000_000,"type": "이체",  "date": "2026-04-25"},
    {"id": 104, "account_no": "110-456-789012", "name": "박민준", "amount": -150_000, "type": "출금",  "date": "2026-04-25"},
    {"id": 105, "account_no": "110-567-890123", "name": "최수진", "amount":  800_000, "type": "입금",  "date": "2026-04-26"},
    {"id": 106, "account_no": "110-123-456789", "name": "홍길동", "amount": -450_000, "type": "출금",  "date": "2026-04-26"},
    {"id": 107, "account_no": "110-678-901234", "name": "홍길동", "amount": 10_000_000,"type": "입금", "date": "2026-04-26"},
    {"id": 108, "account_no": "110-345-678901", "name": "이철수", "amount": -8_000_000,"type": "출금", "date": "2026-04-26"},
]


def _ts(base: datetime, offset_sec: int = 0, duration_ms: int = 12) -> tuple[datetime, datetime]:
    """시작/종료 datetime 쌍 반환"""
    start = base + timedelta(seconds=offset_sec)
    end   = start + timedelta(milliseconds=duration_ms)
    return start, end


def _log(base: datetime, offset_sec: int, duration_ms: int, user: dict,
         sql: str, params, method: str, purpose: str, ref: str,
         status: str, result_data=None, affected: int = 0,
         client_ip: str = "192.168.1.50", error: str = None):
    st, et = _ts(base, offset_sec, duration_ms)
    write_query_log(
        user_id=user["user_id"], user_name=user["user_name"], user_role=user["user_role"],
        client_ip=client_ip, hostname="appserver01",
        db_server="192.168.1.10", db_name="FINDB", db_schema="FINSCHEMA",
        sql=sql, parameters=params,
        execution_method=method,
        purpose=purpose, reference_no=ref,
        start_time=st, end_time=et,
        status=status,
        affected_rows=affected,
        result_data=result_data,
        error_message=error,
    )


# ── 날짜별 시나리오 ────────────────────────────────────────────────

def _generate_day(base_date: date) -> None:
    """하루치 샘플 로그 생성"""
    B = datetime(base_date.year, base_date.month, base_date.day, 9, 0, 0)
    U = USERS
    M_APP  = "애플리케이션"
    M_PROX = "TNS Proxy"
    M_SNIF = "TNS Sniffer"

    # ── 9:00 업무 시작 — 신용 조회 ─────────────────────────────────
    _log(B, 120, 45, U[0],
         "SELECT id, name, ssn, phone, credit_score FROM customers WHERE credit_score >= :1",
         [700], M_APP, "고객 신용평가 심사", "CREDIT-2026-001",
         "SUCCESS",
         result_data=[{k: v for k, v in c.items() if k in ("id","name","ssn","phone","credit_score")}
                      for c in CUSTOMERS if c["credit_score"] >= 700])

    # ── 9:05 계좌 잔액 조회 (JOIN) ──────────────────────────────────
    _log(B, 300, 22, U[1],
         "SELECT c.name, c.phone, a.account_no, a.balance, a.type FROM customers c JOIN accounts a ON a.customer_id = c.id WHERE c.id = :1",
         [1], M_PROX, "창구 고객 계좌 확인", "TELLER-2026-042",
         "SUCCESS",
         result_data=[{"name": "홍길동", "phone": "010-1234-5678",
                       "account_no": "110-123-456789", "balance": 15_000_000, "type": "입출금"},
                      {"name": "홍길동", "phone": "010-1234-5678",
                       "account_no": "110-678-901234", "balance": 50_000_000, "type": "정기예금"}],
         client_ip="192.168.1.51")

    # ── 9:15 AML 고액 거래 조회 ──────────────────────────────────────
    _log(B, 900, 130, U[2],
         "SELECT t.id, c.name, c.phone, a.account_no, t.amount, t.type, t.date FROM transactions t JOIN accounts a ON a.id = t.account_id JOIN customers c ON c.id = a.customer_id WHERE ABS(t.amount) >= :1 ORDER BY ABS(t.amount) DESC",
         [3_000_000], M_SNIF, "AML 이상 거래 점검", "AML-2026-015",
         "SUCCESS",
         result_data=[{"id": 107, "name": "홍길동", "phone": "010-1234-5678",
                       "account_no": "110-678-901234", "amount": 10_000_000, "type": "입금", "date": "2026-04-26"},
                      {"id": 108, "name": "이철수", "phone": "010-3456-7890",
                       "account_no": "110-345-678901", "amount": -8_000_000, "type": "출금", "date": "2026-04-26"},
                      {"id": 103, "name": "이철수", "phone": "010-3456-7890",
                       "account_no": "110-345-678901", "amount": 5_000_000, "type": "이체", "date": "2026-04-25"}],
         client_ip="192.168.1.52")

    # ── 9:30 고객 연락처 수정 ────────────────────────────────────────
    _log(B, 1800, 18, U[0],
         "UPDATE customers SET phone = :1, email = :2 WHERE id = :3",
         ["010-9999-0000", "new@finance.co.kr", 3],
         M_APP, "고객 정보 정정 요청 처리", "UPDATE-2026-007",
         "SUCCESS", affected=1)

    # ── 9:45 신규 계좌 개설 ──────────────────────────────────────────
    _log(B, 2700, 35, U[1],
         "INSERT INTO accounts (account_no, customer_id, balance, type) VALUES (:1, :2, :3, :4)",
         ["110-999-000001", 4, 100_000, "입출금"],
         M_PROX, "신규 계좌 개설", "ACCT-2026-088",
         "SUCCESS", affected=1,
         client_ip="192.168.1.51")

    # ── 10:00 전체 고객 카드번호 조회 (민감 조회) ────────────────────
    _log(B, 3600, 88, U[3],
         "SELECT id, name, ssn, card, account, email FROM customers WHERE status = :1",
         ["ACTIVE"], M_APP, "신용한도 심사", "LIMIT-2026-088",
         "SUCCESS",
         result_data=[{"id": c["id"], "name": c["name"], "ssn": c["ssn"],
                       "card": c["card"], "account": c["account"], "email": c["email"]}
                      for c in CUSTOMERS],
         client_ip="192.168.1.53")

    # ── 10:30 거래 내역 삭제 (오래된 데이터) ────────────────────────
    _log(B, 5400, 55, U[5],
         "DELETE FROM transactions WHERE date < :1 AND type = :2",
         ["2025-01-01", "출금"],
         M_APP, "만료 거래 데이터 정리", "ADMIN-2026-001",
         "SUCCESS", affected=0,
         client_ip="192.168.1.54")

    # ── 11:00 존재하지 않는 테이블 조회 (실패) ──────────────────────
    _log(B, 7200, 8, U[1],
         "SELECT * FROM nonexistent_table WHERE id = :1",
         [1], M_APP, "오류 테스트 쿼리", "",
         "FAILURE",
         error="ORA-00942: table or view does not exist",
         client_ip="192.168.1.51")

    # ── 11:10 권한 없는 테이블 접근 (실패) ──────────────────────────
    _log(B, 7800, 5, U[4],
         "SELECT * FROM dba_users",
         None, M_PROX, "사용자 목록 조회 시도", "",
         "FAILURE",
         error="ORA-00942: table or view does not exist",
         client_ip="192.168.1.51")

    # ── 12:00 점심 후 배치 — 일일 잔액 요약 ─────────────────────────
    _log(B, 10800, 312, U[6],
         "SELECT a.account_no, c.name, c.phone, a.balance FROM accounts a JOIN customers c ON c.id = a.customer_id ORDER BY a.balance DESC",
         None, M_SNIF, "일일 잔액 현황 배치", "BATCH-2026-0426",
         "SUCCESS",
         result_data=[{"account_no": a["account_no"], "name": next(c["name"] for c in CUSTOMERS if c["id"] == a["customer_id"]),
                       "phone": next(c["phone"] for c in CUSTOMERS if c["id"] == a["customer_id"]),
                       "balance": a["balance"]} for a in sorted(ACCOUNTS, key=lambda x: -x["balance"])],
         client_ip="192.168.1.100")

    # ── 13:00 특정 계좌 이체 실행 ────────────────────────────────────
    _log(B, 14400, 42, U[1],
         "UPDATE accounts SET balance = balance + :1 WHERE account_no = :2",
         [500_000, "110-234-567890"],
         M_PROX, "창구 입금 처리", "TXN-2026-5501",
         "SUCCESS", affected=1,
         client_ip="192.168.1.51")

    # ── 13:05 이체 거래 로그 INSERT ──────────────────────────────────
    _log(B, 14700, 15, U[1],
         "INSERT INTO transactions (account_no, amount, type, date) VALUES (:1, :2, :3, :4)",
         ["110-234-567890", 500_000, "입금", base_date.isoformat()],
         M_PROX, "창구 입금 처리", "TXN-2026-5501",
         "SUCCESS", affected=1,
         client_ip="192.168.1.51")

    # ── 14:00 대출 심사 — 주민번호 포함 ─────────────────────────────
    _log(B, 18000, 67, U[0],
         "SELECT c.name, c.ssn, c.phone, c.credit_score, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.id WHERE c.id = :1",
         [2], M_APP, "주택담보대출 심사", "LOAN-2026-0312",
         "SUCCESS",
         result_data=[{"name": "김영희", "ssn": "900215-2345678", "phone": "010-2345-6789",
                       "credit_score": 720, "balance": 8_500_000}])

    # ── 15:00 프로시저 호출 ──────────────────────────────────────────
    _log(B, 21600, 220, U[2],
         "CALL generate_monthly_report(:1, :2)",
         [base_date.strftime("%Y%m"), "AML"],
         M_PROX, "월간 AML 보고서 생성", "RPT-2026-04",
         "SUCCESS",
         client_ip="192.168.1.52")

    # ── 15:30 계좌 정보 조회 (이메일 포함) ──────────────────────────
    _log(B, 23400, 33, U[4],
         "SELECT c.name, c.email, c.phone, a.account_no FROM customers c JOIN accounts a ON a.customer_id = c.id WHERE a.type = :1",
         ["정기예금"], M_APP, "정기예금 만기 안내", "NOTICE-2026-088",
         "SUCCESS",
         result_data=[{"name": "이철수", "email": "lee@finance.co.kr",
                       "phone": "010-3456-7890", "account_no": "110-345-678901"},
                      {"name": "홍길동", "email": "hong@finance.co.kr",
                       "phone": "010-1234-5678", "account_no": "110-678-901234"}],
         client_ip="192.168.1.51")

    # ── 16:00 DDL — 임시 테이블 생성 ────────────────────────────────
    _log(B, 25200, 18, U[5],
         "CREATE TABLE temp_audit_20260426 AS SELECT * FROM transactions WHERE ROWNUM <= 1000",
         None, M_APP, "감사 임시 데이터 추출", "AUDIT-2026-TMP",
         "SUCCESS",
         client_ip="192.168.1.54")

    # ── 17:00 야간 배치 — 신용점수 갱신 ─────────────────────────────
    _log(B, 28800, 1850, U[6],
         "UPDATE customers SET credit_score = credit_score + :1 WHERE id IN (SELECT customer_id FROM accounts WHERE balance >= :2)",
         [5, 10_000_000],
         M_SNIF, "신용점수 자동 갱신 배치", "BATCH-CREDIT-2026",
         "SUCCESS", affected=2,
         client_ip="192.168.1.100")

    # ── 17:30 전체 고객 삭제 시도 (실패 — 권한 없음) ────────────────
    _log(B, 30600, 6, U[4],
         "TRUNCATE TABLE customers",
         None, M_APP, "테이블 초기화 시도", "",
         "FAILURE",
         error="ORA-01031: insufficient privileges",
         client_ip="192.168.1.55")

    # ── 17:45 카드번호 조회 ──────────────────────────────────────────
    _log(B, 31500, 44, U[3],
         "SELECT name, card, ssn FROM customers WHERE id = :1",
         [5], M_APP, "카드 재발급 심사", "CARD-2026-0201",
         "SUCCESS",
         result_data=[{"name": "최수진", "card": "5678-9012-3456-7890", "ssn": "920308-2678901"}],
         client_ip="192.168.1.53")

    print(f"  {base_date}: {17}건 생성")


def main() -> None:
    parser = argparse.ArgumentParser(description="샘플 감사 로그 생성")
    parser.add_argument("--days",  type=int, default=3, help="생성할 날짜 수 (최근 N일)")
    parser.add_argument("--clear", action="store_true",  help="기존 로그 파일 삭제 후 재생성")
    args = parser.parse_args()

    log_dir = Path(LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)

    if args.clear:
        removed = list(log_dir.glob("audit_query_*.jsonl"))
        for f in removed:
            f.unlink()
        print(f"기존 로그 {len(removed)}개 삭제")

    today = date(2026, 4, 26)
    dates = [today - timedelta(days=i) for i in range(args.days - 1, -1, -1)]

    print(f"샘플 로그 생성 중 ({args.days}일치, 일당 17건)...")
    for d in dates:
        _generate_day(d)

    total = args.days * 17
    files = sorted(log_dir.glob("audit_query_*.jsonl"))
    print(f"\n완료: {total}건 기록")
    print(f"파일: {[f.name for f in files]}")
    print("\n조회:")
    print("  python log_viewer.py")
    print("  python log_viewer_web.py  ->  http://localhost:8888")


if __name__ == "__main__":
    main()
