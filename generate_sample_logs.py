"""
샘플 감사 로그 생성 스크립트

Oracle (TNS Sniffer) 과 PostgreSQL (PG Sniffer) 로그를 각각 생성한다.
같은 logs/ 폴더에 저장되므로 웹 뷰어에서 DB 종류 필터로 구분 조회 가능.

실행:
    python generate_sample_logs.py
    python generate_sample_logs.py --clear    # 기존 로그 삭제 후 재생성
"""

import argparse
from datetime import datetime, timedelta, date
from pathlib import Path

from config import LOG_DIR
from query_logger import write_query_log


# ── 공통 픽스처 ────────────────────────────────────────────────────

USERS = [
    {"user_id": "U001", "user_name": "홍길동",    "user_role": "analyst"},
    {"user_id": "U002", "user_name": "김영희",    "user_role": "teller"},
    {"user_id": "U003", "user_name": "이철수",    "user_role": "auditor"},
    {"user_id": "U004", "user_name": "박민준",    "user_role": "analyst"},
    {"user_id": "U005", "user_name": "최수진",    "user_role": "teller"},
    {"user_id": "U006", "user_name": "정다은",    "user_role": "admin"},
    {"user_id": "BATCH","user_name": "배치시스템", "user_role": "system"},
]

CUSTOMERS = [
    {"id":1, "name":"홍길동","ssn":"800101-1234567","phone":"010-1234-5678",
     "card":"1234-5678-9012-3456","account":"110-123-456789","email":"hong@finance.co.kr","credit_score":850},
    {"id":2, "name":"김영희","ssn":"900215-2345678","phone":"010-2345-6789",
     "card":"2345-6789-0123-4567","account":"110-234-567890","email":"kim@finance.co.kr", "credit_score":720},
    {"id":3, "name":"이철수","ssn":"751130-1456789","phone":"010-3456-7890",
     "card":"3456-7890-1234-5678","account":"110-345-678901","email":"lee@finance.co.kr", "credit_score":910},
    {"id":4, "name":"박민준","ssn":"851020-1567890","phone":"010-4567-8901",
     "card":"4567-8901-2345-6789","account":"110-456-789012","email":"park@finance.co.kr","credit_score":680},
    {"id":5, "name":"최수진","ssn":"920308-2678901","phone":"010-5678-9012",
     "card":"5678-9012-3456-7890","account":"110-567-890123","email":"choi@finance.co.kr","credit_score":760},
]

ACCOUNTS = [
    {"account_no":"110-123-456789","customer_id":1,"balance":15_000_000,"type":"입출금"},
    {"account_no":"110-234-567890","customer_id":2,"balance": 8_500_000,"type":"입출금"},
    {"account_no":"110-345-678901","customer_id":3,"balance":32_000_000,"type":"정기예금"},
    {"account_no":"110-456-789012","customer_id":4,"balance": 3_200_000,"type":"입출금"},
    {"account_no":"110-567-890123","customer_id":5,"balance":12_800_000,"type":"입출금"},
    {"account_no":"110-678-901234","customer_id":1,"balance":50_000_000,"type":"정기예금"},
]


def _log(base, offset_sec, duration_ms, user, sql, params,
         exec_method, db_server, db_name, db_schema,
         purpose, ref, status, result_data=None, affected=0,
         client_ip="192.168.1.50", hostname="appserver01", error=None):
    st = base + timedelta(seconds=offset_sec)
    et = st + timedelta(milliseconds=duration_ms)
    write_query_log(
        user_id=user["user_id"], user_name=user["user_name"], user_role=user["user_role"],
        client_ip=client_ip, hostname=hostname,
        db_server=db_server, db_name=db_name, db_schema=db_schema,
        sql=sql, parameters=params,
        execution_method=exec_method,
        purpose=purpose, reference_no=ref,
        start_time=st, end_time=et,
        status=status,
        affected_rows=affected,
        result_data=result_data,
        error_message=error,
    )


# ══════════════════════════════════════════════════════════════════
# Oracle 샘플 로그 (execution_method = "TNS Sniffer")
# Oracle 문법: :1 바인드 변수, ROWNUM, ORA-XXXXX 오류
# ══════════════════════════════════════════════════════════════════

def _generate_oracle_day(base_date: date) -> int:
    B  = datetime(base_date.year, base_date.month, base_date.day, 9, 0, 0)
    U  = USERS
    DB = dict(exec_method="TNS Sniffer",
              db_server="192.168.1.10", db_name="ORCL", db_schema="FINSCHEMA")

    # 09:02 — 신용 우량 고객 조회 (개인정보 포함)
    _log(B, 120, 45, U[0],
         "SELECT id, name, ssn, phone, credit_score FROM customers WHERE credit_score >= :1",
         [700], **DB, purpose="고객 신용평가 심사", ref="CREDIT-2026-001",
         status="SUCCESS", client_ip="192.168.1.51",
         result_data=[{"id":c["id"],"name":c["name"],"ssn":c["ssn"],
                       "phone":c["phone"],"credit_score":c["credit_score"]}
                      for c in CUSTOMERS if c["credit_score"] >= 700])

    # 09:05 — 창구 계좌 조회 (JOIN)
    _log(B, 300, 22, U[1],
         "SELECT c.name, c.phone, a.account_no, a.balance, a.type FROM customers c JOIN accounts a ON a.customer_id = c.id WHERE c.id = :1",
         [1], **DB, purpose="창구 고객 계좌 확인", ref="TELLER-2026-042",
         status="SUCCESS", client_ip="192.168.1.52",
         result_data=[{"name":"홍길동","phone":"010-1234-5678",
                       "account_no":"110-123-456789","balance":15_000_000,"type":"입출금"},
                      {"name":"홍길동","phone":"010-1234-5678",
                       "account_no":"110-678-901234","balance":50_000_000,"type":"정기예금"}])

    # 09:30 — 고객 연락처 수정
    _log(B, 1800, 18, U[0],
         "UPDATE customers SET phone = :1, email = :2 WHERE id = :3",
         ["010-9999-0000","new@finance.co.kr",3],
         **DB, purpose="고객 정보 정정 처리", ref="UPDATE-2026-007",
         status="SUCCESS", affected=1)

    # 09:45 — 신규 계좌 개설
    _log(B, 2700, 35, U[1],
         "INSERT INTO accounts (account_no, customer_id, balance, type) VALUES (:1, :2, :3, :4)",
         ["110-999-000001",4,100_000,"입출금"],
         **DB, purpose="신규 계좌 개설", ref="ACCT-2026-088",
         status="SUCCESS", affected=1, client_ip="192.168.1.52")

    # 10:00 — 전체 고객 민감정보 조회 (카드번호·주민번호·이메일)
    _log(B, 3600, 88, U[3],
         "SELECT id, name, ssn, card, account, email FROM customers WHERE status = :1",
         ["ACTIVE"], **DB, purpose="신용한도 심사", ref="LIMIT-2026-088",
         status="SUCCESS", client_ip="192.168.1.53",
         result_data=[{"id":c["id"],"name":c["name"],"ssn":c["ssn"],
                       "card":c["card"],"account":c["account"],"email":c["email"]}
                      for c in CUSTOMERS])

    # 11:00 — 없는 테이블 조회 (실패)
    _log(B, 7200, 8, U[1],
         "SELECT * FROM nonexistent_table WHERE id = :1",
         [1], **DB, purpose="", ref="",
         status="FAILURE", client_ip="192.168.1.52",
         error="ORA-00942: table or view does not exist")

    # 11:10 — 권한 없는 테이블 접근 (실패)
    _log(B, 7800, 5, U[4],
         "SELECT * FROM dba_users",
         None, **DB, purpose="", ref="",
         status="FAILURE", client_ip="192.168.1.51",
         error="ORA-01031: insufficient privileges")

    # 12:00 — 배치: 일일 잔액 요약
    _log(B, 10800, 312, U[6],
         "SELECT a.account_no, c.name, c.phone, a.balance FROM accounts a JOIN customers c ON c.id = a.customer_id ORDER BY a.balance DESC",
         None, **DB, purpose="일일 잔액 현황 배치", ref="BATCH-2026-0426",
         status="SUCCESS", client_ip="192.168.1.100", hostname="batchserver01",
         result_data=[{"account_no":a["account_no"],
                       "name":next(c["name"] for c in CUSTOMERS if c["id"]==a["customer_id"]),
                       "phone":next(c["phone"] for c in CUSTOMERS if c["id"]==a["customer_id"]),
                       "balance":a["balance"]}
                      for a in sorted(ACCOUNTS, key=lambda x: -x["balance"])])

    # 14:00 — 대출 심사 (주민번호·신용점수)
    _log(B, 18000, 67, U[0],
         "SELECT c.name, c.ssn, c.phone, c.credit_score, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.id WHERE c.id = :1",
         [2], **DB, purpose="주택담보대출 심사", ref="LOAN-2026-0312",
         status="SUCCESS",
         result_data=[{"name":"김영희","ssn":"900215-2345678","phone":"010-2345-6789",
                       "credit_score":720,"balance":8_500_000}])

    # 15:00 — 프로시저 호출
    _log(B, 21600, 220, U[2],
         "CALL generate_monthly_report(:1, :2)",
         [base_date.strftime("%Y%m"),"AML"],
         **DB, purpose="월간 AML 보고서 생성", ref="RPT-2026-04",
         status="SUCCESS", client_ip="192.168.1.52")

    # 15:30 — 정기예금 고객 이메일 조회
    _log(B, 23400, 33, U[4],
         "SELECT c.name, c.email, c.phone, a.account_no FROM customers c JOIN accounts a ON a.customer_id = c.id WHERE a.type = :1",
         ["정기예금"], **DB, purpose="정기예금 만기 안내", ref="NOTICE-2026-088",
         status="SUCCESS", client_ip="192.168.1.51",
         result_data=[{"name":"이철수","email":"lee@finance.co.kr",
                       "phone":"010-3456-7890","account_no":"110-345-678901"},
                      {"name":"홍길동","email":"hong@finance.co.kr",
                       "phone":"010-1234-5678","account_no":"110-678-901234"}])

    # 17:00 — 배치: 신용점수 갱신
    _log(B, 28800, 1850, U[6],
         "UPDATE customers SET credit_score = credit_score + :1 WHERE id IN (SELECT customer_id FROM accounts WHERE balance >= :2)",
         [5, 10_000_000],
         **DB, purpose="신용점수 자동 갱신", ref="BATCH-CREDIT-2026",
         status="SUCCESS", affected=2, client_ip="192.168.1.100", hostname="batchserver01")

    # 17:30 — TRUNCATE 시도 (실패)
    _log(B, 30600, 6, U[4],
         "TRUNCATE TABLE customers",
         None, **DB, purpose="", ref="",
         status="FAILURE", client_ip="192.168.1.55",
         error="ORA-01031: insufficient privileges")

    cnt = 13
    print(f"  Oracle  {base_date}: {cnt}건")
    return cnt


# ══════════════════════════════════════════════════════════════════
# PostgreSQL 샘플 로그 (execution_method = "PG Sniffer")
# PostgreSQL 문법: $1 바인드 변수, LIMIT/OFFSET, RETURNING, 오류 코드
# ══════════════════════════════════════════════════════════════════

def _generate_pg_day(base_date: date) -> int:
    B  = datetime(base_date.year, base_date.month, base_date.day, 9, 30, 0)
    U  = USERS
    DB = dict(exec_method="PG Sniffer",
              db_server="192.168.1.20", db_name="financedb", db_schema="public")

    # 09:32 — 고객 목록 조회 (이메일·전화번호)
    _log(B, 120, 38, U[0],
         "SELECT id, name, email, phone FROM customers WHERE credit_score >= $1 ORDER BY credit_score DESC LIMIT $2",
         [700, 100], **DB, purpose="우량 고객 마케팅 대상 추출", ref="MKT-2026-011",
         status="SUCCESS", client_ip="192.168.1.61",
         result_data=[{"id":c["id"],"name":c["name"],"email":c["email"],"phone":c["phone"]}
                      for c in CUSTOMERS if c["credit_score"] >= 700])

    # 09:45 — 계좌 잔액 집계
    _log(B, 900, 15, U[1],
         "SELECT account_type, COUNT(*) AS cnt, SUM(balance) AS total FROM accounts GROUP BY account_type ORDER BY total DESC",
         None, **DB, purpose="잔액 현황 집계", ref="RPT-PG-2026-001",
         status="SUCCESS", client_ip="192.168.1.62",
         result_data=[{"account_type":"정기예금","cnt":2,"total":82_000_000},
                      {"account_type":"입출금",  "cnt":4,"total":39_500_000}])

    # 10:00 — 고객 정보 UPDATE (RETURNING 절)
    _log(B, 1800, 12, U[0],
         "UPDATE customers SET phone = $1 WHERE id = $2 RETURNING id, name, phone",
         ["010-7777-8888", 2],
         **DB, purpose="고객 연락처 변경", ref="UPDATE-PG-2026-003",
         status="SUCCESS", affected=1, client_ip="192.168.1.61",
         result_data=[{"id":2,"name":"김영희","phone":"010-7777-8888"}])

    # 10:15 — 신규 고객 INSERT
    _log(B, 2700, 9, U[1],
         "INSERT INTO customers (name, ssn, phone, email, credit_score) VALUES ($1, $2, $3, $4, $5) RETURNING id",
         ["신규고객","950101-1999999","010-0000-1111","new@finance.co.kr",650],
         **DB, purpose="신규 고객 등록", ref="REG-PG-2026-088",
         status="SUCCESS", affected=1, client_ip="192.168.1.62",
         result_data=[{"id": 6}])

    # 10:30 — 주민번호 포함 대출 심사 조회
    _log(B, 3600, 55, U[3],
         "SELECT c.name, c.ssn, c.phone, c.credit_score, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.id WHERE c.id = $1",
         [3], **DB, purpose="부동산담보대출 심사", ref="LOAN-PG-2026-007",
         status="SUCCESS", client_ip="192.168.1.63",
         result_data=[{"name":"이철수","ssn":"751130-1456789","phone":"010-3456-7890",
                       "credit_score":910,"balance":32_000_000}])

    # 11:00 — 트랜잭션 내역 페이징 조회
    _log(B, 5400, 28, U[2],
         "SELECT t.id, c.name, c.phone, t.amount, t.type, t.date FROM transactions t JOIN accounts a ON a.account_no = t.account_no JOIN customers c ON c.id = a.customer_id ORDER BY t.date DESC LIMIT $1 OFFSET $2",
         [10, 0], **DB, purpose="거래 내역 감사", ref="AML-PG-2026-022",
         status="SUCCESS", client_ip="192.168.1.64",
         result_data=[{"id":107,"name":"홍길동","phone":"010-1234-5678","amount":10_000_000,"type":"입금","date":"2026-04-26"},
                      {"id":108,"name":"이철수","phone":"010-3456-7890","amount":-8_000_000,"type":"출금","date":"2026-04-26"},
                      {"id":105,"name":"최수진","phone":"010-5678-9012","amount":800_000,"type":"입금","date":"2026-04-26"}])

    # 11:30 — 없는 테이블 (실패)
    _log(B, 7200, 6, U[4],
         "SELECT * FROM pg_shadow",
         None, **DB, purpose="", ref="",
         status="FAILURE", client_ip="192.168.1.61",
         error="ERROR: permission denied for table pg_shadow")

    # 12:00 — 카드번호·이메일 조회 (배치)
    _log(B, 9000, 190, U[6],
         "SELECT name, card, email, account FROM customers WHERE credit_score < $1",
         [700], **DB, purpose="저신용 고객 정리 배치", ref="BATCH-PG-LOW",
         status="SUCCESS", client_ip="192.168.1.100", hostname="batchserver01",
         result_data=[{"name":c["name"],"card":c["card"],"email":c["email"],"account":c["account"]}
                      for c in CUSTOMERS if c["credit_score"] < 700])

    # 13:00 — 잔액 이체 UPDATE
    _log(B, 12600, 22, U[1],
         "UPDATE accounts SET balance = balance + $1 WHERE account_no = $2",
         [300_000,"110-234-567890"],
         **DB, purpose="온라인 입금 처리", ref="TXN-PG-2026-3301",
         status="SUCCESS", affected=1, client_ip="192.168.1.62")

    # 13:05 — 거래 INSERT
    _log(B, 12900, 11, U[1],
         "INSERT INTO transactions (account_no, amount, type, date) VALUES ($1, $2, $3, $4)",
         ["110-234-567890", 300_000,"입금", base_date.isoformat()],
         **DB, purpose="온라인 입금 처리", ref="TXN-PG-2026-3301",
         status="SUCCESS", affected=1, client_ip="192.168.1.62")

    # 14:00 — 정기예금 만기 고객 조회
    _log(B, 16200, 41, U[4],
         "SELECT c.name, c.email, c.phone, a.account_no, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.id WHERE a.account_type = $1 AND a.maturity_date <= $2",
         ["정기예금", base_date.isoformat()],
         **DB, purpose="정기예금 만기 안내", ref="NOTICE-PG-2026-055",
         status="SUCCESS", client_ip="192.168.1.61",
         result_data=[{"name":"이철수","email":"lee@finance.co.kr","phone":"010-3456-7890",
                       "account_no":"110-345-678901","balance":32_000_000}])

    # 15:00 — DDL: 감사 뷰 생성
    _log(B, 19800, 45, U[5],
         "CREATE VIEW v_high_balance AS SELECT c.name, c.phone, a.account_no, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.id WHERE a.balance >= 10000000",
         None, **DB, purpose="고액 계좌 감사 뷰 생성", ref="DDL-PG-2026-003",
         status="SUCCESS", client_ip="192.168.1.64")

    # 17:00 — 배치: 신용점수 일괄 갱신
    _log(B, 27000, 980, U[6],
         "UPDATE customers SET credit_score = credit_score + $1 WHERE id IN (SELECT customer_id FROM accounts WHERE balance >= $2)",
         [5, 10_000_000],
         **DB, purpose="신용점수 자동 갱신", ref="BATCH-PG-CREDIT",
         status="SUCCESS", affected=2, client_ip="192.168.1.100", hostname="batchserver01")

    cnt = 13
    print(f"  PG      {base_date}: {cnt}건")
    return cnt


# ── 메인 ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Oracle·PostgreSQL 샘플 감사 로그 생성")
    parser.add_argument("--days",  type=int, default=3, help="생성할 날짜 수 (기본: 3일)")
    parser.add_argument("--clear", action="store_true",  help="기존 로그 삭제 후 재생성")
    args = parser.parse_args()

    log_dir = Path(LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)

    if args.clear:
        removed = list(log_dir.glob("audit_query_*.jsonl"))
        for f in removed: f.unlink()
        print(f"기존 로그 {len(removed)}개 삭제\n")

    today = date(2026, 4, 26)
    dates = [today - timedelta(days=i) for i in range(args.days - 1, -1, -1)]

    print(f"샘플 로그 생성 중 ({args.days}일치) ...\n")
    total = 0
    for d in dates:
        total += _generate_oracle_day(d)
        total += _generate_pg_day(d)

    files = sorted(log_dir.glob("audit_query_*.jsonl"))
    print(f"\n완료: Oracle + PostgreSQL 합계 {total}건")
    print(f"파일: {[f.name for f in files]}")
    print("\n웹 조회: python log_viewer_web.py  →  http://localhost:8888")


if __name__ == "__main__":
    main()
