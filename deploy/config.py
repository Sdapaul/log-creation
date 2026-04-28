"""
쿼리 감사 로그 시스템 - 설정 파일
"""
from pathlib import Path

BASE_DIR = Path(__file__).parent
LOG_DIR  = BASE_DIR / "logs"
DB_DIR   = BASE_DIR / "db"

LOG_DIR.mkdir(exist_ok=True)
DB_DIR.mkdir(exist_ok=True)

# 로그 파일 설정
LOG_FILE_PREFIX  = "audit_query"
LOG_ENCODING     = "utf-8"
LOG_DATE_FORMAT  = "%Y%m%d"          # 하루 1파일 로테이션
LOG_MAX_SIZE_MB  = 200               # 파일당 최대 크기 (초과시 _001, _002 … 분할)

# 애플리케이션 정보
APP_NAME    = "FinanceApp"
APP_VERSION = "1.0.0"

# 데모용 SQLite DB 경로 (운영 환경에서는 실제 DB 연결 정보로 교체)
DEMO_DB_PATH = str(DB_DIR / "finance_demo.db")

# ── Oracle 연결 정보 (oracle_proxy.py 기본값) ───────────────────────────
DB_SERVER    = "localhost"
DB_NAME      = "finance_db"
DB_SCHEMA    = "dbo"

# ── PostgreSQL 연결 정보 (Superset ↔ Azure RedHat 9.7) ─────────────────
PG_HOST      = "localhost"           # 실제 PostgreSQL 서버 호스트
PG_PORT      = 5432                  # PostgreSQL 리스너 포트
PG_DB        = "postgres"            # 기본 데이터베이스 이름
PG_SCHEMA    = "public"              # 기본 스키마

# 개인정보 마스킹 설정 (로그 뷰어 표시용)
MASK_PERSONAL_INFO = True            # True: 뷰어 출력 시 마스킹, False: 원문
MASK_CHAR         = "*"
