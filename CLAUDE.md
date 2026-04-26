# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 프로젝트 개요

폐쇄망 금융 애플리케이션용 **쿼리 감사 로그 시스템**. DB 쿼리를 실행할 때마다 6하원칙(누가/언제/어디서/무엇을/어떻게/왜)에 따라 자동으로 로그를 기록하고, CLI/웹으로 조회한다. 외부 라이브러리 없이 Python 표준 라이브러리만 사용한다.

## 실행 명령

```bash
# 데모 DB 초기화 (최초 1회)
python demo_setup.py

# 데모 쿼리 수행 + 로그 생성
python demo_run.py

# 웹 조회 서버 (http://localhost:8888)
python log_viewer_web.py
python log_viewer_web.py --host 0.0.0.0 --port 9000   # 원격 접속

# CLI 조회
python log_viewer.py                          # 대화형 메뉴
python log_viewer.py --date 20260425          # 날짜 지정
python log_viewer.py --op 조회 --pi --detail  # 복합 필터
python log_viewer.py --verify                 # 무결성 검증
python log_viewer.py --export out.csv         # CSV 내보내기
```

## 모듈 의존 관계

```
config.py
    └── query_logger.py          ← 로그 기록·읽기·필터·검증 핵심
            ├── db_connector.py  ← AuditedDB 래퍼 (쿼리 실행 + 자동 로그)
            ├── log_viewer.py    ← CLI 뷰어
            └── log_viewer_web.py ← 웹 뷰어 (http.server 기반)
```

`query_logger.py`가 **유일한 공유 모듈**이다. 뷰어 둘 다 여기서 `iter_logs`, `filter_logs`, `verify_entry`, `mask_personal_info`, `PI_TYPE_NAMES`를 import한다.

## 로그 JSON 스키마

로그 파일: `logs/audit_query_YYYYMMDD.jsonl` (JSON Lines, UTF-8, 일별 로테이션, 200 MB 초과 시 `_001` 분할)

```jsonc
{
  "log_id": "<uuid4>",
  "when":   { "start_time": "<ISO8601μs>", "end_time": "<ISO8601μs>", "duration_ms": 0 },
  "who":    { "user_id": "", "user_name": "", "user_role": "" },
  "where":  { "client_ip": "", "hostname": "", "db_server": "", "db_name": "", "db_schema": "" },
  "what":   {
    "query_type": "SELECT",          // SQL 키워드
    "operation_type": "조회",        // 한글 업무유형 (OPERATION_TYPE_MAP으로 자동 매핑)
    "sql": "",
    "parameters": null,
    "row_count": 4,                  // SELECT → 조회 건수, DML → affected_rows
    "affected_rows": 0
  },
  "how":    { "execution_method": "", "application": "FinanceApp v1.0.0", "session_id": "" },
  "why":    { "purpose": "", "reference_no": "" },  // purpose 미입력 시 operation_type으로 자동 채움
  "result": {
    "status": "SUCCESS",             // "SUCCESS" | "FAILURE"
    "error_message": null,
    "has_personal_info": true,
    "personal_info_counts": {        // 5개 유형별 패턴 매치 건수 (PI_TYPE_NAMES 순서)
      "주민등록번호": 0, "카드번호": 0, "계좌번호": 0, "전화번호": 0, "이메일": 0
    },
    "result_count": 4,
    "result_data": [...]
  },
  "integrity_hash": "<sha256>"       // log_id + start_time + sql + status
}
```

## 핵심 설계 패턴

**AuditedDB 래퍼 패턴**: 애플리케이션은 `sqlite3.connect()` 대신 `AuditedDB(user_id=..., purpose=...)`를 사용한다. `execute(sql, params)` 호출 시 실행 전후 시각을 측정하고 `write_query_log()`를 자동 호출한다. 애플리케이션 코드에 로그 코드를 직접 삽입하지 않는다.

**개인정보 이중 렌더링**: 웹 뷰어는 서버에서 마스킹/원문 양쪽을 `<span class="pi-mask">` / `<span class="pi-raw" style="display:none">` 쌍으로 렌더링한다. 헤더 체크박스(`#globalMaskChk`)의 `onchange`가 `applyMask(bool)`을 호출해 JS로만 토글한다. 서버 재요청 없이 즉시 전환된다.

**개인정보 패턴 확장**: `_PI_PATTERN_DEFS` 리스트에 `(한글유형명, re.compile(...), lambda m: ...)` 튜플을 추가하면 마스킹·카운팅·CSV 컬럼이 자동으로 확장된다. `PI_TYPE_NAMES`는 이 리스트에서 자동 생성된다.

**무결성 해시**: `sha256(log_id + start_time + sql + status)`. `verify_entry(entry: dict) -> bool`로 검증. 로그 파일을 수동으로 편집하면 검증 실패한다.

## 운영 환경 교체 포인트

| 항목 | 현재 (데모) | 운영 교체 대상 |
|------|------------|--------------|
| DB 드라이버 | `sqlite3` | `cx_Oracle`, `pyodbc` 등 |
| DB 연결 정보 | `config.py`의 `DEMO_DB_PATH`, `DB_SERVER`, `DB_NAME` | 실제 서버 정보 |
| 로그 저장 경로 | `logs/` (앱과 동일 디렉토리) | 별도 파티션 또는 NAS 경로 |

`db_connector.py`의 `sqlite3.connect()` 부분만 교체하면 나머지 로직은 그대로 동작한다.

## 웹 뷰어 라우트

`log_viewer_web.py`의 `LogViewerHandler.do_GET`이 모든 라우팅을 처리한다.

| 경로 | 함수 | 설명 |
|------|------|------|
| `/` 또는 `/search` | `_render_search(params)` | 검색 폼 + 결과 목록 |
| `/detail?id=&from_dt=&to_dt=` | `_render_detail(...)` | 6하원칙 상세 + 결과 데이터 |
| `/verify?from_dt=&to_dt=` | `_render_verify(params)` | 무결성 일괄 검증 |
| `/export?...` | `_build_csv(params)` | CSV 파일 다운로드 (BOM 포함) |

새 라우트 추가 시 `do_GET`의 `if/elif` 블록에 분기를 추가하고 `_render_*` 함수를 작성한다. HTML은 `_header()` + 본문 + `_footer()`로 조립하며, `_masked_html(value)` 헬퍼로 개인정보 토글 셀을 생성한다.
