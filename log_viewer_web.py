"""
쿼리 감사 로그 웹 조회 프로그램

외부 라이브러리 불필요 — Python 표준 라이브러리만 사용 (폐쇄망 적합)

실행)
    python log_viewer_web.py              # 기본 포트 8888
    python log_viewer_web.py --port 9000  # 포트 지정
    python log_viewer_web.py --host 0.0.0.0  # 원격 접속 허용

접속)  http://localhost:8888
"""

import json
import csv
import io
import sys
import html
import argparse
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, str(Path(__file__).parent))
from query_logger import (
    iter_logs, filter_logs, verify_entry,
    mask_personal_info, PI_TYPE_NAMES, OPERATION_TYPE_MAP,
)

PAGE_SIZE = 25

OP_CSS = {
    "조회": "badge-blue", "생성": "badge-green",
    "변경": "badge-orange", "삭제": "badge-red",
}


# ── 공통 헬퍼 ────────────────────────────────

def _today() -> date:
    return date.today()

def _parse_date(s: str) -> date:
    return datetime.strptime(s.strip(), "%Y%m%d").date()

def _q(params: dict, key: str, default: str = "") -> str:
    vals = params.get(key, [])
    return vals[0].strip() if vals else default

def _esc(text) -> str:
    return html.escape(str(text) if text is not None else "")

def _build_qs(params: dict) -> str:
    flat = {k: v[0] for k, v in params.items() if v and v[0]}
    flat.pop("page", None)
    return urlencode(flat)

def _masked_html(value) -> str:
    """값에 개인정보 패턴이 있으면 마스킹/원문 토글 가능한 HTML span 쌍을 반환한다."""
    raw    = str(value) if value is not None else ""
    masked = mask_personal_info(raw)
    if raw == masked:
        return _esc(raw)
    return (f'<span class="pi-mask">{_esc(masked)}</span>'
            f'<span class="pi-raw" style="display:none">{_esc(raw)}</span>')

def _sql_preview_html(sql: str, max_len: int = 90) -> str:
    s = " ".join(sql.split())
    trunc = s[:max_len] + "…" if len(s) > max_len else s
    return _masked_html(trunc)


# ── 공통 CSS ─────────────────────────────────

_CSS = """
:root{--primary:#1a3a5c;--primary-h:#16304f;--success:#276749;--success-bg:#d4edda;
      --danger:#721c24;--danger-bg:#f8d7da;--warn:#856404;--warn-bg:#fff3cd;
      --info:#004085;--info-bg:#cce5ff;--border:#dee2e6;--text:#212529;
      --muted:#6c757d;--bg:#f8f9fa;--white:#fff;--shadow:0 1px 4px rgba(0,0,0,.12);}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Malgun Gothic','Apple SD Gothic Neo',sans-serif;font-size:14px;
     background:var(--bg);color:var(--text);}
a{color:var(--primary);text-decoration:none;}a:hover{text-decoration:underline;}

/* header */
header{background:var(--primary);color:#fff;padding:12px 24px;display:flex;
       align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;}
header h1{font-size:17px;font-weight:700;letter-spacing:.5px;}
header nav{display:flex;align-items:center;gap:16px;flex-wrap:wrap;}
header nav a{color:#aac4e0;font-size:13px;}
header nav a:hover{color:#fff;text-decoration:none;}

/* 마스킹 토글 (헤더 내) */
.mask-toggle-wrap{display:flex;align-items:center;gap:6px;
  background:rgba(255,255,255,.12);border-radius:20px;padding:5px 12px;cursor:pointer;}
.mask-toggle-wrap input[type=checkbox]{width:16px;height:16px;cursor:pointer;accent-color:#fff;}
.mask-toggle-wrap label{color:#fff;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;}
.mask-status{font-size:11px;color:#ffd700;font-weight:700;margin-left:2px;}

/* layout */
.container{max-width:1400px;margin:0 auto;padding:20px 16px;}

/* card */
.card{background:var(--white);border:1px solid var(--border);border-radius:6px;
      box-shadow:var(--shadow);margin-bottom:18px;}
.card-header{background:#f1f3f5;padding:10px 16px;font-weight:700;font-size:13px;
             border-bottom:1px solid var(--border);border-radius:6px 6px 0 0;
             display:flex;align-items:center;justify-content:space-between;}
.card-body{padding:14px 16px;}

/* search form */
.search-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));
             gap:10px 16px;align-items:end;}
.form-group{display:flex;flex-direction:column;gap:4px;}
.form-group label{font-size:12px;color:var(--muted);font-weight:600;}
.form-group input,.form-group select{border:1px solid var(--border);border-radius:4px;
             padding:6px 10px;font-size:13px;width:100%;}
.btn{padding:7px 18px;border:none;border-radius:4px;cursor:pointer;font-size:13px;font-weight:600;}
.btn-primary{background:var(--primary);color:#fff;}
.btn-primary:hover{background:var(--primary-h);}
.btn-success{background:#28a745;color:#fff;}btn-success:hover{background:#218838;}
.btn-warning{background:#ffc107;color:#212529;}
.btn-danger{background:#dc3545;color:#fff;}
.btn-secondary{background:#6c757d;color:#fff;}
.btn-sm{padding:4px 10px;font-size:12px;}
.btn-row{display:flex;gap:8px;margin-top:4px;flex-wrap:wrap;}

/* stats bar */
.stats-bar{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;}
.stat-box{background:var(--white);border:1px solid var(--border);border-radius:6px;
          padding:10px 18px;text-align:center;min-width:110px;box-shadow:var(--shadow);}
.stat-box .num{font-size:24px;font-weight:700;}
.stat-box .lbl{font-size:11px;color:var(--muted);margin-top:2px;}
.num-total{color:var(--primary);}
.num-ok{color:var(--success);}
.num-fail{color:var(--danger);}
.num-pi{color:#856404;}

/* table */
.tbl-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{background:#f1f3f5;border-bottom:2px solid var(--border);padding:8px 10px;
   text-align:left;white-space:nowrap;font-size:12px;}
td{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;}
tr:hover td{background:#f5f8ff;}
.sql-cell{font-family:Consolas,'Courier New',monospace;font-size:12px;
          color:#1a3a5c;word-break:break-all;}
.num-cell{text-align:right;font-weight:600;}

/* badges */
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;}
.badge-blue{background:#cce5ff;color:#004085;}
.badge-green{background:#d4edda;color:#155724;}
.badge-orange{background:#fff3cd;color:#856404;}
.badge-red{background:#f8d7da;color:#721c24;}
.badge-gray{background:#e2e3e5;color:#383d41;}
.badge-success{background:var(--success-bg);color:var(--success);}
.badge-failure{background:var(--danger-bg);color:var(--danger);}
.badge-pi{background:#fff3cd;color:#856404;}

/* pagination */
.pagination{display:flex;gap:4px;justify-content:center;padding:12px 0;}
.pagination a,.pagination span{display:inline-block;padding:5px 12px;
     border:1px solid var(--border);border-radius:4px;font-size:13px;}
.pagination a:hover{background:#e9ecef;text-decoration:none;}
.pagination .active{background:var(--primary);color:#fff;border-color:var(--primary);}

/* detail page */
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:0;}
.detail-cell{padding:12px 16px;border:1px solid var(--border);}
.detail-cell:nth-child(odd){border-right:none;}
.detail-cell:nth-child(n+3){border-top:none;}
.principle-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;
                 letter-spacing:.8px;margin-bottom:4px;}
.principle-title{font-size:15px;font-weight:700;color:var(--primary);margin-bottom:8px;}
.kv{display:flex;gap:8px;margin-bottom:4px;font-size:13px;}
.kv .k{color:var(--muted);min-width:80px;flex-shrink:0;font-size:12px;}
.kv .v{word-break:break-all;}
pre.sql-block{background:#f8f9fa;border:1px solid var(--border);border-radius:4px;
             padding:12px;font-family:Consolas,'Courier New',monospace;font-size:12px;
             overflow-x:auto;white-space:pre-wrap;word-break:break-all;line-height:1.6;}

/* 결과 데이터 테이블 */
.result-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px;}
.result-table th{background:#f1f3f5;padding:6px 8px;border:1px solid var(--border);
                 white-space:nowrap;}
.result-table td{padding:5px 8px;border:1px solid var(--border);word-break:break-all;}

/* 개인정보 항목별 건수 표 */
.pi-counts-grid{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px;}
.pi-count-item{background:var(--warn-bg);border:1px solid #ffc107;border-radius:4px;
               padding:5px 12px;font-size:12px;font-weight:600;color:var(--warn);}
.pi-count-item.zero{background:#f8f9fa;border-color:var(--border);color:var(--muted);
                    font-weight:400;}

/* 마스킹 표시 */
.pi-mask{color:#721c24;background:#f8d7da;border-radius:2px;padding:0 2px;}
.pi-raw{color:#155724;background:#d4edda;border-radius:2px;padding:0 2px;}
.unmasked-banner{background:#dc3545;color:#fff;padding:6px 14px;border-radius:4px;
                 font-size:12px;font-weight:700;display:none;margin-left:8px;}

/* integrity */
.integrity-ok{color:var(--success);font-weight:700;}
.integrity-fail{color:var(--danger);font-weight:700;}

/* verify */
.verify-item{padding:6px 10px;border-radius:4px;margin-bottom:4px;font-size:13px;}
.verify-ok{background:var(--success-bg);color:var(--success);}
.verify-fail{background:var(--danger-bg);color:var(--danger);}
.alert{padding:12px 16px;border-radius:4px;margin-bottom:12px;font-size:14px;}
.alert-success{background:var(--success-bg);color:var(--success);}
.alert-danger{background:var(--danger-bg);color:var(--danger);}

@media(max-width:700px){
  .detail-grid{grid-template-columns:1fr;}
  .detail-cell:nth-child(odd){border-right:1px solid var(--border);}
  .detail-cell:nth-child(n+3){border-top:none;}
}
"""

# ── 공통 JavaScript (전역 마스킹 제어) ──────

_JS_GLOBAL = """
<script>
// 페이지 로드 시 헤더 체크박스 상태에 맞게 마스킹 적용
document.addEventListener('DOMContentLoaded', function(){
  var chk = document.getElementById('globalMaskChk');
  if(chk){ applyMask(chk.checked); }
});

function applyMask(on){
  // pi-mask 요소: 마스킹 ON일 때 표시
  document.querySelectorAll('.pi-mask').forEach(function(el){
    el.style.display = on ? '' : 'none';
  });
  // pi-raw 요소: 마스킹 OFF일 때 표시
  document.querySelectorAll('.pi-raw').forEach(function(el){
    el.style.display = on ? 'none' : '';
  });
  // 마스킹 해제 경고 배너
  document.querySelectorAll('.unmasked-banner').forEach(function(el){
    el.style.display = on ? 'none' : 'inline-block';
  });
  // 헤더 상태 텍스트
  var st = document.getElementById('maskStatusText');
  if(st){ st.textContent = on ? '🔒 ON' : '🔓 OFF'; }
}

function onMaskChange(chk){
  if(!chk.checked){
    if(!confirm('개인정보 마스킹을 해제하면 주민등록번호, 계좌번호 등 민감정보가 원문으로 표시됩니다.\\n계속하시겠습니까?')){
      chk.checked = true;  // 취소 시 복원
      return;
    }
  }
  applyMask(chk.checked);
}
</script>
"""


# ── 공통 헤더/푸터 ───────────────────────────

def _header() -> str:
    return f"""<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>쿼리 감사 로그 조회 시스템</title>
<style>{_CSS}</style>
</head><body>
<header>
  <h1>🔍 쿼리 감사 로그 조회 시스템</h1>
  <nav>
    <a href="/">홈</a>
    <a href="/search">로그 조회</a>
    <a href="/verify">무결성 검증</a>
    <div class="mask-toggle-wrap">
      <input type="checkbox" id="globalMaskChk" checked onchange="onMaskChange(this)">
      <label for="globalMaskChk">개인정보 마스킹</label>
      <span class="mask-status" id="maskStatusText">🔒 ON</span>
    </div>
    <span class="unmasked-banner" id="unmaskedBanner">⚠ 원문 표시 중</span>
  </nav>
</header>
<div class="container">
{_JS_GLOBAL}"""

def _footer() -> str:
    return "</div></body></html>"

def _op_badge(op: str) -> str:
    css = OP_CSS.get(op, "badge-gray")
    return f'<span class="badge {css}">{_esc(op)}</span>'

def _status_badge(status: str) -> str:
    label = "성공" if status == "SUCCESS" else "실패"
    css   = "badge-success" if status == "SUCCESS" else "badge-failure"
    return f'<span class="badge {css}">{label}</span>'

def _pi_badge(has_pi: bool) -> str:
    return '<span class="badge badge-pi">개인정보</span>' if has_pi else ""


# ── 검색 폼 ──────────────────────────────────

def _search_form(params: dict) -> str:
    today    = _today().strftime("%Y-%m-%d")
    fr_val   = _q(params, "from_dt", today)
    to_val   = _q(params, "to_dt",   today)
    user_val = _esc(_q(params, "user_id"))
    op_val   = _q(params, "op_type")
    st_val   = _q(params, "status")
    pi_val   = _q(params, "has_pi")
    kw_val   = _esc(_q(params, "keyword"))

    def _sel(opts: list[tuple[str,str]], cur: str) -> str:
        return "".join(
            f'<option value="{v}" {"selected" if cur==v else ""}>{l}</option>'
            for v, l in opts
        )

    op_opts = _sel([("","전체"),("조회","조회"),("생성","생성"),("변경","변경"),("삭제","삭제")], op_val)
    st_opts = _sel([("","전체"),("SUCCESS","성공"),("FAILURE","실패")], st_val)
    pi_opts = _sel([("","전체"),("1","포함"),("0","미포함")], pi_val)

    return f"""
<div class="card">
  <div class="card-header">조회 조건</div>
  <div class="card-body">
  <form method="GET" action="/search">
    <div class="search-grid">
      <div class="form-group">
        <label>시작일</label>
        <input type="date" name="from_dt" value="{fr_val}">
      </div>
      <div class="form-group">
        <label>종료일</label>
        <input type="date" name="to_dt" value="{to_val}">
      </div>
      <div class="form-group">
        <label>사용자 ID</label>
        <input type="text" name="user_id" value="{user_val}" placeholder="예) U001">
      </div>
      <div class="form-group">
        <label>수행 업무</label>
        <select name="op_type">{op_opts}</select>
      </div>
      <div class="form-group">
        <label>처리 상태</label>
        <select name="status">{st_opts}</select>
      </div>
      <div class="form-group">
        <label>개인정보 포함</label>
        <select name="has_pi">{pi_opts}</select>
      </div>
      <div class="form-group">
        <label>키워드</label>
        <input type="text" name="keyword" value="{kw_val}" placeholder="SQL, 사용자명 등">
      </div>
      <div class="form-group" style="justify-content:flex-end;">
        <label>&nbsp;</label>
        <div class="btn-row">
          <button class="btn btn-primary" type="submit">🔍 조회</button>
          <a class="btn btn-success" href="/export?{_build_qs(params)}">📥 CSV</a>
          <a class="btn btn-warning" href="/verify?from_dt={fr_val}&to_dt={to_val}">🔐 무결성</a>
        </div>
      </div>
    </div>
  </form>
  </div>
</div>"""


# ── 검색 결과 페이지 ─────────────────────────

def _render_search(params: dict) -> str:
    today  = _today()
    fr_str = _q(params, "from_dt", today.strftime("%Y-%m-%d"))
    to_str = _q(params, "to_dt",   today.strftime("%Y-%m-%d"))
    try:
        fr = _parse_date(fr_str.replace("-", ""))
        to = _parse_date(to_str.replace("-", ""))
    except ValueError:
        fr = to = today

    user_id    = _q(params, "user_id") or None
    op_type    = _q(params, "op_type") or None
    status     = _q(params, "status")  or None
    keyword    = _q(params, "keyword") or None
    pi_val     = _q(params, "has_pi")
    has_pi     = (True if pi_val == "1" else (False if pi_val == "0" else None))

    all_entries = list(filter_logs(
        iter_logs(fr, to),
        user_id=user_id, status=status,
        operation_type=op_type, keyword=keyword, has_pi=has_pi,
    ))

    total   = len(all_entries)
    success = sum(1 for e in all_entries if e["result"]["status"] == "SUCCESS")
    failure = total - success
    pi_cnt  = sum(1 for e in all_entries if e["result"]["has_personal_info"])
    total_rows = sum(e["what"].get("row_count", 0) for e in all_entries)

    page  = max(1, int(_q(params, "page", "1") or "1"))
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page  = min(page, pages)
    chunk = all_entries[(page-1)*PAGE_SIZE : page*PAGE_SIZE]

    out = [_header(), _search_form(params)]

    # 통계 박스
    out.append(f"""
<div class="stats-bar">
  <div class="stat-box"><div class="num num-total">{total}</div><div class="lbl">전체 쿼리</div></div>
  <div class="stat-box"><div class="num num-ok">{success}</div><div class="lbl">성공</div></div>
  <div class="stat-box"><div class="num num-fail">{failure}</div><div class="lbl">실패</div></div>
  <div class="stat-box"><div class="num num-pi">{pi_cnt}</div><div class="lbl">개인정보 포함</div></div>
  <div class="stat-box"><div class="num" style="color:#5a4fcf">{total_rows:,}</div><div class="lbl">총 결과 건수</div></div>
</div>""")

    if not chunk:
        out.append('<div class="card"><div class="card-body" style="color:var(--muted)">조회 결과가 없습니다.</div></div>')
    else:
        qs_no_page = _build_qs(params)
        rows = []
        for i, e in enumerate(chunk, (page-1)*PAGE_SIZE+1):
            op       = e["what"].get("operation_type", e["what"]["query_type"])
            dt       = e["when"]["start_time"][:19].replace("T", " ")
            dur      = e["when"]["duration_ms"]
            who      = f'{_esc(e["who"]["user_name"])} ({_esc(e["who"]["user_id"])})'
            purp     = _esc(e["why"].get("purpose", ""))
            ref      = _esc(e["why"].get("reference_no", ""))
            row_cnt  = e["what"].get("row_count", 0)
            ref_str  = f'<br><span style="font-size:11px;color:var(--muted)">{ref}</span>' if ref else ""
            pi_b     = _pi_badge(e["result"]["has_personal_info"])

            rows.append(f"""<tr>
  <td style="text-align:center;color:var(--muted)">{i}</td>
  <td style="white-space:nowrap">{_esc(dt)}<br><span style="font-size:11px;color:var(--muted)">{dur}ms</span></td>
  <td>{who}<br><span style="font-size:11px;color:var(--muted)">{_esc(e["who"]["user_role"])}</span></td>
  <td style="text-align:center">{_op_badge(op)}</td>
  <td class="sql-cell">{_sql_preview_html(e["what"]["sql"])}</td>
  <td>{purp}{ref_str}</td>
  <td class="num-cell" style="text-align:right">{row_cnt:,}건</td>
  <td style="text-align:center">{_status_badge(e["result"]["status"])}</td>
  <td style="text-align:center">{pi_b}</td>
  <td style="text-align:center"><a href="/detail?id={_esc(e["log_id"])}&from_dt={fr_str}&to_dt={to_str}">▶ 상세</a></td>
</tr>""")

        out.append(f"""
<div class="card">
  <div class="card-header">
    <span>조회 결과 — 총 {total}건 (페이지 {page}/{pages})</span>
  </div>
  <div class="card-body" style="padding:0">
  <div class="tbl-wrap">
  <table>
    <thead><tr>
      <th>#</th><th>일시 (언제)</th><th>사용자 (누가)</th><th>수행업무<br>(무엇을)</th>
      <th>SQL 요약</th><th>처리목적 (왜)</th><th>결과건수</th><th>상태</th><th>개인정보</th><th>상세</th>
    </tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  </div></div>
</div>""")

        # 페이지네이션
        pag = ['<div class="pagination">']
        if page > 1:
            pag.append(f'<a href="/search?{qs_no_page}&page={page-1}">‹ 이전</a>')
        for p in range(max(1, page-4), min(pages, page+4)+1):
            cls = "active" if p == page else ""
            pag.append(f'<a class="{cls}" href="/search?{qs_no_page}&page={p}">{p}</a>')
        if page < pages:
            pag.append(f'<a href="/search?{qs_no_page}&page={page+1}">다음 ›</a>')
        pag.append('</div>')
        out.append("".join(pag))

    out.append(_footer())
    return "".join(out)


# ── 개인정보 유형별 건수 HTML ─────────────────

def _pi_counts_html(pi_counts: dict) -> str:
    """개인정보 항목별 건수를 배지 형태 HTML로 렌더링한다."""
    if not pi_counts:
        return '<span style="color:var(--muted);font-size:12px">정보 없음</span>'
    items = []
    for name in PI_TYPE_NAMES:
        cnt = pi_counts.get(name, 0)
        cls = "pi-count-item" if cnt > 0 else "pi-count-item zero"
        items.append(f'<div class="{cls}">{_esc(name)}: {cnt}건</div>')
    return f'<div class="pi-counts-grid">{"".join(items)}</div>'


# ── 결과 데이터 테이블 HTML ───────────────────

def _result_data_html(result_data: list) -> str:
    """결과 데이터를 개인정보 마스킹 토글 가능한 테이블 HTML로 렌더링한다."""
    if not result_data:
        return '<span style="color:var(--muted)">결과 데이터 없음</span>'

    if not isinstance(result_data[0], dict):
        return f'<pre>{_esc(json.dumps(result_data, ensure_ascii=False, indent=2))}</pre>'

    cols    = list(result_data[0].keys())
    hdr     = "".join(f"<th>{_esc(c)}</th>" for c in cols)
    row_lim = result_data[:200]
    rows    = "".join(
        "<tr>" + "".join(f"<td>{_masked_html(row.get(c, ''))}</td>" for c in cols) + "</tr>"
        for row in row_lim
    )
    overflow = f'<p style="color:var(--muted);font-size:12px;margin-top:6px">... 외 {len(result_data)-200}건 생략</p>' if len(result_data) > 200 else ""
    return f'<div class="tbl-wrap"><table class="result-table"><thead><tr>{hdr}</tr></thead><tbody>{rows}</tbody></table></div>{overflow}'


# ── 상세 페이지 ──────────────────────────────

def _render_detail(log_id: str, fr_str: str, to_str: str) -> str:
    today = _today()
    try:
        fr = _parse_date(fr_str.replace("-", ""))
        to = _parse_date(to_str.replace("-", ""))
    except Exception:
        fr = to = today

    entry = None
    for e in iter_logs(fr, to):
        if e.get("log_id") == log_id:
            entry = e
            break

    if not entry:
        return _header() + '<div class="alert alert-danger">로그를 찾을 수 없습니다.</div>' + _footer()

    w    = entry["who"]
    when = entry["when"]
    whr  = entry["where"]
    wht  = entry["what"]
    how  = entry["how"]
    why  = entry["why"]
    res  = entry["result"]

    op        = wht.get("operation_type", wht["query_type"])
    ok        = verify_entry(entry)
    row_cnt   = wht.get("row_count", res.get("result_count", 0))
    pi_counts = res.get("personal_info_counts", {})
    int_tag   = ('<span class="integrity-ok">✔ 무결성 정상</span>' if ok
                 else '<span class="integrity-fail">✘ 무결성 위반!</span>')
    back_qs   = f"from_dt={fr_str}&to_dt={to_str}"

    params_html = _masked_html(json.dumps(wht.get("parameters"), ensure_ascii=False)) if wht.get("parameters") else "—"

    out = [_header()]
    out.append(f"""
<div style="margin-bottom:12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
  <a class="btn btn-secondary btn-sm" href="/search?{back_qs}">← 목록으로</a>
  <span style="font-size:12px;color:var(--muted)">로그 ID: <code>{_esc(entry["log_id"])}</code></span>
  <span>{int_tag}</span>
  <span class="unmasked-banner" id="unmaskedBanner">⚠ 개인정보 원문 표시 중</span>
</div>

<div class="card">
  <div class="card-header">
    <span>수행 개요</span>
    <span>{_op_badge(op)}&nbsp;{_status_badge(res["status"])}&nbsp;{_pi_badge(res["has_personal_info"])}</span>
  </div>
  <div class="card-body" style="padding:0">
  <div class="detail-grid">

    <div class="detail-cell">
      <div class="principle-label">WHO</div>
      <div class="principle-title">누가</div>
      <div class="kv"><span class="k">사용자 ID</span><span class="v">{_esc(w["user_id"])}</span></div>
      <div class="kv"><span class="k">이름</span><span class="v">{_esc(w["user_name"])}</span></div>
      <div class="kv"><span class="k">권한</span><span class="v">{_esc(w["user_role"])}</span></div>
    </div>

    <div class="detail-cell">
      <div class="principle-label">WHEN</div>
      <div class="principle-title">언제</div>
      <div class="kv"><span class="k">시작</span><span class="v">{_esc(when["start_time"])}</span></div>
      <div class="kv"><span class="k">종료</span><span class="v">{_esc(when["end_time"])}</span></div>
      <div class="kv"><span class="k">소요 시간</span><span class="v">{when["duration_ms"]} ms</span></div>
    </div>

    <div class="detail-cell">
      <div class="principle-label">WHERE</div>
      <div class="principle-title">어디서</div>
      <div class="kv"><span class="k">클라이언트 IP</span><span class="v">{_esc(whr["client_ip"])}</span></div>
      <div class="kv"><span class="k">호스트명</span><span class="v">{_esc(whr["hostname"])}</span></div>
      <div class="kv"><span class="k">DB 서버</span><span class="v">{_esc(whr["db_server"])}</span></div>
      <div class="kv"><span class="k">DB 명</span><span class="v">{_esc(whr["db_name"])}.{_esc(whr["db_schema"])}</span></div>
    </div>

    <div class="detail-cell">
      <div class="principle-label">WHAT</div>
      <div class="principle-title">무엇을</div>
      <div class="kv"><span class="k">수행 업무</span><span class="v">{_op_badge(op)}</span></div>
      <div class="kv"><span class="k">SQL 유형</span><span class="v">{_esc(wht["query_type"])}</span></div>
      <div class="kv"><span class="k">결과 건수</span><span class="v"><strong>{row_cnt:,}건</strong></span></div>
      <div class="kv"><span class="k">파라미터</span><span class="v">{params_html}</span></div>
    </div>

    <div class="detail-cell">
      <div class="principle-label">HOW</div>
      <div class="principle-title">어떻게</div>
      <div class="kv"><span class="k">수행 방식</span><span class="v">{_esc(how["execution_method"])}</span></div>
      <div class="kv"><span class="k">애플리케이션</span><span class="v">{_esc(how["application"])}</span></div>
      <div class="kv"><span class="k">세션 ID</span><span class="v">{_esc(how["session_id"])}</span></div>
    </div>

    <div class="detail-cell">
      <div class="principle-label">WHY</div>
      <div class="principle-title">왜</div>
      <div class="kv"><span class="k">처리 목적</span><span class="v">{_esc(why.get("purpose","—"))}</span></div>
      <div class="kv"><span class="k">참조 번호</span><span class="v">{_esc(why.get("reference_no","—"))}</span></div>
    </div>

  </div>

  <!-- SQL 전문 -->
  <div style="padding:14px 16px;border-top:1px solid var(--border)">
    <div style="font-weight:700;margin-bottom:8px;">SQL 쿼리 (전문)</div>
    <pre class="sql-block">{_masked_html(wht["sql"])}</pre>
  </div>

  <!-- 개인정보 항목별 건수 -->
  <div style="padding:14px 16px;border-top:1px solid var(--border)">
    <div style="font-weight:700;margin-bottom:8px;">
      개인정보 항목별 건수
      {'<span class="badge badge-pi" style="margin-left:6px">포함</span>' if res["has_personal_info"] else '<span style="color:var(--muted);font-size:12px;margin-left:6px">해당 없음</span>'}
    </div>
    {_pi_counts_html(pi_counts)}
  </div>

  <!-- 수행 결과 데이터 -->
  <div style="padding:14px 16px;border-top:1px solid var(--border)">
    <div style="font-weight:700;margin-bottom:8px;">
      수행 결과 데이터
      <span style="font-size:12px;color:var(--muted);font-weight:400;margin-left:6px">
        (헤더의 마스킹 체크박스로 개인정보 표시/숨김 전환)
      </span>
    </div>
    {_result_data_html(res.get("result_data") or [])}
    {f'<p style="color:var(--danger);margin-top:8px"><b>오류:</b> {_esc(res["error_message"])}</p>' if res.get("error_message") else ""}
  </div>

  </div>
</div>
""")
    out.append(_footer())
    return "".join(out)


# ── 무결성 검증 페이지 ───────────────────────

def _render_verify(params: dict) -> str:
    today  = _today()
    fr_str = _q(params, "from_dt", today.strftime("%Y-%m-%d"))
    to_str = _q(params, "to_dt",   today.strftime("%Y-%m-%d"))
    try:
        fr = _parse_date(fr_str.replace("-", ""))
        to = _parse_date(to_str.replace("-", ""))
    except Exception:
        fr = to = today

    items = []
    total = ok = fail = 0
    for e in iter_logs(fr, to):
        total += 1
        valid  = verify_entry(e)
        ok    += 1 if valid else 0
        fail  += 0 if valid else 1
        dt  = e["when"]["start_time"][:19].replace("T", " ")
        who = f'{_esc(e["who"]["user_name"])} ({_esc(e["who"]["user_id"])})'
        op  = e["what"].get("operation_type", e["what"]["query_type"])
        cls = "verify-ok" if valid else "verify-fail"
        icon = "✔" if valid else "✘"
        items.append(
            f'<div class="verify-item {cls}">'
            f'{icon} &nbsp; {_esc(dt)} &nbsp;|&nbsp; {who} &nbsp;|&nbsp; {_op_badge(op)} &nbsp;|&nbsp;'
            f'<code style="font-size:11px">{_esc(e["log_id"])}</code>'
            f'</div>'
        )

    summary_cls = "alert-success" if fail == 0 else "alert-danger"
    summary_msg = (f"✔ 총 {total}건 모두 무결성 정상입니다."
                   if fail == 0 else
                   f"✘ 총 {total}건 중 {fail}건 무결성 위반이 발견되었습니다!")

    out = [_header()]
    out.append(f"""
<form method="GET" action="/verify"
      style="display:flex;gap:12px;align-items:flex-end;margin-bottom:16px;flex-wrap:wrap;">
  <div class="form-group">
    <label>시작일</label>
    <input type="date" name="from_dt" value="{_esc(fr_str)}">
  </div>
  <div class="form-group">
    <label>종료일</label>
    <input type="date" name="to_dt" value="{_esc(to_str)}">
  </div>
  <button class="btn btn-warning" type="submit">🔐 검증 실행</button>
</form>
<div class="alert {summary_cls}">{summary_msg}</div>
<div class="card"><div class="card-body">{"".join(items) or "검증할 로그가 없습니다."}</div></div>
""")
    out.append(_footer())
    return "".join(out)


# ── CSV 내보내기 ─────────────────────────────

def _build_csv(params: dict) -> bytes:
    today  = _today()
    fr_str = _q(params, "from_dt", today.strftime("%Y-%m-%d"))
    to_str = _q(params, "to_dt",   today.strftime("%Y-%m-%d"))
    try:
        fr = _parse_date(fr_str.replace("-", ""))
        to = _parse_date(to_str.replace("-", ""))
    except Exception:
        fr = to = today

    entries = list(filter_logs(
        iter_logs(fr, to),
        user_id=_q(params, "user_id") or None,
        status=_q(params, "status")   or None,
        operation_type=_q(params, "op_type") or None,
        keyword=_q(params, "keyword") or None,
        has_pi=(True if _q(params,"has_pi")=="1" else (False if _q(params,"has_pi")=="0" else None)),
    ))

    buf = io.StringIO()
    fieldnames = [
        "log_id","start_time","duration_ms","user_id","user_name","user_role",
        "client_ip","hostname","db_server","db_name",
        "operation_type","query_type","sql","parameters","row_count",
        "execution_method","session_id","purpose","reference_no",
        "status","affected_rows","result_count","has_personal_info",
        *[f"pi_{n}" for n in PI_TYPE_NAMES],
        "error_message","integrity_ok",
    ]
    w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    for e in entries:
        pi_c = e["result"].get("personal_info_counts", {})
        row = {
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
            "parameters"      : json.dumps(e["what"].get("parameters"), ensure_ascii=False),
            "row_count"       : e["what"].get("row_count", 0),
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
            **{f"pi_{n}": pi_c.get(n, 0) for n in PI_TYPE_NAMES},
        }
        w.writerow(row)
    return ("﻿" + buf.getvalue()).encode("utf-8")


# ── HTTP 핸들러 ──────────────────────────────

class LogViewerHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path   = parsed.path.rstrip("/") or "/"

        if path in ("/", "/search"):
            self._send(200, "text/html; charset=utf-8",
                       _render_search(params).encode("utf-8"))

        elif path == "/detail":
            log_id = _q(params, "id")
            fr_str = _q(params, "from_dt", _today().strftime("%Y-%m-%d"))
            to_str = _q(params, "to_dt",   _today().strftime("%Y-%m-%d"))
            self._send(200, "text/html; charset=utf-8",
                       _render_detail(log_id, fr_str, to_str).encode("utf-8"))

        elif path == "/verify":
            self._send(200, "text/html; charset=utf-8",
                       _render_verify(params).encode("utf-8"))

        elif path == "/export":
            csv_bytes = _build_csv(params)
            fname     = f"audit_export_{_today().strftime('%Y%m%d')}.csv"
            self.send_response(200)
            self.send_header("Content-Type",        "text/csv; charset=utf-8-sig")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length",      str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)

        else:
            self._send(404, "text/plain; charset=utf-8", b"Not Found")

    def _send(self, code: int, ctype: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type",   ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ── 서버 시작 ────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="쿼리 감사 로그 웹 조회 서버")
    parser.add_argument("--host", default="127.0.0.1",
                        help="바인드 주소 (기본: 127.0.0.1, 원격: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8888,
                        help="포트 번호 (기본: 8888)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), LogViewerHandler)
    print(f"[웹 뷰어] http://{args.host}:{args.port}  (종료: Ctrl+C)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[웹 뷰어] 서버 종료.")


if __name__ == "__main__":
    main()
