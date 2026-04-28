#!/bin/bash
# PostgreSQL 감사 프록시 실행 스크립트 (Superset 전용)
# root 권한 불필요 — 일반 계정으로 실행 가능

cd "$(dirname "$0")"

if   [ -f "./python/bin/python3" ];  then PYTHON="./python/bin/python3"
elif [ -f "./python/python3" ];      then PYTHON="./python/python3"
else                                      PYTHON="python3"
fi

echo ""
echo "==================================================="
echo "  PostgreSQL 감사 프록시 (Superset 전용)"
echo "  root 권한 불필요 — 일반 계정으로 실행 가능"
echo "==================================================="
echo ""
echo "  Superset DB URI:"
echo "  postgresql+psycopg2://user:pass@<이서버IP>:5433/dbname?sslmode=disable"
echo ""

exec $PYTHON pg_proxy.py "$@"
