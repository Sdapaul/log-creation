#!/bin/bash
# PostgreSQL 패킷 스니퍼 실행 스크립트 (Linux/macOS)
# root 권한 또는 CAP_NET_RAW capability 필요

cd "$(dirname "$0")"

if   [ -f "./python/bin/python3" ];  then PYTHON="./python/bin/python3"
elif [ -f "./python/python3" ];      then PYTHON="./python/python3"
else                                      PYTHON="python3"
fi

echo ""
echo "==================================================="
echo "  PostgreSQL 패킷 스니퍼"
echo "  root 권한이 필요합니다 (AF_PACKET 소켓)"
echo "==================================================="
echo ""

if [ "$(id -u)" = "0" ]; then
    exec $PYTHON pg_sniffer.py "$@"
else
    exec sudo $PYTHON pg_sniffer.py "$@"
fi
