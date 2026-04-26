#!/bin/bash
# 감사 로그 웹 조회 서버 실행 스크립트 (Linux/macOS)
# 관리자 권한 불필요

cd "$(dirname "$0")"

if   [ -f "./python/bin/python3" ];  then PYTHON="./python/bin/python3"
elif [ -f "./python/python3" ];      then PYTHON="./python/python3"
else                                      PYTHON="python3"
fi

echo ""
echo "==================================================="
echo "  감사 로그 웹 조회 서버"
echo "  브라우저에서 http://$(hostname -I | awk '{print $1}'):8888 접속"
echo "==================================================="
echo ""

exec $PYTHON log_viewer_web.py "$@"
