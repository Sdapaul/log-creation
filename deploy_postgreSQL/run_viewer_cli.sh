#!/bin/bash
# 감사 로그 CLI 조회 실행 스크립트 (Linux/macOS)

cd "$(dirname "$0")"

if   [ -f "./python/bin/python3" ];  then PYTHON="./python/bin/python3"
elif [ -f "./python/python3" ];      then PYTHON="./python/python3"
else                                      PYTHON="python3"
fi

exec $PYTHON log_viewer.py "$@"
