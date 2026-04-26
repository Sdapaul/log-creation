#!/bin/bash
# Oracle TNS 패킷 스니퍼 실행 스크립트 (Linux/macOS)
# root 권한 또는 CAP_NET_RAW capability 필요

cd "$(dirname "$0")"

# Python 위치 결정
if   [ -f "./python/bin/python3" ];  then PYTHON="./python/bin/python3"
elif [ -f "./python/python3" ];      then PYTHON="./python/python3"
else                                      PYTHON="python3"
fi

echo ""
echo "==================================================="
echo "  Oracle TNS 패킷 스니퍼"
echo "  root 권한이 필요합니다 (AF_PACKET 소켓)"
echo "==================================================="
echo ""

if [ "$(id -u)" = "0" ]; then
    exec $PYTHON packet_sniffer.py "$@"
else
    exec sudo $PYTHON packet_sniffer.py "$@"
fi
