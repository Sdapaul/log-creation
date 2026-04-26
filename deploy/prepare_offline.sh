#!/bin/bash
# ============================================================
# prepare_offline.sh
# 외부망(인터넷 연결 가능한 Linux PC)에서 실행
# 배포판별 Python 3 패키지를 다운로드해 python_pkgs/ 폴더에 저장한다.
# 완료 후 deploy/ 폴더 전체를 내부망으로 반입하면 바로 사용 가능.
# ============================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$SCRIPT_DIR/python_pkgs"

echo ""
echo "==================================================="
echo "  Linux 오프라인 Python 3 패키지 준비"
echo "==================================================="

# 배포판 감지
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif command -v apt-get &>/dev/null; then
        echo "debian"
    elif command -v yum &>/dev/null; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
echo "  감지된 배포판: $DISTRO"
echo ""
mkdir -p "$PKG_DIR"

case "$DISTRO" in
    ubuntu|debian|linuxmint)
        echo "[Ubuntu/Debian] apt 패키지 다운로드 중..."
        apt-get install --download-only \
            -o dir::cache::archives="$PKG_DIR" \
            python3 python3-minimal libpython3-stdlib 2>/dev/null || true
        # 이미 설치된 경우 재다운로드
        apt-get install --reinstall --download-only \
            -o dir::cache::archives="$PKG_DIR" \
            python3 2>/dev/null || true
        echo ""
        echo "  패키지 저장 위치: $PKG_DIR"
        echo "  내부망 설치 명령: sudo dpkg -i '$PKG_DIR'/*.deb"
        ;;

    rhel|centos|rocky|almalinux|fedora)
        echo "[RHEL/CentOS/Rocky] yum/dnf 패키지 다운로드 중..."
        if command -v dnf &>/dev/null; then
            dnf download --destdir="$PKG_DIR" python3 python3-libs 2>/dev/null || true
        else
            yum install --downloadonly --downloaddir="$PKG_DIR" python3 2>/dev/null || true
        fi
        echo ""
        echo "  패키지 저장 위치: $PKG_DIR"
        echo "  내부망 설치 명령: sudo rpm -ivh '$PKG_DIR'/*.rpm"
        ;;

    *)
        echo "  배포판을 자동 감지하지 못했습니다."
        echo ""
        echo "  수동 방법 선택:"
        echo "  A) Miniconda 오프라인 설치파일 (권장 — 배포판 무관)"
        echo "     wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh"
        echo "     bash Miniconda3-latest-Linux-x86_64.sh -b -p ./python"
        echo "     ./python/bin/python3 --version"
        echo ""
        echo "  B) Python 소스 빌드"
        echo "     wget https://www.python.org/ftp/python/3.12.9/Python-3.12.9.tgz"
        echo "     tar xf Python-3.12.9.tgz && cd Python-3.12.9"
        echo "     ./configure --prefix=\$SCRIPT_DIR/python --enable-optimizations"
        echo "     make -j4 && make install"
        ;;
esac

echo ""
echo "==================================================="
echo "  준비 완료."
echo "  deploy/ 폴더 전체를 내부망 서버로 복사하세요."
echo "  이후 run_oracle_sniffer.sh 또는 run_pg_sniffer.sh 실행"
echo "==================================================="
