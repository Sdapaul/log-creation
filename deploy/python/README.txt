이 폴더에 Python embeddable 패키지를 압축 해제하세요.
=======================================================

[Windows]
  1. 외부망 PC에서 prepare_offline.ps1 실행
     → python\ 폴더가 자동으로 생성됩니다.

  수동 설치 시:
  1. https://www.python.org/downloads/ 에서
     "Windows embeddable package (64-bit)" 다운로드
  2. 이 폴더(python\)에 ZIP 압축 해제
  3. python3XX._pth 파일을 메모장으로 열어
     '#import site' 줄의 '#' 를 제거하고 저장

  설치 후 폴더 구조:
  python\
    python.exe       ← 런처 스크립트가 이 파일을 사용
    python312.dll
    python3.dll
    python312.zip    ← 표준 라이브러리 포함
    python312._pth
    ...

[Linux]
  1. 외부망 PC에서 prepare_offline.sh 실행
     → 배포판별 .deb 또는 .rpm 패키지가 python_pkgs\ 에 저장됩니다.
  2. 내부망 서버에서 설치:
     Ubuntu: sudo dpkg -i python_pkgs/*.deb
     RHEL  : sudo rpm -ivh python_pkgs/*.rpm

  Python 이 이미 설치된 경우: 런처 스크립트(run_*.sh)가 시스템 python3 를 자동 사용합니다.
