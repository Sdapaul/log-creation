# ============================================================
# prepare_offline.ps1
# 외부망(인터넷 연결 가능한 PC)에서 실행
# Python embeddable 패키지를 다운로드해 python\ 폴더에 설치한다.
# 완료 후 deploy\ 폴더 전체를 내부망으로 반입하면 바로 사용 가능.
# ============================================================

param(
    [string]$PythonVersion = "3.12.9",
    [string]$Arch = ""   # 비워두면 자동 감지
)

$ErrorActionPreference = "Stop"

# 아키텍처 자동 감지
if (-not $Arch) {
    $Arch = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "win32" }
}

$ZipName  = "python-$PythonVersion-embed-$Arch.zip"
$Url      = "https://www.python.org/ftp/python/$PythonVersion/$ZipName"
$OutDir   = Join-Path $PSScriptRoot "python"
$ZipPath  = Join-Path $PSScriptRoot $ZipName

Write-Host ""
Write-Host "==================================================="
Write-Host "  Python $PythonVersion Embeddable 오프라인 준비"
Write-Host "==================================================="
Write-Host "  다운로드: $Url"
Write-Host "  설치 경로: $OutDir"
Write-Host ""

# 다운로드
Write-Host "[1/3] 다운로드 중..."
Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing

# 기존 폴더 제거 후 압축 해제
Write-Host "[2/3] 압축 해제 중..."
if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
Expand-Archive -Path $ZipPath -DestinationPath $OutDir
Remove-Item $ZipPath

# python3XX._pth 파일에서 '#import site' 주석 해제
# → PYTHONPATH 환경 변수 및 site-packages 지원 활성화
Write-Host "[3/3] import site 활성화 중..."
$pthFile = Get-ChildItem "$OutDir\python*._pth" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($pthFile) {
    $content = Get-Content $pthFile.FullName -Raw
    $content = $content -replace '#import site', 'import site'
    Set-Content -Path $pthFile.FullName -Value $content -Encoding UTF8
    Write-Host "  수정 완료: $($pthFile.Name)"
} else {
    Write-Warning ".pth 파일을 찾을 수 없습니다. 런처 스크립트에서 수동으로 경로를 설정합니다."
}

# 검증
$pyExe = Join-Path $OutDir "python.exe"
if (Test-Path $pyExe) {
    $ver = & $pyExe --version 2>&1
    Write-Host ""
    Write-Host "==================================================="
    Write-Host "  완료: $ver"
    Write-Host "  python\ 폴더가 생성되었습니다."
    Write-Host ""
    Write-Host "  다음 단계:"
    Write-Host "  1. deploy\ 폴더 전체를 내부망 서버로 복사"
    Write-Host "  2. run_oracle_sniffer.bat (또는 .sh) 실행"
    Write-Host "==================================================="
} else {
    Write-Error "python.exe 를 찾을 수 없습니다. 다운로드를 다시 시도하세요."
}
