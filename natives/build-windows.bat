@echo off
setlocal EnableDelayedExpansion

set "VERSION=%~1"
if "!VERSION!"=="" (
    for /f "tokens=*" %%i in ('git describe --tags --always --dirty 2^>nul') do set "VERSION=%%i"
    if "!VERSION!"=="" set "VERSION=dev"
)

if not exist dist mkdir dist

set CGO_ENABLED=1
set GOOS=windows
set GOARCH=amd64

go build -ldflags="-s -w -X main.Version=!VERSION!" -o dist\native-client.exe ./cmd/native
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Native client build failed
    exit /b 1
)
echo [OK] Built: dist\native-client.exe
