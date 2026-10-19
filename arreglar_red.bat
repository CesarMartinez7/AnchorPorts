@echo off
REM ============================================================
REM  Onitsuka - Reparar red (revierte IP forwarding y limpia)
REM  Doble clic. Se auto-eleva a Administrador.
REM ============================================================

REM --- Auto-elevacion a Administrador ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando permisos de Administrador...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo === Desactivando modo router (IPEnableRouter = 0) ===
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter /t REG_DWORD /d 0 /f

echo.
echo === Deteniendo el servicio RemoteAccess ===
sc stop RemoteAccess >nul 2>&1

echo.
echo === Limpiando cache ARP y DNS ===
netsh interface ip delete arpcache >nul 2>&1
ipconfig /flushdns

echo.
echo === Renovando direccion IP ===
ipconfig /release
ipconfig /renew

echo.
echo ============================================================
echo  Listo. Para que el cambio de "modo router" surta efecto,
echo  REINICIA el equipo ahora.
echo ============================================================
echo.
pause
