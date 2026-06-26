@echo off
title Ethernal Code
cd /d "X:\DOWNLOADS\Ethernal-Code"

:: Evita que el editor arranque como Node (por si se lanza desde la terminal
:: integrada de otro editor Electron como Cursor/VS Code/Antigravity)
set "ELECTRON_RUN_AS_NODE="

echo ============================================
echo   Abriendo Ethernal Code (dev)...
echo   No cierres esta ventana mientras lo usas.
echo ============================================
echo.

call ".\scripts\code.bat"
