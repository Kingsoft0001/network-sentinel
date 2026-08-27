@echo off
title NetSentinel - Host IDS & Network Traffic Monitor
color 0A
cd /d "%~dp0"
echo ===================================================
echo     Starting NetSentinel Live Network Monitor
echo ===================================================
python main.py %*
pause
