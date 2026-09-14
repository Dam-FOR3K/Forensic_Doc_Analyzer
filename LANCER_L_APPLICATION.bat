@echo off
title Forensic Doc Analyzer v1.0.0
color 0A
echo =======================================================================
echo    Forensic Doc Analyzer v1.0.0
echo    Concu par Dam-FOR3K (avec l'aide de l'IA Antigravity)
echo =======================================================================
echo.
echo Demarrage de l'application forensique et ouverture du navigateur...
echo.
cd /d "%~dp0"
python run_app.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Une erreur est survenue lors du demarrage.
    pause
)
