@echo off
REM WebGuardian - versao oficial. Fonte oficial: https://github.com/LuizZanchetta/WebGuardian
REM Assinatura digital oficial: WG-D0C5-ACA9-5777-6D53-ED11 (confira com VERIFICAR AUTENTICIDADE.bat)
title Verificar a autenticidade do WebGuardian
echo Conferindo se esta copia do WebGuardian e a versao oficial, sem nenhum arquivo alterado...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WebGuardian.ps1" -Verificar
