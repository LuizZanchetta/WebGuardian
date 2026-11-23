@echo off
REM WebGuardian - versao oficial. Fonte oficial: https://github.com/LuizZanchetta/WebGuardian
REM Assinatura digital oficial: WG-D0C5-ACA9-5777-6D53-ED11 (confira com VERIFICAR AUTENTICIDADE.bat)
title Desinstalar o WebGuardian
echo Para desinstalar o WebGuardian sera pedida a SENHA do Windows do dono do PC.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WebGuardian.ps1" -Desinstalar
