@echo off
REM WebGuardian - versao oficial. Fonte oficial: https://github.com/LuizZanchetta/WebGuardian
REM Assinatura digital oficial: WG-D0C5-ACA9-5777-6D53-ED11 (confira com VERIFICAR AUTENTICIDADE.bat)
title Atualizar o WebGuardian
echo Atualizando o WebGuardian com os arquivos desta pasta... aceite o aviso de Administrador.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WebGuardian.ps1" -Atualizar
