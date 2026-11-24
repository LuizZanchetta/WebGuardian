@echo off
REM WebGuardian - versao oficial. Fonte oficial: https://github.com/LuizZanchetta/WebGuardian
REM Assinatura digital oficial: WG-D0C5-ACA9-5777-6D53-ED11 (confira com VERIFICAR AUTENTICIDADE.bat)
chcp 65001 >nul
title Atualizar o WebGuardian
set "PEDIDO=%LOCALAPPDATA%\Guardiao\atualizar-pedido"
if not exist "%ProgramData%\Guardiao" goto antigo
REM O WebGuardian JA INSTALADO confere a assinatura desta pasta com a chave oficial dele e aplica a versao nova.
echo Pedindo ao WebGuardian instalado que confira a assinatura desta versao...
if not exist "%LOCALAPPDATA%\Guardiao" mkdir "%LOCALAPPDATA%\Guardiao"
> "%PEDIDO%" echo %~dp0
for /l %%i in (1,1,20) do (
  if not exist "%PEDIDO%" goto aceito
  timeout /t 1 /nobreak >nul
)
del "%PEDIDO%" >nul 2>&1
echo O WebGuardian instalado nao respondeu (versao antiga ou monitor parado).
:antigo
echo Usando o atualizador desta pasta... aceite o aviso de Administrador.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WebGuardian.ps1" -Atualizar
goto :eof
:aceito
echo Pedido recebido. Confirme na janela "WebGuardian - confirme" que vai aparecer.
echo Depois, a atualizacao segue sozinha numa janela propria.
timeout /t 10 >nul