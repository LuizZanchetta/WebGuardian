<#
.SYNOPSIS
  WebGuardian — monitora acesso indevido no Windows e ISOLA (de forma reversível)
  até você decidir o que fazer junto com o Windows Defender.

.DESCRIPTION
  O que ele vigia:
    - Tentativas de logon com falha em série (força bruta)        -> bloqueia o IP no firewall
    - Logon remoto (RDP / rede) vindo de IP externo                -> bloqueia o IP no firewall
    - Criação de usuário novo                                      -> desativa o usuário
    - Usuário adicionado ao grupo Administradores                  -> remove do grupo
    - Serviço novo instalado (suspeito)                            -> para e desativa o serviço
    - Tarefa agendada nova (suspeita)                              -> desativa a tarefa
    - Entrada nova de inicialização (Run) suspeita                 -> remove (guarda backup)
    - Processo sem assinatura, rodando de pasta suspeita,
      conectado à internet                                         -> SUSPENDE o processo + bloqueia no firewall
    - Defender desligado, ameaça detectada, log de segurança apagado -> alerta

  Nada é apagado sem você mandar. Tudo vai para a quarentena e você decide
  no PAINEL (HTML no navegador): Liberar (era seguro) ou Apagar ameaça.

.EXAMPLE
  .\WebGuardian.ps1                      # instala (pede Administrador sozinho)
  .\WebGuardian.ps1 -Painel              # abre o painel no navegador
  .\WebGuardian.ps1 -Monitorar           # roda o monitor nesta janela
  .\WebGuardian.ps1 -Status              # lista a quarentena no terminal
  .\WebGuardian.ps1 -Liberar 3           # desfaz o isolamento do item 3
  .\WebGuardian.ps1 -Apagar 3            # elimina a ameaça do item 3
  .\WebGuardian.ps1 -IsolarRede          # EMERGÊNCIA: desliga todas as placas de rede
  .\WebGuardian.ps1 -RestaurarRede       # religa as placas de rede
  .\WebGuardian.ps1 -Atualizar           # aplica uma versão nova (guarda backup da anterior)
  .\WebGuardian.ps1 -Desinstalar         # remove a inicialização automática (pede a senha do dono)
  .\WebGuardian.ps1 -Verificar           # confere se esta cópia é a versão oficial (sem Administrador)

.NOTES
  VERSÃO OFICIAL - fonte oficial: https://github.com/LuizZanchetta/WebGuardian
  Assinatura digital oficial (impressão digital): WG-D0C5-ACA9-5777-6D53-ED11
  Antes de instalar, confira a cópia com "VERIFICAR AUTENTICIDADE.bat". Cópias baixadas de
  outros lugares podem ter sido alteradas para fazer mal ao seu PC.
#>
[CmdletBinding(DefaultParameterSetName = 'Instalar')]
param(
    [Parameter(ParameterSetName = 'Monitorar')][switch]$Monitorar,
    [Parameter(ParameterSetName = 'Painel')][switch]$Painel,
    [Parameter(ParameterSetName = 'Menu')][switch]$Menu,
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    [Parameter(ParameterSetName = 'Liberar', Mandatory)][string]$Liberar,
    [Parameter(ParameterSetName = 'Apagar', Mandatory)][string]$Apagar,
    [Parameter(ParameterSetName = 'Confirmar', Mandatory)][string]$Confirmar,
    [Parameter(ParameterSetName = 'IsolarRede')][switch]$IsolarRede,
    [Parameter(ParameterSetName = 'RestaurarRede')][switch]$RestaurarRede,
    [Parameter(ParameterSetName = 'Instalar')][switch]$Instalar,
    [Parameter(ParameterSetName = 'Desinstalar')][switch]$Desinstalar,
    [Parameter(ParameterSetName = 'Atualizar')][switch]$Atualizar,
    [Parameter(ParameterSetName = 'Verificar')][switch]$Verificar,

    [Parameter(ParameterSetName = 'Monitorar')][int]$IntervaloSegundos = 15,
    # Só alerta, não isola nada (útil nos primeiros dias para ver falsos positivos)
    [Parameter(ParameterSetName = 'Monitorar')][switch]$SomenteAlertar
)

$ErrorActionPreference = 'Continue'
$VersaoGuardiao = '1.9.0'   # 1.9.0: ameaças detectadas pelo Defender na aba Decisões (liberar ou apagar)
                            # 1.8.2: verificação pelo antivírus ativo (AMSI): downloads e verificações rápida/completa
                            #        com Avast/AVG/Kaspersky... sem abrir a tela deles; verificação rápida automática diária
                            # 1.8.1: compatível com outros antivírus (Avast, AVG, Norton...): sem alarme falso de
                            #        "Defender desligado", downloads conferidos pelo antivírus ativo
                            # 1.8.0: primeira versão pública: assinatura digital oficial + conferência de autenticidade
                            #        (na instalação, na atualização e a cada 10 min nos arquivos instalados)
                            # 1.7.1: atividade por sessão (arquivada a cada PC ligado) + registro de entradas no Windows;
                            #        limpar lista de ameaças detectadas e de histórico
                            # 1.7.0: nome WebGuardian; regras contra golpes em downloads + quarentena de arquivos;
                            #        base do Defender sempre atualizada; limpar lista de downloads; proteções extras
                            # 1.6.1: verifica todo download (inclusive instaladores); % das verificações;
                            #        painel em abas + emergência no teclado; app compilado na instalação
                            # 1.6.0: app WebGuardian.exe (janela própria, entrada por código de uso único)
                            # 1.5.0: classificador por assinatura digital (menos alarmes falsos) + atualizador

# ===================== AUTENTICIDADE: versão oficial assinada =====================
# Cada versão oficial traz ASSINATURA\manifesto.json (o SHA-256 de cada arquivo) e ASSINATURA\manifesto.sig
# (assinatura digital RSA-3072 do manifesto). Só quem tem a chave PRIVADA oficial consegue assinar, e ela
# nunca é publicada. A chave PÚBLICA abaixo confere: se um único caractere de qualquer arquivo mudar, a
# conferência acusa. Se alguém trocar a chave para assinar uma cópia falsa, a IMPRESSÃO DIGITAL muda e
# deixa de bater com a publicada na página oficial.
$FonteOficial = 'https://github.com/LuizZanchetta/WebGuardian'
$ChavePublicaOficial = '<RSAKeyValue><Modulus>19puAGxzdUppr2DZy93JLUAm/eCjVMxpfqWjb82ODNVTYJCuoJNFPPGfU2lQScv0xkW4Ix2HUrHq3jDPqKQ2lrwAvhf8ALLicns8qY0sKpvs04n2bf2PEvsxFLg1HjfPvSMXbuQAYc0Ca2IudLeyB5YYIb9I6mVNPKzwUQ8+D0FX1Nc9OWnSMJTNaRhPLB4kAwsIXTKI2IL4QR4AVWgnZIqbslXYTEX7MUZv2QQ1K4LyIztLgU0ksRjO0Kpx9dKODlPB0AIIyhiPedg+FDmeTQQW3Dg3O6J4+qy9XXPmdY9KsUVG0eP7qW8iDR4mQ9PmGu7Jvqp13PWgZLhfi4Quy0E9DSyECvPF4vpKOCHmBLOGzmCO+asy4FOZnujU8iIpETPZWVVxsc7sE+ixSMkyVW+Kr43Bu2krnqRQqJdILbadsLnACIZKZ0Vj8BO6LfqpoMDtRW644UAKa26klQ4f2TtIsOXorE/wTh7EBms1VM8qY2dFaMHA8GHr/KXwobjN</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'   # impressão digital: WG-D0C5-ACA9-5777-6D53-ED11
$ExtTexto = @('.ps1', '.html', '.bat', '.cs', '.manifest', '.md', '.json', '.txt')

function Get-BytesCanonicos([byte[]]$Bytes) {
    # CRLF vira LF: o Git pode trocar uma quebra de linha pela outra ao baixar, sem mudar o conteúdo
    $l1 = [Text.Encoding]::GetEncoding(28591)   # 1 byte = 1 caractere (não altera nenhum outro byte)
    return , $l1.GetBytes($l1.GetString($Bytes).Replace("`r`n", "`n"))
}
function Get-HashWG([string]$Caminho) {
    $b = [IO.File]::ReadAllBytes($Caminho)
    if ($ExtTexto -contains [IO.Path]::GetExtension($Caminho).ToLower()) { $b = Get-BytesCanonicos $b }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($b)) -replace '-', '').ToLower() } finally { $sha.Dispose() }
}
function Get-ImpressaoDigital([string]$ChaveXml) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $h = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($ChaveXml))) -replace '-', '').Substring(0, 20)
    $sha.Dispose()
    return 'WG-' + ((0..4 | ForEach-Object { $h.Substring($_ * 4, 4) }) -join '-')
}
function Test-Autenticidade([string]$DirAssinatura, [string]$Raiz, [hashtable]$Mapa = $null) {
    # $Mapa (arquivos instalados): nome no manifesto -> caminho real. Sem $Mapa: confere a pasta $Raiz inteira.
    $r = [ordered]@{ estado = 'sem-assinatura'; versao = ''; assinadoEm = ''; fonte = $FonteOficial
                     impressao = (Get-ImpressaoDigital $ChavePublicaOficial); problemas = @(); conferidos = 0 }
    $arqM = Join-Path $DirAssinatura 'manifesto.json'; $arqS = Join-Path $DirAssinatura 'manifesto.sig'
    if (-not (Test-Path -LiteralPath $arqM) -or -not (Test-Path -LiteralPath $arqS)) {
        $r.problemas = @('Sem a assinatura oficial (falta a pasta ASSINATURA)'); return [pscustomobject]$r
    }
    $ok = $false
    try {
        $bytesM = Get-BytesCanonicos ([IO.File]::ReadAllBytes($arqM))
        $sig = [Convert]::FromBase64String(([IO.File]::ReadAllText($arqS)).Trim())
        $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
        $rsa.PersistKeyInCsp = $false
        $rsa.FromXmlString($ChavePublicaOficial)
        $ok = $rsa.VerifyData($bytesM, 'SHA256', $sig)
        $rsa.Dispose()
    } catch { $ok = $false }
    if (-not $ok) {
        $r.estado = 'assinatura-invalida'
        $r.problemas = @('A assinatura nao confere com a chave oficial: o manifesto foi alterado ou assinado por outra pessoa')
        return [pscustomobject]$r
    }
    $man = [Text.Encoding]::UTF8.GetString($bytesM).TrimStart([char]0xFEFF) | ConvertFrom-Json
    $r.versao = "$($man.versao)"; $r.assinadoEm = "$($man.assinadoEm)"
    $probs = New-Object System.Collections.Generic.List[string]
    $nomes = @($man.arquivos.PSObject.Properties | ForEach-Object Name)
    if ($nomes -notcontains 'WebGuardian.ps1') { $probs.Add('Manifesto sem o WebGuardian.ps1') }
    foreach ($p in $man.arquivos.PSObject.Properties) {
        if ($Mapa) { if (-not $Mapa.ContainsKey($p.Name)) { continue }; $cam = $Mapa[$p.Name] }
        else { $cam = Join-Path $Raiz ($p.Name -replace '/', '\') }
        if (-not (Test-Path -LiteralPath $cam)) { $probs.Add("Faltando: $($p.Name)"); continue }
        if ((Get-HashWG $cam) -ne "$($p.Value)") { $probs.Add("Alterado: $($p.Name)") } else { $r.conferidos++ }
    }
    if ($Mapa) { foreach ($k in $Mapa.Keys) { if ($nomes -notcontains $k) { $probs.Add("Sem assinatura: $k") } } }
    $r.problemas = @($probs)
    $r.estado = if ($probs.Count) { 'alterada' } else { 'oficial' }
    return [pscustomobject]$r
}

function Show-Verificacao([string]$Raiz) {
    # VERIFICAR AUTENTICIDADE.bat: confere a pasta baixada ANTES de instalar (não precisa de Administrador)
    $v = Test-Autenticidade (Join-Path $Raiz 'ASSINATURA') $Raiz
    Write-Host ''
    Write-Host '================ WEBGUARDIAN - VERIFICAR AUTENTICIDADE ================' -ForegroundColor Cyan
    Write-Host " Pasta conferida: $Raiz"
    Write-Host ''
    switch ($v.estado) {
        'oficial' {
            Write-Host " RESULTADO: VERSAO OFICIAL $($v.versao) - NENHUM ARQUIVO FOI ALTERADO" -ForegroundColor Green
            Write-Host " $($v.conferidos) arquivos conferidos um por um (SHA-256). Assinada em $($v.assinadoEm)." -ForegroundColor Green
        }
        'alterada'            { Write-Host ' RESULTADO: COPIA ALTERADA - NAO INSTALE' -ForegroundColor Red }
        'assinatura-invalida' { Write-Host ' RESULTADO: ASSINATURA FALSA OU DANIFICADA - NAO INSTALE' -ForegroundColor Red }
        default               { Write-Host ' RESULTADO: SEM ASSINATURA OFICIAL - NAO INSTALE' -ForegroundColor Red }
    }
    foreach ($p in $v.problemas) { Write-Host "   - $p" -ForegroundColor Red }
    # Programas a mais na pasta (o WebGuardian.exe é normal: é compilado neste PC na instalação)
    $listados = @('WebGuardian.exe')
    try { $listados += @((Get-Content -LiteralPath (Join-Path $Raiz 'ASSINATURA\manifesto.json') -Raw -Encoding UTF8 | ConvertFrom-Json).arquivos.PSObject.Properties | ForEach-Object Name) } catch { }
    $extras = @(Get-ChildItem -LiteralPath $Raiz -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^\.(ps1|psm1|bat|cmd|exe|dll|vbs|js|lnk|scr)$' -and $_.FullName -notmatch '\\\.git\\' } |
                ForEach-Object { $_.FullName.Substring($Raiz.TrimEnd('\').Length + 1) -replace '\\', '/' } |
                Where-Object { $listados -notcontains $_ })
    if ($extras.Count) {
        Write-Host ''
        Write-Host ' Programas na pasta que NAO fazem parte da versao oficial (apague e nao abra):' -ForegroundColor Yellow
        foreach ($e in $extras) { Write-Host "   - $e" -ForegroundColor Yellow }
    }
    Write-Host ''
    Write-Host " Impressao digital desta copia: $($v.impressao)" -ForegroundColor Cyan
    Write-Host " Ela precisa ser IGUAL a publicada na pagina oficial: $FonteOficial" -ForegroundColor Cyan
    Write-Host ' Se for diferente, alguem trocou a chave: a copia NAO e oficial, mesmo que diga OK acima.' -ForegroundColor Cyan
    Write-Host '=======================================================================' -ForegroundColor Cyan
    try { Read-Host 'Pressione Enter para fechar' | Out-Null } catch { }
    return $v
}

if ($PSCmdlet.ParameterSetName -eq 'Verificar') { Show-Verificacao $PSScriptRoot | Out-Null; exit }

# ---------------- Eleva para Administrador automaticamente ----------------
$ehAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $ehAdmin) {
    $argumentos = @('-NoProfile', '-ExecutionPolicy', 'Bypass')
    if ($PSCmdlet.ParameterSetName -eq 'Painel') { $argumentos += @('-WindowStyle', 'Minimized') }
    $argumentos += @('-File', "`"$PSCommandPath`"")
    foreach ($p in $PSBoundParameters.GetEnumerator()) {
        if ($p.Value -is [switch]) { if ($p.Value) { $argumentos += "-$($p.Key)" } }
        else { $argumentos += "-$($p.Key)"; $argumentos += "`"$($p.Value)`"" }
    }
    try { Start-Process powershell.exe -Verb RunAs -ArgumentList $argumentos }
    catch { Write-Host 'E preciso aceitar o aviso de Administrador para o WebGuardian funcionar.' -ForegroundColor Red; Start-Sleep 5 }
    exit
}

# ============================== CONFIGURAÇÃO ==============================
$Pasta          = Join-Path $env:ProgramData 'Guardiao'
$ArqLog         = Join-Path $Pasta 'guardiao.log'
$ArqQuarentena  = Join-Path $Pasta 'quarentena.json'
$ArqRede        = Join-Path $Pasta 'placas_desligadas.json'
$ArqPainel      = Join-Path $Pasta 'painel_ativo.json'
$ArqAmeacasOcultas = Join-Path $Pasta 'ameacas_ocultas_ate.txt'
$DirScript      = $PSScriptRoot
$ModoAtual      = $PSCmdlet.ParameterSetName
$GrupoFirewall  = 'Guardiao'
$NomeTarefa     = 'Guardiao - Monitor de Acesso'

$Config = @{
    LimiteFalhasLogon = 5          # falhas do mesmo IP...
    JanelaFalhasMin   = 10         # ...dentro desta janela (minutos) = bloqueio
    IPsConfiaveis     = @('127.0.0.1', '::1', '-', '')   # adicione IPs seus aqui
    # Trechos de caminho onde programa legítimo raramente roda conectado à internet
    PastasSuspeitas   = @(
        '\AppData\Local\Temp\', '\Windows\Temp\', '\Downloads\', '\Users\Public\',
        '\AppData\Roaming\', '\ProgramData\', '\$Recycle.Bin\', '\Windows\Tasks\'
    )
}
# =========================================================================

if (-not (Test-Path $Pasta)) {
    New-Item -ItemType Directory -Path $Pasta -Force | Out-Null
    # Só Administradores e SYSTEM podem mexer na pasta (evita que um invasor
    # sem privilégio troque o script que roda como administrador)
    icacls $Pasta /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
}

# ------------------------------ Utilidades -------------------------------
function Write-Log([string]$Nivel, [string]$Msg, $Quando = $null) {
    # $Quando: hora real do evento (ex.: entradas no Windows lidas desde que o PC ligou)
    $hora = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; if ($Quando) { $hora = ([datetime]$Quando).ToString('yyyy-MM-dd HH:mm:ss') }
    $linha = '{0} [{1}] {2}' -f $hora, $Nivel, $Msg
    Add-Content -Path $ArqLog -Value $linha -Encoding UTF8
    $cor = switch ($Nivel) { 'ALERTA' { 'Yellow' } 'ISOLADO' { 'Red' } 'CRITICO' { 'Magenta' } default { 'Gray' } }
    Write-Host $linha -ForegroundColor $cor
}

function Open-Painel {
    # Com o app instalado: abre o WebGuardian.exe como USUÁRIO COMUM (o explorer.exe da sessão
    # é quem inicia), assim a janela do painel nunca herda os poderes de Administrador do monitor.
    $app = Join-Path $Pasta 'app\WebGuardian.exe'
    if (Test-Path $app) { Start-Process explorer.exe -ArgumentList "`"$app`""; return }
    # Sem o app (versões antigas): abre no navegador
    if ($script:UrlPainel) { Start-Process $script:UrlPainel; return }
    # Fora do monitor: sobe um painel avulso (o processo atual já é administrador)
    Start-Process powershell.exe -WindowStyle Minimized -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Minimized', '-File', "`"$PSCommandPath`"", '-Painel')
}

$script:Icone = $null
function Initialize-Icone {
    if ($script:Icone) { return }
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $script:Icone = New-Object System.Windows.Forms.NotifyIcon
    $script:Icone.Icon = [System.Drawing.SystemIcons]::Shield
    $script:Icone.Text = 'WebGuardian - clique duas vezes para abrir o painel'
    $script:Icone.Visible = $true
    $script:Icone.add_DoubleClick({ Open-Painel })
    $script:Icone.add_BalloonTipClicked({ Open-Painel })
    $menuCtx = New-Object System.Windows.Forms.ContextMenuStrip
    [void]$menuCtx.Items.Add('Abrir painel', $null, { Open-Painel })
    $script:Icone.ContextMenuStrip = $menuCtx
}
function Show-Alerta([string]$Titulo, [string]$Texto) {
    try {
        Initialize-Icone
        $script:Icone.ShowBalloonTip(15000, $Titulo, "$Texto`n(clique para abrir o painel)", [System.Windows.Forms.ToolTipIcon]::Warning)
        [console]::Beep(1000, 300); [console]::Beep(1400, 300)
    } catch { }
}

function Get-Quarentena {
    if (-not (Test-Path $ArqQuarentena)) { return @() }
    $txt = Get-Content $ArqQuarentena -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($txt)) { return @() }
    # Atenção (PowerShell 5.1): "@(texto | ConvertFrom-Json)" embrulha a lista inteira como UM item.
    # Guardar em variável primeiro e só depois usar @() devolve os itens certos.
    $lista = $txt | ConvertFrom-Json
    return @($lista)
}
function Save-Quarentena($Itens) {
    ConvertTo-Json -InputObject @($Itens) -Depth 6 | Set-Content $ArqQuarentena -Encoding UTF8
}

function Add-Quarentena([string]$Tipo, [string]$Alvo, [string]$Motivo, [hashtable]$Desfazer) {
    $itens = @(Get-Quarentena)
    $id = 1; if ($itens.Count) { $id = ([int]($itens | Measure-Object Id -Maximum).Maximum) + 1 }
    $itens += [pscustomobject]@{
        Id = $id; Tipo = $Tipo; Alvo = $Alvo; Motivo = $Motivo
        Quando = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Estado = 'ISOLADO'; Desfazer = $Desfazer
    }
    Save-Quarentena $itens
    Write-Log 'ISOLADO' "#$id [$Tipo] $Alvo - $Motivo"
    Show-Alerta "WebGuardian isolou: $Tipo" "$Alvo`n$Motivo"
}

function Test-Alerta([string]$Tipo, [string]$Alvo, [string]$Motivo) {
    Write-Log 'ALERTA' "[$Tipo] $Alvo - $Motivo"
    Show-Alerta "WebGuardian: $Tipo" "$Alvo`n$Motivo"
}

function Test-IpPrivado([string]$Ip) {
    if ($Config.IPsConfiaveis -contains $Ip) { return $true }
    return ($Ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1$|fe80:|f[cd][0-9a-f]{2}:|0\.0\.0\.0$|::$)')
}

$script:CacheAssinatura = @{}
function Test-Suspeito([string]$Caminho) {
    # Suspeito = arquivo em pasta suspeita E sem assinatura digital válida
    if ([string]::IsNullOrWhiteSpace($Caminho)) { return $false }
    if ($script:CacheAssinatura.ContainsKey($Caminho)) { return $script:CacheAssinatura[$Caminho] }
    $emPasta = $false
    foreach ($p in $Config.PastasSuspeitas) { if ($Caminho -like "*$p*") { $emPasta = $true; break } }
    $assinado = $false
    if (Test-Path -LiteralPath $Caminho -ErrorAction SilentlyContinue) {
        try { $assinado = ((Get-AuthenticodeSignature -LiteralPath $Caminho).Status -eq 'Valid') } catch { }
    }
    $res = ($emPasta -and -not $assinado)
    $script:CacheAssinatura[$Caminho] = $res
    return $res
}

function Get-ExeDeComando([string]$Linha) {
    if ([string]::IsNullOrWhiteSpace($Linha)) { return $null }
    $l = [Environment]::ExpandEnvironmentVariables($Linha.Trim())
    if ($l -match '^"([^"]+)"') { return $Matches[1] }
    if ($l -match '^(.+?\.(exe|dll|bat|cmd|ps1|vbs|js|scr|com))\b') { return $Matches[1] }
    return ($l -split ' ')[0]
}

$script:JobScan = $null
function Start-ScanDefender([string]$Caminho) {
    try {
        if ($Caminho -and (Test-Path -LiteralPath $Caminho)) {
            Write-Log 'INFO' "Defender: verificando $Caminho"
            Start-Job -ScriptBlock { param($c) Start-MpScan -ScanType CustomScan -ScanPath $c } -ArgumentList $Caminho | Out-Null
        }
    } catch { Write-Log 'INFO' "Falha ao chamar Defender: $_" }
}

# ===================== VERIFICAÇÃO DE DOWNLOADS (1.6.1) =====================
# Todo arquivo baixado (inclusive instaladores) passa pelo Windows Defender assim que termina
# de baixar. Pastas vigiadas: Downloads (tudo) e Área de Trabalho/Documentos (só arquivos que
# têm a "marca de download" do Windows, o Zone.Identifier).
$MpCmdRun = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
$ExtTemporarias = @('.crdownload', '.part', '.partial', '.download', '.opdownload', '.tmp', '.temp', '.!ut', '.aria2')
$ExtExecutaveis = @('.exe', '.msi', '.msix', '.msixbundle', '.appx', '.appxbundle', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse',
                    '.wsf', '.hta', '.scr', '.com', '.pif', '.lnk', '.dll', '.jar', '.iso', '.img', '.vhd', '.vhdx', '.reg')
$script:Vigias = @(); $script:FilaDownloads = @{}; $script:ScansDownload = @(); $script:DownloadsVistos = @{}
$script:DownloadsRecentes = New-Object System.Collections.ArrayList
$ArqDownloads = Join-Path $Pasta 'downloads.json'

function Get-PastasVigiadas {
    $dl = $null
    try { $dl = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop).'{374DE290-123F-4565-9164-39C4925E467B}') } catch { }
    if (-not $dl -or -not (Test-Path $dl)) { $dl = Join-Path $env:USERPROFILE 'Downloads' }
    $lista = @(@{ Pasta = $dl; SoComMarca = $false })
    foreach ($p in [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('MyDocuments')) {
        if ($p -and (Test-Path $p) -and $p -ne $dl) { $lista += @{ Pasta = $p; SoComMarca = $true } }
    }
    return $lista
}

function Start-VigiaDownloads {
    $i = 0
    foreach ($v in Get-PastasVigiadas) {
        try {
            $w = New-Object System.IO.FileSystemWatcher $v.Pasta
            $w.IncludeSubdirectories = $true
            $w.NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite, Size'
            $w.InternalBufferSize = 65536
            # Em Área de Trabalho/Documentos (muitas vezes no OneDrive) só criação/renomeação: a sincronização
            # gera "alterações" o tempo todo e não indica download novo.
            $eventos = @('Created', 'Renamed'); if (-not $v.SoComMarca) { $eventos += 'Changed' }
            foreach ($ev in $eventos) {
                Register-ObjectEvent -InputObject $w -EventName $ev -SourceIdentifier "GuardiaoDL_$($i)_$ev" -MessageData $v.SoComMarca | Out-Null
            }
            $w.EnableRaisingEvents = $true
            $script:Vigias += $w; $i++
        } catch { Write-Log 'INFO' "Nao foi possivel vigiar $($v.Pasta): $_" }
    }
    if (Test-Path $ArqDownloads) {
        try {
            $salvos = Get-Content $ArqDownloads -Raw -Encoding UTF8 | ConvertFrom-Json   # ver nota em Get-Quarentena
            foreach ($d in @($salvos)) { if ($d -and $d.nome) { [void]$script:DownloadsRecentes.Add($d) } }
        } catch { }
    }
    Write-Log 'INFO' ("Verificacao automatica de downloads ativa em: " + ((Get-PastasVigiadas | ForEach-Object { $_.Pasta }) -join ', '))
}

function Stop-VigiaDownloads {
    Get-EventSubscriber -ErrorAction SilentlyContinue | Where-Object SourceIdentifier -like 'GuardiaoDL_*' | Unregister-Event -ErrorAction SilentlyContinue
    foreach ($w in $script:Vigias) { try { $w.EnableRaisingEvents = $false; $w.Dispose() } catch { } }
}

function Get-MarcaDownload([string]$Arq) {
    # Lê a "marca da web" (Zone.Identifier) que navegadores gravam em arquivos baixados
    try {
        $z = Get-Content -LiteralPath $Arq -Stream Zone.Identifier -ErrorAction Stop
        $zona = 0; $origem = ''
        foreach ($l in $z) {
            if ($l -match '^ZoneId=(\d)') { $zona = [int]$Matches[1] }
            if ($l -match '^HostUrl=(https?://[^/\s]+)') { $origem = $Matches[1] -replace '^https?://', '' }
            elseif (-not $origem -and $l -match '^ReferrerUrl=(https?://[^/\s]+)') { $origem = $Matches[1] -replace '^https?://', '' }
        }
        return @{ Zona = $zona; Origem = $origem }
    } catch { return $null }
}

function Add-DownloadRecente($Item) {
    # Um registro por arquivo: se o mesmo arquivo foi avaliado de novo há pouco, o resultado novo substitui o antigo
    $limite = (Get-Date).AddMinutes(-30).ToString('yyyy-MM-dd HH:mm:ss')
    for ($i = $script:DownloadsRecentes.Count - 1; $i -ge 0; $i--) {
        $r = $script:DownloadsRecentes[$i]
        if ("$($r.caminho)" -eq "$($Item.caminho)" -and "$($r.quando)" -ge $limite) { $script:DownloadsRecentes.RemoveAt($i) }
    }
    [void]$script:DownloadsRecentes.Insert(0, $Item)
    while ($script:DownloadsRecentes.Count -gt 40) { $script:DownloadsRecentes.RemoveAt($script:DownloadsRecentes.Count - 1) }
    try { ConvertTo-Json -InputObject @($script:DownloadsRecentes) -Depth 3 | Set-Content $ArqDownloads -Encoding UTF8 } catch { }
}

# ------------- Regras próprias contra truques de golpe (funcionam sem internet) -------------
$CaracteresInvisiveis = @(0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x200E, 0x200F, 0x2066, 0x2067, 0x2068, 0x2069) | ForEach-Object { [char]$_ }
$ExtIsolarSempre = @('.scr', '.pif', '.cpl')                                       # quase nunca legítimos vindos da internet
$ExtGolpe        = @('.js', '.jse', '.vbs', '.vbe', '.wsf', '.wsh', '.hta', '.lnk', '.jar', '.reg', '.chm')   # comuns em golpes
$ExtImagemDisco  = @('.iso', '.img', '.vhd', '.vhdx')

function Get-RegraGolpe([string]$Arq, [string]$Nome) {
    # Devolve $null ou @{ Nivel = 'isolar'|'alertar'; Motivo }
    foreach ($c in $CaracteresInvisiveis) {
        if ($Nome.Contains($c)) { return @{ Nivel = 'isolar'; Motivo = 'nome com caractere invisível que inverte o texto para disfarçar a extensão real' } }
    }
    if ($Nome -match '(?i)\.(pdf|docx?|xlsx?|pptx?|txt|rtf|odt|csv|jpe?g|png|gif|bmp|webp|mp3|mp4|avi|mkv|mov|zip|rar|7z)[\s._-]*\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|lnk|msi|ps1|cpl|jar)$') {
        return @{ Nivel = 'isolar'; Motivo = "extensão falsa: parece .$($Matches[1].ToLower()), mas na verdade é um programa (.$($Matches[2].ToLower()))" } }
    if ($Nome -match '\s{3,}\.[^.\s]+$') { return @{ Nivel = 'isolar'; Motivo = 'muitos espaços antes da extensão para escondê-la' } }
    $ext = [IO.Path]::GetExtension($Nome).ToLower()
    if ($ExtIsolarSempre -contains $ext) { return @{ Nivel = 'isolar'; Motivo = "arquivo $ext vindo da internet: quase sempre é vírus" } }
    if ($ExtGolpe -contains $ext) { return @{ Nivel = 'alertar'; Motivo = "tipo de arquivo ($ext) muito usado em golpes: não abra se não estava esperando" } }
    if ($ExtImagemDisco -contains $ext) { return @{ Nivel = 'alertar'; Motivo = 'imagem de disco: golpistas usam para escapar da proteção do Windows; confira o conteúdo antes de abrir' } }
    if ($ext -eq '.zip') {
        try {
            $fs = [IO.File]::Open($Arq, 'Open', 'Read', 'ReadWrite'); $b = New-Object byte[] 8; [void]$fs.Read($b, 0, 8); $fs.Close()
            if ($b[0] -eq 0x50 -and $b[1] -eq 0x4B -and $b[2] -eq 3 -and $b[3] -eq 4 -and ($b[6] -band 1)) {
                return @{ Nivel = 'alertar'; Motivo = 'ZIP protegido por senha: o antivírus não consegue olhar dentro (truque comum para esconder vírus)' } }
        } catch { }
    }
    return $null
}

function Lock-ArquivoBaixado([string]$Arq, [string]$Motivo) {
    # Move o arquivo para a quarentena (pasta só de Administradores). Liberar devolve; Apagar exclui.
    if ($SomenteAlertar) { Test-Alerta 'Download suspeito' ([IO.Path]::GetFileName($Arq)) $Motivo; return $false }
    $dir = Join-Path $Pasta 'quarentena-arquivos'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $nomeSeguro = [IO.Path]::GetFileName($Arq); foreach ($c in $CaracteresInvisiveis) { $nomeSeguro = $nomeSeguro.Replace([string]$c, '') }
    $guardado = Join-Path $dir ('{0}__{1}.bloqueado' -f [guid]::NewGuid().ToString('N').Substring(0, 8), $nomeSeguro)
    try { Move-Item -LiteralPath $Arq -Destination $guardado -Force -ErrorAction Stop }
    catch { Test-Alerta 'Download suspeito' $nomeSeguro "$Motivo (nao foi possivel isolar: $($_.Exception.Message))"; return $false }
    Add-Quarentena 'Arquivo' $Arq $Motivo @{ Original = $Arq; Guardado = $guardado }
    return $true
}

function Test-DetectadoPeloDefender([string]$Arq, [datetime]$Desde) {
    try {
        $alvo = [regex]::Escape($Arq)
        return [bool](Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $Desde.AddMinutes(-1) -and ((@($_.Resources) -join ' ') -match "$alvo(\s|$|,)") } | Select-Object -First 1)
    } catch { return $false }
}

# ---------- Ameaças que o Defender detecta também viram DECISÕES no painel (liberar ou apagar) ----------
# Antes elas só apareciam como "neutralizada" na aba Defender: decidir exigia abrir a Segurança do Windows.
function Get-ArquivosDeteccao($Det) {
    @(@($Det.Resources) | Where-Object { "$_" -like 'file:_*' } | ForEach-Object { "$_".Substring(6) })
}
function Get-TextoStatusDefender([int]$Status) {
    switch ($Status) {
        2       { 'limpou o arquivo' }
        3       { 'colocou o arquivo na quarentena dele' }
        4       { 'removeu o arquivo' }
        6       { 'bloqueou o arquivo' }
        { $_ -in 102, 103, 107 } { 'tentou neutralizar e FALHOU: ameaça ATIVA' }
        default { 'ainda NÃO neutralizou: ameaça ATIVA' }
    }
}
function Sync-DecisoesDefender {
    # Detecções com arquivo dos últimos 7 dias que ainda não viraram decisão (uma por ameaça + arquivo)
    $corte = (Get-Date).AddDays(-7)
    if (Test-Path $ArqAmeacasOcultas) { try { $c = [datetime]::ParseExact((Get-Content $ArqAmeacasOcultas -Raw).Trim(), 'yyyy-MM-dd HH:mm:ss', $null); if ($c -gt $corte) { $corte = $c } } catch { } }
    $dets = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt $corte -and [int]$_.ThreatStatusID -ne 5 -and @(Get-ArquivosDeteccao $_).Count })
    if (-not $dets.Count) { return 0 }
    $itens = @(Get-Quarentena)
    $conhecidos = @{}
    foreach ($i in @($itens | Where-Object Tipo -eq 'Ameaca')) { foreach ($x in @($i.Desfazer.Deteccoes)) { $conhecidos["$x"] = $true } }
    $novos = @($dets | Where-Object { -not $conhecidos["$($_.DetectionID)"] })
    if (-not $novos.Count) { return 0 }
    $nomes = @{}; Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $nomes["$($_.ThreatID)"] = "$($_.ThreatName)" }
    $criados = 0
    foreach ($g in @($novos | Group-Object { "$($_.ThreatID)|" + ((Get-ArquivosDeteccao $_) -join ', ') })) {
        $ids = @($g.Group | ForEach-Object { "$($_.DetectionID)" })
        $pend = @($itens | Where-Object { $_.Tipo -eq 'Ameaca' -and $_.Estado -eq 'ISOLADO' -and "$($_.Desfazer.Chave)" -eq $g.Name })
        if ($pend.Count) { $pend[0].Desfazer.Deteccoes = @(@($pend[0].Desfazer.Deteccoes) + $ids); continue }   # mesma ameaça, mesmo arquivo
        $ult = $g.Group | Sort-Object InitialDetectionTime -Descending | Select-Object -First 1
        $nome = $nomes["$($ult.ThreatID)"]; if (-not $nome) { $nome = "ameaca $($ult.ThreatID)" }
        $arqs = @(Get-ArquivosDeteccao $ult)
        $id = 1; if ($itens.Count) { $id = ([int]($itens | Measure-Object Id -Maximum).Maximum) + 1 }
        $motivo = "O Windows Defender detectou $nome e $(Get-TextoStatusDefender ([int]$ult.ThreatStatusID))"
        $itens += [pscustomobject]@{
            Id = $id; Tipo = 'Ameaca'; Alvo = ($arqs -join ', '); Motivo = $motivo
            Quando = $ult.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm:ss'); Estado = 'ISOLADO'
            Desfazer = @{ ThreatID = "$($ult.ThreatID)"; Nome = $nome; Arquivos = $arqs; Deteccoes = $ids; Chave = $g.Name; Status = [int]$ult.ThreatStatusID }
        }
        Write-Log 'ISOLADO' "#$id [Ameaca] $($arqs -join ', ') - $motivo"
        $criados++
    }
    Save-Quarentena $itens
    if ($criados) { Show-Alerta 'WebGuardian: decisao pendente' "O Defender detectou $criados ameaca(s). Decida no WebGuardian, aba Decisoes: liberar (era seguro) ou apagar." }
    return $criados
}

# --------------------- Base de assinaturas do Defender sempre atualizada ---------------------
$script:AtualizacaoDef = $null
$script:ProximaAtualizacaoDef = (Get-Date).AddMinutes(2)

function Start-AtualizacaoDefender([string]$Motivo) {
    $a = $script:AtualizacaoDef
    if ($a -and -not $a.Fim) { return 'A base do Defender ja esta sendo atualizada.' }
    $outro = Get-AntivirusSubstituto
    if ($outro) { return "O antivírus ativo deste PC é o $outro, que atualiza a própria base sozinho. A base do Defender fica parada enquanto ele estiver ligado." }
    $antes = ''; try { $antes = (Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureVersion } catch { }
    try { $p = Start-Process -FilePath $MpCmdRun -ArgumentList '-SignatureUpdate' -WindowStyle Hidden -PassThru -ErrorAction Stop }
    catch { Write-Log 'ALERTA' "Nao foi possivel atualizar a base do Defender: $_"; return 'Nao foi possivel iniciar a atualizacao da base do Defender.' }
    $script:AtualizacaoDef = @{ Processo = $p; Inicio = Get-Date; Motivo = $Motivo; Antes = $antes; Fim = $null }
    Write-Log 'INFO' "Atualizando a base de assinaturas do Defender ($Motivo)"
    return 'Atualizando a base de assinaturas do Defender. Leva de alguns segundos a poucos minutos.'
}

function Step-AtualizacaoDefender {
    $a = $script:AtualizacaoDef
    if ($a -and -not $a.Fim -and ($a.Processo.HasExited -or ((Get-Date) - $a.Inicio).TotalMinutes -gt 15)) {
        $a.Fim = Get-Date; $script:Cache.Remove('defender')
        $depois = ''; try { $depois = (Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureVersion } catch { }
        $cod = -1; if ($a.Processo.HasExited) { $cod = $a.Processo.ExitCode }
        if ($cod -eq 0) {
            if ($depois -and $depois -ne $a.Antes) { Write-Log 'INFO' "Base do Defender atualizada: versao $($a.Antes) -> $depois" }
            else { Write-Log 'INFO' "Base do Defender ja estava em dia (versao $depois)" }
        } else { Write-Log 'ALERTA' "Atualizacao da base do Defender falhou (codigo $cod). Sem internet? Tentarei de novo em 30 min."; $script:ProximaAtualizacaoDef = (Get-Date).AddMinutes(30) }
    }
    if ((Get-Date) -ge $script:ProximaAtualizacaoDef) {
        $script:ProximaAtualizacaoDef = (Get-Date).AddHours(3)
        if (-not (Get-AntivirusSubstituto)) { Start-AtualizacaoDefender 'automatica, a cada 3 horas' | Out-Null }   # com outro antivírus: ele cuida da base dele
    }
}

function Test-BaseDefenderVelha {
    # Base com mais de 3 horas? (atualiza antes de confiar só nela para um programa baixado)
    try { return ((Get-Date) - (Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureLastUpdated).TotalHours -gt 3 } catch { return $false }
}

# ------------- Outro antivírus no PC (Avast, AVG, Norton, Kaspersky, McAfee, ESET...) -------------
# Quando outro antivírus está ligado, o PRÓPRIO Windows desliga a proteção em tempo real do Defender.
# Isso é normal e não é ataque: o WebGuardian passa a tratar o outro antivírus como a proteção do PC.
function ConvertFrom-EstadoAntivirus([int]$Estado) {
    # productState da Central de Segurança: 2º byte = ligado (0x10/0x11), 3º byte = base em dia (0x00)
    $hex = '{0:X6}' -f $Estado
    return @{ Ligado = (@('10', '11') -contains $hex.Substring(2, 2)); EmDia = ($hex.Substring(4, 2) -eq '00') }
}
function Get-AntivirusRegistrados {
    $lista = @()
    try {
        foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
            $e = ConvertFrom-EstadoAntivirus ([int]$p.productState)
            $lista += [pscustomobject]@{ Nome = "$($p.displayName)"; Ligado = $e.Ligado; EmDia = $e.EmDia
                                         Microsoft = ("$($p.displayName)" -match 'Windows Defender|Microsoft Defender') }
        }
    } catch { }
    return $lista
}
function Get-OutroAntivirus {
    # Antivírus de outra empresa registrado no Windows (o ligado primeiro), ou $null. Consulta a cada 60 s.
    $c = $script:OutroAV
    if ($c -and ((Get-Date) - $c.Quando).TotalSeconds -lt 60) { return $c.Valor }
    $outros = @(Get-AntivirusRegistrados | Where-Object { -not $_.Microsoft } | Sort-Object @{ Expression = 'Ligado'; Descending = $true })
    $v = $null; if ($outros.Count) { $v = $outros[0] }
    $script:OutroAV = @{ Quando = Get-Date; Valor = $v }
    return $v
}
function Test-DefenderAtivo {
    try { $st = Get-MpComputerStatus -ErrorAction Stop; return ([bool]$st.RealTimeProtectionEnabled -and [bool]$st.AntivirusEnabled) } catch { return $false }
}
function Get-AntivirusSubstituto {
    # Nome do outro antivírus quando ELE é a proteção ativa (Defender desligado por causa dele); senão $null
    $o = Get-OutroAntivirus
    if ($o -and $o.Ligado -and -not (Test-DefenderAtivo)) { return $o.Nome }
    return $null
}

function Step-Downloads {
    # 1) eventos do Windows -> fila (espera o arquivo parar de crescer)
    foreach ($e in @(Get-Event -ErrorAction SilentlyContinue | Where-Object SourceIdentifier -like 'GuardiaoDL_*')) {
        $arq = "$($e.SourceEventArgs.FullPath)"; $soMarca = [bool]$e.MessageData
        Remove-Event -EventIdentifier $e.EventIdentifier -ErrorAction SilentlyContinue
        if (-not $arq -or $script:FilaDownloads.ContainsKey($arq)) { continue }
        $ext = [IO.Path]::GetExtension($arq).ToLower()
        if ($ExtTemporarias -contains $ext -or [IO.Path]::GetFileName($arq) -like '~$*') { continue }
        $script:FilaDownloads[$arq] = @{ SoComMarca = $soMarca; Tamanho = -1; Gravado = 0; Estavel = $null; Desde = Get-Date }
    }
    # 2) arquivos estáveis -> regras contra golpes -> Defender (no máximo 2 verificações ao mesmo tempo)
    foreach ($arq in @($script:FilaDownloads.Keys)) {
        $f = $script:FilaDownloads[$arq]
        if (((Get-Date) - $f.Desde).TotalMinutes -gt 30) { $script:FilaDownloads.Remove($arq); continue }   # nunca terminou
        $item = Get-Item -LiteralPath $arq -ErrorAction SilentlyContinue
        if (-not $item) {
            # Sumiu antes de terminar: o Defender pode tê-lo bloqueado em tempo real (registra; senão ignora)
            $script:FilaDownloads.Remove($arq)
            $nm = [IO.Path]::GetFileName($arq)
            if (-not $f.SoComMarca -and (Test-DetectadoPeloDefender $arq $f.Desde.AddMinutes(-5))) {
                Write-Log 'CRITICO' "Download com AMEACA bloqueado pelo Defender em tempo real: $nm"
                Show-Alerta 'WebGuardian: download perigoso' "$nm`nO Defender bloqueou o arquivo assim que ele foi gravado."
                Add-DownloadRecente @{ quando = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); nome = $nm; caminho = $arq; origem = ''; tamanho = [int64]0
                                       resultado = 'ameaca'; detalhe = 'Bloqueado pelo Defender em tempo real, assim que foi gravado' }
            } elseif (-not $f.SoComMarca -and ($ExtExecutaveis -contains [IO.Path]::GetExtension($arq).ToLower()) -and ($outroAv = Get-AntivirusSubstituto)) {
                # Com outro antivírus não dá para consultar as detecções dele: um programa que some logo depois de
                # baixado quase sempre foi bloqueado por ele (o WebGuardian registra, sem afirmar o motivo)
                Write-Log 'ALERTA' "[Download] $nm sumiu logo depois de baixado: provavelmente o $outroAv bloqueou ou mandou para a quarentena dele"
                Add-DownloadRecente @{ quando = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); nome = $nm; caminho = $arq; origem = ''; tamanho = [int64]0
                                       resultado = 'removido'; detalhe = "Sumiu logo depois de baixado: provavelmente bloqueado pelo $outroAv (veja a quarentena dele)" }
            }
            continue
        }
        if ($item.PSIsContainer) { $script:FilaDownloads.Remove($arq); continue }
        # Arquivo "só na nuvem" (OneDrive etc.): não é download novo e NUNCA deve ser aberto
        # (abrir faria o Windows baixá-lo da nuvem e travaria o monitor).
        # 0x400000 = recall on data access, 0x40000 = recall on open, 0x1000 = offline
        if (([int64]$item.Attributes -band 0x441000) -ne 0) { $script:FilaDownloads.Remove($arq); continue }
        # Download terminou quando o tamanho e a data param de mudar por 3 s (sem abrir o arquivo)
        $marcaTempo = $item.LastWriteTimeUtc.Ticks
        if ($item.Length -ne $f.Tamanho -or $marcaTempo -ne $f.Gravado) { $f.Tamanho = $item.Length; $f.Gravado = $marcaTempo; $f.Estavel = Get-Date; continue }
        if (((Get-Date) - $f.Estavel).TotalSeconds -lt 3) { continue }
        if (@($script:ScansDownload).Count -ge 2) { break }
        $script:FilaDownloads.Remove($arq)
        $chave = "$arq|$($item.Length)|$($item.LastWriteTimeUtc.Ticks)"
        if ($script:DownloadsVistos.ContainsKey($chave)) { continue }
        $marca = Get-MarcaDownload $arq
        if ($f.SoComMarca -and (-not $marca -or $marca.Zona -lt 3)) { continue }   # fora de Downloads: só o que veio da internet
        $script:DownloadsVistos[$chave] = $true
        $origem = ''; if ($marca) { $origem = $marca.Origem }
        $deOnde = ''; if ($origem) { $deOnde = " (baixado de $origem)" }

        # Regras contra golpes ANTES de qualquer coisa: truques graves vão direto para a quarentena
        $regra = Get-RegraGolpe $arq $item.Name
        if ($regra -and $regra.Nivel -eq 'isolar') {
            Write-Log 'ALERTA' "[Download] $($item.Name)$deOnde - $($regra.Motivo)"
            $isolou = Lock-ArquivoBaixado $arq "Download suspeito$deOnde`: $($regra.Motivo)"
            $res = 'isolado'; if (-not $isolou) { $res = 'suspeito' }
            Add-DownloadRecente @{ quando = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); nome = $item.Name; caminho = $arq; origem = $origem
                                   tamanho = [int64]$item.Length; resultado = $res; detalhe = $regra.Motivo }
            continue
        }
        $p = $null
        $outroAv = Get-AntivirusSubstituto
        if (-not $outroAv) {
            # Programa baixado com a base do Defender velha: pede atualização (a verificação segue já)
            if (($ExtExecutaveis -contains [IO.Path]::GetExtension($arq).ToLower()) -and (Test-BaseDefenderVelha)) { Start-AtualizacaoDefender 'programa baixado com a base desatualizada' | Out-Null }
            # Verificação do arquivo pelo Defender (se achar ameaça, o próprio Defender bloqueia/remove)
            try { $p = Start-Process -FilePath $MpCmdRun -ArgumentList @('-Scan', '-ScanType', '3', '-File', "`"$arq`"") -WindowStyle Hidden -PassThru -ErrorAction Stop }
            catch { Write-Log 'INFO' "Nao foi possivel chamar o Defender para $($item.Name): $_" }
        }
        # Com outro antivírus ligado o Windows desliga o Defender: o WebGuardian pede ao OUTRO antivírus que confira
        # o arquivo (AMSI), em segundo plano. Regras contra golpes e assinatura digital continuam valendo.
        $tarefa = $null
        if ($outroAv -and (Test-AmsiOutroAntivirus)) { try { $tarefa = [Guardiao.Varredor]::VerificarAsync($arq, 64) } catch { } }
        $script:CacheEditor.Remove($arq)
        $script:ScansDownload += @{ Arquivo = $arq; Nome = $item.Name; Tamanho = $item.Length; Origem = $origem; Processo = $p; Inicio = Get-Date; Regra = $regra; Criado = $item.CreationTime; OutroAV = $outroAv; Tarefa = $tarefa }
    }
    # 3) verificações terminadas -> resultado
    $ainda = @()
    foreach ($s in @($script:ScansDownload | Where-Object { $_ })) {
        if ($s.Processo -and -not $s.Processo.HasExited -and ((Get-Date) - $s.Inicio).TotalMinutes -lt 20) { $ainda += $s; continue }
        if ($s.Tarefa -and -not $s.Tarefa.IsCompleted -and ((Get-Date) - $s.Inicio).TotalMinutes -lt 20) { $ainda += $s; continue }
        $codigo = -1; if ($s.Processo -and $s.Processo.HasExited) { $codigo = $s.Processo.ExitCode }
        $existe = Test-Path -LiteralPath $s.Arquivo
        $deOnde = ''; if ($s.Origem) { $deOnde = " (baixado de $($s.Origem))" }
        $ext = [IO.Path]::GetExtension($s.Arquivo).ToLower()
        $res = 'limpo'; $det = 'Nenhuma ameaca encontrada pelo Defender'
        $av = $s.OutroAV; $quemVerifica = 'Defender'; $estadoAv = ''
        if ($av) {
            $codigo = 0; $quemVerifica = $av
            $estadoAv = 'indisponivel'
            if ($s.Tarefa -and $s.Tarefa.IsCompleted -and -not $s.Tarefa.IsFaulted) { $estadoAv = "$($s.Tarefa.Result)" }
            if ($estadoAv -eq 'limpo') {
                # o outro antivírus conferiu o arquivo a pedido do WebGuardian e não achou ameaça
                $res = 'limpo'; $det = "Nenhuma ameaça encontrada pelo $av"
            } else {
                # grande demais / sem AMSI: só a proteção em tempo real dele (sem afirmar "limpo")
                $res = 'outro-av'; $det = "Não bloqueado pelo $av, o antivírus ativo deste PC (ele confere o arquivo ao gravar e ao abrir)"
            }
        }
        if ($av -and $estadoAv -eq 'ameaca') {
            # O outro antivírus apontou ameaça: o WebGuardian isola o arquivo até você decidir
            $nmA = $s.Nome
            $isolou = $false; if (Test-Path -LiteralPath $s.Arquivo) { $isolou = Lock-ArquivoBaixado $s.Arquivo "O $av encontrou uma ameaca neste download$deOnde" }
            Write-Log 'CRITICO' "Download com AMEACA encontrada pelo ${av}: $nmA$deOnde"
            Show-Alerta 'WebGuardian: download perigoso' "$nmA$deOnde`nO $av encontrou uma ameaça. $(if ($isolou) { 'O WebGuardian isolou o arquivo.' } else { '' })"
            $r1 = 'ameaca'; $d1 = "O $av encontrou uma ameaça"; if ($isolou) { $r1 = 'isolado'; $d1 = "O $av encontrou uma ameaça; o WebGuardian isolou o arquivo (aba Decisões)" }
            Add-DownloadRecente @{ quando = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); nome = $nmA; caminho = $s.Arquivo; origem = $s.Origem; tamanho = [int64]$s.Tamanho; resultado = $r1; detalhe = $d1 }
            continue
        }
        if ($av -and $estadoAv -eq 'bloqueado') {
            Write-Log 'CRITICO' "Download com AMEACA bloqueado pelo ${av}: $($s.Nome)$deOnde"
            Show-Alerta 'WebGuardian: download perigoso' "$($s.Nome)$deOnde`nO $av bloqueou o arquivo."
            Add-DownloadRecente @{ quando = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); nome = $s.Nome; caminho = $s.Arquivo; origem = $s.Origem; tamanho = [int64]$s.Tamanho; resultado = 'ameaca'; detalhe = "O $av bloqueou o arquivo" }
            continue
        }
        # Ameaça se a verificação achou, OU se a proteção em tempo real do Defender já detectou este arquivo desde que ele
        # foi criado (nesse caso a verificação manual pode responder "nada encontrado" porque o Defender já está cuidando dele)
        $desdeCriacao = $s.Inicio; if ($s.Criado -and $s.Criado -lt $s.Inicio) { $desdeCriacao = $s.Criado }
        $ameaca = (-not $av) -and (($codigo -eq 2) -or (Test-DetectadoPeloDefender $s.Arquivo $desdeCriacao))
        if ($ameaca) {
            $res = 'ameaca'; $det = 'O Defender encontrou uma ameaca e bloqueou o arquivo'
            Write-Log 'CRITICO' "Download com AMEACA bloqueado pelo Defender: $($s.Nome)$deOnde"
            Show-Alerta 'WebGuardian: download perigoso' "$($s.Nome)$deOnde`nO Defender bloqueou o arquivo."
        } elseif (-not $existe) {
            $res = 'removido'; $det = 'O arquivo foi apagado ou movido antes de a verificação terminar'
            if ($av) { $det = "Sumiu logo depois de baixado: provavelmente bloqueado pelo $av (veja a quarentena dele)" }
            Write-Log 'INFO' "Download $($s.Nome)$deOnde - removido antes de terminar a verificacao"
        } elseif ($codigo -ne 0) {
            # O Defender não conseguiu verificar (desligado, ocupado, arquivo protegido...): nunca chamar de "limpo"
            $res = 'erro'; $det = "Nao foi possivel verificar com o Defender (codigo $codigo). Abra com cuidado ou rode uma verificacao manual."
            Write-Log 'ALERTA' "[Download] $($s.Nome)$deOnde - NAO verificado pelo Defender (codigo $codigo)"
            Show-Alerta 'WebGuardian: download nao verificado' "$($s.Nome)$deOnde`nO Defender não conseguiu verificar este arquivo."
        } elseif ($s.Regra) {
            $res = 'suspeito'; $det = "$($s.Regra.Motivo). O Defender não achou ameaça conhecida."
            if ($av) { $det = "$($s.Regra.Motivo). O $av não bloqueou." }
            Write-Log 'ALERTA' "[Download] $($s.Nome)$deOnde - $($s.Regra.Motivo)"
            Show-Alerta 'WebGuardian: download suspeito' "$($s.Nome)$deOnde`nTipo de arquivo comum em golpes: não abra se não esperava."
        } elseif ($ExtExecutaveis -contains $ext) {
            $ed = Get-Editor $s.Arquivo
            if ($ed -eq 'microsoft' -or $ed -like 'assinado:*') {
                $quem = 'Microsoft'; if ($ed -like 'assinado:*') { $quem = $ed.Substring(9) }
                $det = "Instalador/programa assinado por $quem; sem ameacas"
                if ($av -and $res -eq 'limpo') { $det = "Instalador/programa assinado por $quem; nenhuma ameaça encontrada pelo $av" }
                elseif ($av) { $det = "Instalador/programa assinado por $quem; não bloqueado pelo $av" }
                Write-Log 'INFO' "Download verificado: $($s.Nome)$deOnde - $(if ($av) { "$res pelo $av" } else { 'limpo' }), assinado por $quem"
            } else {
                $res = 'sem-assinatura'; $det = 'Sem ameacas conhecidas, mas o programa NAO tem assinatura digital: so execute se confiar na origem'
                if ($av -and $estadoAv -eq 'limpo') { $det = "O $av não achou ameaça, mas o programa NÃO tem assinatura digital: só execute se confiar na origem" }
                elseif ($av) { $det = "O $av não bloqueou, mas o programa NÃO tem assinatura digital: só execute se confiar na origem" }
                Write-Log 'ALERTA' "[Download] $($s.Nome)$deOnde - programa SEM assinatura digital ($quemVerifica nao bloqueou)"
                Show-Alerta 'WebGuardian: programa sem assinatura' "$($s.Nome)$deOnde`nSó execute se confiar na origem."
            }
        } else {
            if ($av -and $res -eq 'limpo') { Write-Log 'INFO' "Download verificado: $($s.Nome)$deOnde - limpo pelo $av" }
            elseif ($av) { Write-Log 'INFO' "Download conferido: $($s.Nome)$deOnde - nao bloqueado pelo $av" }
            else { Write-Log 'INFO' "Download verificado: $($s.Nome)$deOnde - limpo" }
        }
        Add-DownloadRecente @{ quando = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); nome = $s.Nome; caminho = $s.Arquivo; origem = $s.Origem
                               tamanho = [int64]$s.Tamanho; resultado = $res; detalhe = $det }
    }
    $script:ScansDownload = $ainda
}

function Clear-DownloadsVerificados {
    $script:DownloadsRecentes.Clear()
    Remove-Item $ArqDownloads -ErrorAction SilentlyContinue
    Write-Log 'INFO' 'Lista de downloads verificados limpa pelo usuario'
    return 'Lista de downloads verificados limpa.'
}

function Get-DownloadsPainel {
    $lista = @()
    foreach ($s in @($script:ScansDownload | Where-Object { $_ })) {
        $lista += @{ quando = $s.Inicio.ToString('yyyy-MM-dd HH:mm:ss'); nome = $s.Nome; caminho = $s.Arquivo; origem = $s.Origem; tamanho = [int64]$s.Tamanho; resultado = 'verificando'; detalhe = $(if ($s.OutroAV) { "$($s.OutroAV) verificando agora" } else { 'Windows Defender verificando agora' }) }
    }
    foreach ($k in @($script:FilaDownloads.Keys)) {
        $lista += @{ quando = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); nome = [IO.Path]::GetFileName($k); caminho = $k; origem = ''; tamanho = [int64]0; resultado = 'baixando'; detalhe = 'Aguardando o download terminar' }
    }
    return @($lista + @($script:DownloadsRecentes | Select-Object -First 25))
}

# ===================== VERIFICAÇÃO RÁPIDA/COMPLETA COM PROGRESSO =====================
# O Defender não informa o progresso real. A porcentagem é ESTIMADA pelo tempo que a última
# verificação do mesmo tipo levou neste PC (ou, sem histórico, por um valor típico / tamanho do disco).
$script:Varredura = $null

function Get-DuracaoPrevista([string]$Tipo) {
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        $ini = $st.QuickScanStartTime; $fim = $st.QuickScanEndTime
        if ($Tipo -eq 'completa') { $ini = $st.FullScanStartTime; $fim = $st.FullScanEndTime }
        if ($ini -and $fim -and $fim -gt $ini) {
            $seg = ($fim - $ini).TotalSeconds
            if ($seg -ge 20 -and $seg -le 6 * 3600) { return @{ Segundos = [int]$seg; Base = 'ultima verificacao deste PC' } }
        }
    } catch { }
    if ($Tipo -eq 'rapida') { return @{ Segundos = 180; Base = 'tempo tipico' } }
    $gb = 0; try { $gb = (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { $_.Size - $_.FreeSpace } | Measure-Object -Sum).Sum / 1GB } catch { }
    return @{ Segundos = [int][Math]::Max(900, $gb * 15); Base = 'tamanho do disco' }
}

function Start-Varredura([string]$Tipo, [switch]$Auto) {
    $v = $script:Varredura
    if ($v -and -not $v.Fim) { $e = Get-EstadoVarredura; return "Ja existe uma verificacao $($v.Tipo) em andamento ($($e.pct)%)." }
    # Outro antivírus ligado (Avast etc.): o WebGuardian manda ELE conferir os arquivos, sem abrir a tela dele
    $outro = Get-AntivirusSubstituto
    if ($outro) { return (Start-VarreduraAntivirus $Tipo $outro -Auto:$Auto) }
    $prev = Get-DuracaoPrevista $Tipo
    $tipoMp = 'QuickScan'; if ($Tipo -eq 'completa') { $tipoMp = 'FullScan' }
    $job = Start-Job -ScriptBlock { param($t) Start-MpScan -ScanType $t } -ArgumentList $tipoMp
    $script:Varredura = @{ Tipo = $Tipo; Inicio = Get-Date; Previsto = $prev.Segundos; Base = $prev.Base; Job = $job; Fim = $null; Resultado = ''; Auto = [bool]$Auto }
    $script:JobScan = $job
    $comoTxt = ''; if ($Auto) { $comoTxt = ' (automatica diaria)' }
    Write-Log 'INFO' "Verificacao $Tipo do Defender iniciada$comoTxt (previsao: $([Math]::Ceiling($prev.Segundos / 60)) min, pela $($prev.Base))"
    return "Verificacao $Tipo iniciada. Previsao: cerca de $([Math]::Ceiling($prev.Segundos / 60)) min."
}

function Get-EstadoVarredura {
    $v = $script:Varredura
    if (-not $v) { return $null }
    if ($v.Motor) {
        # Verificação feita pelo outro antivírus via WebGuardian: porcentagem REAL (arquivos conferidos)
        $A = [Guardiao.VarreduraAv]
        if (-not $v.Fim -and $A::Fim) {
            $v.Fim = Get-Date
            try { Complete-VarreduraAntivirus $v } catch { $v.Resultado = "Concluida com erro ao tratar o resultado: $_" }
            Write-Log 'INFO' "Verificacao $($v.Tipo) pelo $($v.Motor) terminou em $([Math]::Round(($v.Fim - $v.Inicio).TotalMinutes, 1)) min. $($v.Resultado)"
        }
        $ate = Get-Date; if ($v.Fim) { $ate = $v.Fim }
        $dec = ($ate - $v.Inicio).TotalSeconds; $tot = [int]$A::Total; $feitos = [int]$A::Feitos
        $info = @{ tipo = $v.Tipo; motor = $v.Motor; decorrido = [int]$dec; estimado = $false; total = $tot; feitos = $feitos; auto = [bool]$v.Auto }
        if ($v.Fim) {
            if (((Get-Date) - $v.Fim).TotalMinutes -gt 3) { $script:Varredura = $null; return $null }
            return $info + @{ ativo = $false; pct = 100; restante = 0; listando = $false; base = "$tot arquivos conferidos pelo $($v.Motor)"; resultado = $v.Resultado }
        }
        $listando = [bool]$A::Listando; $pct = 0; $resta = 0
        if (-not $listando -and $tot -gt 0) {
            $pct = [int][Math]::Min(99, [Math]::Floor(100 * $feitos / $tot))
            if ($feitos -gt 0) { $resta = [int](($dec / $feitos) * ($tot - $feitos)) }
        }
        $base = "$feitos de $tot arquivos conferidos pelo $($v.Motor)"; if ($listando) { $base = "listando arquivos ($tot ate agora)" }
        return $info + @{ ativo = $true; pct = $pct; restante = $resta; listando = $listando; finalizando = $false; base = $base; resultado = '' }
    }
    if (-not $v.Fim -and $v.Job.State -ne 'Running' -and $v.Job.State -ne 'NotStarted') {
        $v.Fim = Get-Date
        $novas = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $v.Inicio }).Count
        if ($v.Job.State -eq 'Failed') { $v.Resultado = 'A verificacao nao terminou (o Defender recusou ou foi interrompido).' }
        elseif ($novas) {
            $v.Resultado = "Concluida: $novas ameaca(s) encontrada(s). Veja a aba Defender."; Write-Log 'CRITICO' "Verificacao $($v.Tipo) encontrou $novas ameaca(s)"
            Show-Alerta 'WebGuardian: ameaca encontrada' "A verificacao $($v.Tipo) do Defender encontrou $novas ameaca(s)."
        }
        else { $v.Resultado = 'Concluida: nenhuma ameaca encontrada.' }
        Write-Log 'INFO' "Verificacao $($v.Tipo) terminou em $([Math]::Round(($v.Fim - $v.Inicio).TotalMinutes, 1)) min. $($v.Resultado)"
        Remove-Job $v.Job -Force -ErrorAction SilentlyContinue
    }
    $ate = Get-Date; if ($v.Fim) { $ate = $v.Fim }
    $decorrido = ($ate - $v.Inicio).TotalSeconds
    if ($v.Fim) {
        if (((Get-Date) - $v.Fim).TotalMinutes -gt 3) { $script:Varredura = $null; return $null }   # resultado fica 3 min na tela
        return @{ ativo = $false; tipo = $v.Tipo; pct = 100; decorrido = [int]$decorrido; restante = 0; estimado = $false; base = $v.Base; resultado = $v.Resultado }
    }
    $pct = [int][Math]::Floor(100 * $decorrido / [Math]::Max(1, $v.Previsto))
    $final = $pct -ge 99; if ($pct -gt 99) { $pct = 99 }
    return @{ ativo = $true; tipo = $v.Tipo; pct = $pct; decorrido = [int]$decorrido; restante = [int][Math]::Max(0, $v.Previsto - $decorrido)
              estimado = $true; finalizando = $final; base = $v.Base; resultado = '' }
}

# ============ VERIFICAÇÃO PELO ANTIVÍRUS ATIVO (Avast, AVG, Kaspersky... ou o próprio Defender) ============
# O WebGuardian pede ao antivírus ativo do PC que confira cada arquivo pela interface oficial do Windows para
# isso (AMSI). Assim downloads e verificações rápida/completa funcionam com qualquer antivírus compatível,
# sem precisar abrir a tela dele. A porcentagem aqui é REAL (arquivos conferidos / total).
if (-not ('Guardiao.Varredor' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Guardiao {
    public static class Varredor {
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)] static extern int AmsiInitialize(string appName, out IntPtr ctx);
        [DllImport("amsi.dll")] static extern void AmsiUninitialize(IntPtr ctx);
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)] static extern int AmsiScanBuffer(IntPtr ctx, byte[] buffer, uint length, string contentName, IntPtr session, out int result);

        public static bool Disponivel() {
            IntPtr ctx;
            try { if (AmsiInitialize("WebGuardian", out ctx) != 0 || ctx == IntPtr.Zero) return false; AmsiUninitialize(ctx); return true; }
            catch { return false; }
        }

        // "limpo", "ameaca", "bloqueado" (o Windows recusou abrir: o antivírus pegou), "sumiu", "grande" (acima do
        // limite: só a proteção em tempo real confere), "indisponivel" (sem AMSI) ou "erro:<mensagem>"
        public static string Verificar(string caminho, int limiteMB) {
            byte[] dados;
            try {
                var info = new FileInfo(caminho);
                if (!info.Exists) return "sumiu";
                if (info.Length > (long)limiteMB * 1024 * 1024) {
                    using (var fs = new FileStream(caminho, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) { fs.ReadByte(); }
                    return "grande";
                }
                using (var fs = new FileStream(caminho, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
                    dados = new byte[fs.Length]; int lidos = 0, n;
                    while (lidos < dados.Length && (n = fs.Read(dados, lidos, dados.Length - lidos)) > 0) lidos += n;
                }
            } catch (FileNotFoundException) { return "sumiu"; }
            catch (IOException e) {
                int cod = e.HResult & 0xFFFF;
                if (cod == 225 || cod == 226) return "bloqueado";   // ERROR_VIRUS_INFECTED / ERROR_VIRUS_DELETED
                return File.Exists(caminho) ? "erro:" + e.Message : "sumiu";
            } catch (UnauthorizedAccessException e) { return File.Exists(caminho) ? "erro:" + e.Message : "sumiu"; }
            catch (Exception e) { return "erro:" + e.Message; }
            return Conferir(dados, Path.GetFileName(caminho));
        }

        public static string Conferir(byte[] dados, string nome) {
            IntPtr ctx;
            try { if (AmsiInitialize("WebGuardian", out ctx) != 0 || ctx == IntPtr.Zero) return "indisponivel"; }
            catch { return "indisponivel"; }
            try {
                int res;
                if (AmsiScanBuffer(ctx, dados, (uint)dados.Length, nome, IntPtr.Zero, out res) != 0) return "indisponivel";
                if (res >= 32768) return "ameaca";                       // AMSI_RESULT_DETECTED
                if (res >= 16384 && res <= 20479) return "ameaca";       // bloqueado pela política do antivírus
                return "limpo";
            } finally { AmsiUninitialize(ctx); }
        }

        public static Task<string> VerificarAsync(string caminho, int limiteMB) {
            return Task.Run(() => Verificar(caminho, limiteMB));
        }
    }

    // Verificação rápida/completa em segundo plano: lista os arquivos e manda o antivírus conferir um por um
    public static class VarreduraAv {
        public static volatile int Total, Feitos;
        public static volatile bool Fim = true, Listando;
        static readonly List<string> encontrados = new List<string>();
        static readonly object trava = new object();

        public static string[] Encontrados() { lock (trava) { return encontrados.ToArray(); } }

        public static void Iniciar(string[] pastas, string[] arquivos, string[] extensoes, string[] ignorar, int limiteMB) {
            lock (trava) { encontrados.Clear(); }
            Total = 0; Feitos = 0; Listando = true; Fim = false;
            var t = new Thread(() => Rodar(pastas, arquivos, extensoes, ignorar, limiteMB));
            t.IsBackground = true; t.Priority = ThreadPriority.BelowNormal; t.Start();
        }

        static void Rodar(string[] pastas, string[] arquivos, string[] extensoes, string[] ignorar, int limiteMB) {
            try {
                var exts = new HashSet<string>(extensoes, StringComparer.OrdinalIgnoreCase);
                var lista = new List<string>(); var vistos = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var a in arquivos) if (!string.IsNullOrEmpty(a) && File.Exists(a) && vistos.Add(a)) lista.Add(a);
                var pilha = new Stack<string>();
                foreach (var p in pastas) if (!string.IsNullOrEmpty(p) && Directory.Exists(p)) pilha.Push(p);
                while (pilha.Count > 0) {
                    var dir = pilha.Pop();
                    bool pular = false;
                    foreach (var ig in ignorar) if (dir.IndexOf(ig, StringComparison.OrdinalIgnoreCase) >= 0) { pular = true; break; }
                    if (pular) continue;
                    try {
                        foreach (var sub in Directory.GetDirectories(dir)) {
                            try { if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) == 0) pilha.Push(sub); } catch { }
                        }
                        foreach (var f in Directory.GetFiles(dir)) {
                            if (exts.Count > 0 && !exts.Contains(Path.GetExtension(f))) continue;
                            try { if (((int)File.GetAttributes(f) & 0x441000) != 0) continue; } catch { continue; }   // só na nuvem: não baixa
                            if (vistos.Add(f)) lista.Add(f);
                        }
                    } catch { }
                    Total = lista.Count;
                }
                Total = lista.Count; Listando = false;
                foreach (var f in lista) {
                    string r = Varredor.Verificar(f, limiteMB);
                    if (r == "ameaca" || r == "bloqueado") { lock (trava) { encontrados.Add(f + "|" + r); } }
                    Feitos++;
                }
            } finally { Listando = false; Fim = true; }
        }
    }
}
'@
}

$ExtVarredura = @($ExtExecutaveis + @('.cpl', '.sys', '.ocx', '.wsh', '.chm', '.zip', '.rar', '.7z', '.cab', '.pdf', '.doc', '.docm', '.xls', '.xlsm', '.pptm', '.rtf') | Select-Object -Unique)
$ArqVarreduraAuto = Join-Path $Pasta 'ultima_varredura_auto.txt'

function Test-AmsiOutroAntivirus {
    # O outro antivírus está registrado no AMSI? (sem isso o Windows responderia "nada encontrado" sem ninguém conferir)
    $c = $script:CacheAmsiOutro
    if ($c -and ((Get-Date) - $c.Quando).TotalMinutes -lt 10) { return $c.Valor }
    $tem = $false
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue)) {
        $dll = "$((Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\CLSID\$($k.PSChildName)\InprocServer32" -ErrorAction SilentlyContinue).'(default)')"
        if ($dll -and $dll -notmatch 'Windows Defender|MpOav\.dll') { $tem = $true }
    }
    $tem = $tem -and [Guardiao.Varredor]::Disponivel()
    $script:CacheAmsiOutro = @{ Quando = Get-Date; Valor = $tem }
    return $tem
}

function Start-VarreduraAntivirus([string]$Tipo, [string]$Motor, [switch]$Auto) {
    if (-not (Test-AmsiOutroAntivirus)) {
        return "O $Motor nao aceita pedidos de verificacao de outros programas (AMSI). Faca a verificacao pela tela do $Motor."
    }
    $p = [Environment]::GetFolderPath('UserProfile')
    $arquivos = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $_.Path } | Where-Object { $_ } | Select-Object -Unique)
    if ($Tipo -eq 'completa') {
        $pastas = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ForEach-Object { "$($_.DeviceID)\" })
    } else {
        # rápida: onde as ameaças costumam ficar + os programas que estão rodando agora
        $pastas = @((Join-Path $p 'Downloads'), [Environment]::GetFolderPath('Desktop'), $env:TEMP, (Join-Path $env:windir 'Temp'),
                    [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'), $env:PUBLIC,
                    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'), (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'))
    }
    $ignorar = @('\Windows\WinSxS\', '\System Volume Information', '\Windows\servicing\', '\$WINDOWS.~BT', '\Windows\SoftwareDistribution\Download\', (Join-Path $Pasta 'quarentena-arquivos'))
    [Guardiao.VarreduraAv]::Iniciar([string[]]$pastas, [string[]]$arquivos, [string[]]$ExtVarredura, [string[]]$ignorar, 64)
    $script:Varredura = @{ Tipo = $Tipo; Inicio = Get-Date; Motor = $Motor; Fim = $null; Resultado = ''; Base = 'arquivos conferidos'; Previsto = 0; Auto = [bool]$Auto }
    $comoTxt = 'pedida no painel'; if ($Auto) { $comoTxt = 'automatica diaria' }
    Write-Log 'INFO' "Verificacao $Tipo pelo $Motor iniciada ($comoTxt): o WebGuardian manda o $Motor conferir cada arquivo"
    $tipoTxt = 'rápida'; if ($Tipo -eq 'completa') { $tipoTxt = 'completa' }
    return "Verificação $tipoTxt pelo $Motor iniciada. O WebGuardian manda o $Motor conferir cada arquivo, sem precisar abrir o $Motor."
}

function Complete-VarreduraAntivirus($v) {
    # Terminou: isola o que o antivírus apontou (fora das pastas do sistema) e avisa
    $achados = @([Guardiao.VarreduraAv]::Encontrados())
    foreach ($e in $achados) {
        $arq, $estado = $e -split '\|', 2
        $nm = [IO.Path]::GetFileName($arq)
        if ($estado -eq 'bloqueado' -or -not (Test-Path -LiteralPath $arq)) { Write-Log 'CRITICO' "Verificacao $($v.Tipo): o $($v.Motor) bloqueou $arq"; continue }
        $sistema = $arq -like "$env:windir\*" -or $arq -like "$env:ProgramFiles\*" -or $arq -like "${env:ProgramFiles(x86)}\*"
        if ($sistema) { Test-Alerta 'Ameaca no sistema' $arq "O $($v.Motor) apontou ameaca na verificacao $($v.Tipo). Arquivo do sistema: nao foi movido. Rode a verificacao offline." }
        else { Lock-ArquivoBaixado $arq "O $($v.Motor) encontrou ameaca na verificacao $($v.Tipo)" | Out-Null }
    }
    $n = $achados.Count; $total = [Guardiao.VarreduraAv]::Total
    if ($n) {
        $v.Resultado = "Concluida: $n ameaca(s) encontrada(s) pelo $($v.Motor). Veja a aba Decisoes."
        Write-Log 'CRITICO' "Verificacao $($v.Tipo) pelo $($v.Motor) encontrou $n ameaca(s) em $total arquivos"
        Show-Alerta 'WebGuardian: ameaca encontrada' "A verificacao $($v.Tipo) encontrou $n ameaca(s). Abra o WebGuardian."
    } else { $v.Resultado = "Concluida: nenhuma ameaca encontrada ($total arquivos conferidos pelo $($v.Motor))." }
}

function Step-VarreduraAutomatica {
    # Verificação rápida AUTOMÁTICA uma vez por dia, em segundo plano, sem abrir nada (20 min depois de ligar)
    if ((Get-Date) -lt $script:ProxVarreduraAuto) { return }
    $script:ProxVarreduraAuto = (Get-Date).AddHours(1)
    $ultima = [datetime]::MinValue
    if (Test-Path $ArqVarreduraAuto) { try { $ultima = [datetime]::ParseExact((Get-Content $ArqVarreduraAuto -Raw).Trim(), 'yyyy-MM-dd HH:mm:ss', $null) } catch { } }
    if (((Get-Date) - $ultima).TotalHours -lt 24) { return }
    if ($script:Varredura -and -not $script:Varredura.Fim) { return }
    $agora = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    if (-not (Get-AntivirusSubstituto)) {
        # Defender ativo e já fez a verificação rápida dele nas últimas 24 h: não repete
        try { $q = (Get-MpComputerStatus -ErrorAction Stop).QuickScanEndTime; if ($q -and ((Get-Date) - $q).TotalHours -lt 24) { Set-Content $ArqVarreduraAuto $agora -Encoding ASCII; return } } catch { }
    }
    Set-Content $ArqVarreduraAuto $agora -Encoding ASCII
    Start-Varredura 'rapida' -Auto | Out-Null
}
$script:ProxVarreduraAuto = (Get-Date).AddMinutes(20)

# --------------------------- Suspender processo ---------------------------
if (-not ('Guardiao.Proc' -as [type])) {
    Add-Type -Namespace Guardiao -Name Proc -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, int pid);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
[DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
[DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);
public static bool Suspend(int pid){ IntPtr h=OpenProcess(0x0800,false,pid); if(h==IntPtr.Zero)return false; int r=NtSuspendProcess(h); CloseHandle(h); return r==0; }
public static bool Resume(int pid){ IntPtr h=OpenProcess(0x0800,false,pid); if(h==IntPtr.Zero)return false; int r=NtResumeProcess(h); CloseHandle(h); return r==0; }
'@
}

# ------------------------------ Ações de isolamento -----------------------
function Block-Ip([string]$Ip, [string]$Motivo) {
    $nome = "Guardiao - IP $Ip"
    if (Get-NetFirewallRule -DisplayName "$nome*" -ErrorAction SilentlyContinue) { return }
    if ($SomenteAlertar) { Test-Alerta 'IP' $Ip $Motivo; return }
    New-NetFirewallRule -DisplayName "$nome (entrada)" -Group $GrupoFirewall -Direction Inbound  -RemoteAddress $Ip -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "$nome (saida)"   -Group $GrupoFirewall -Direction Outbound -RemoteAddress $Ip -Action Block | Out-Null
    Add-Quarentena 'IP' $Ip $Motivo @{ Regra = $nome }
}

function Lock-Processo([int]$ProcId, [string]$Caminho, [string]$Motivo) {
    if ($SomenteAlertar) { Test-Alerta 'Processo' "$Caminho (PID $ProcId)" $Motivo; return }
    $ok = [Guardiao.Proc]::Suspend($ProcId)
    $regra = "Guardiao - Programa $([IO.Path]::GetFileName($Caminho)) $ProcId"
    New-NetFirewallRule -DisplayName $regra -Group $GrupoFirewall -Direction Outbound -Program $Caminho -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "$regra (entrada)" -Group $GrupoFirewall -Direction Inbound -Program $Caminho -Action Block | Out-Null
    Add-Quarentena 'Processo' "$Caminho (PID $ProcId)" "$Motivo (suspenso: $ok)" @{ Pid = $ProcId; Caminho = $Caminho; Regra = $regra }
    Start-ScanDefender $Caminho
}

function Lock-Usuario([string]$Nome, [string]$Motivo) {
    if ($Nome -eq $env:USERNAME) { Test-Alerta 'Usuario' $Nome "$Motivo (e voce; nao isolado)"; return }
    if ($SomenteAlertar) { Test-Alerta 'Usuario' $Nome $Motivo; return }
    try { Disable-LocalUser -Name $Nome -ErrorAction Stop } catch { Test-Alerta 'Usuario' $Nome "$Motivo (falha ao desativar: $_)"; return }
    Add-Quarentena 'Usuario' $Nome $Motivo @{ Nome = $Nome }
}

function Lock-Admin([string]$Sid, [string]$Nome, [string]$Motivo) {
    if ($Nome -like "*\$env:USERNAME" -or $Nome -eq $env:USERNAME) { Test-Alerta 'Administrador' $Nome "$Motivo (e voce; nao isolado)"; return }
    if ($SomenteAlertar) { Test-Alerta 'Administrador' $Nome $Motivo; return }
    try { Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $Sid -ErrorAction Stop } catch { Test-Alerta 'Administrador' $Nome "$Motivo (falha ao remover: $_)"; return }
    Add-Quarentena 'Administrador' $Nome $Motivo @{ Sid = $Sid }
}

function Lock-Servico([string]$Nome, [string]$Exe, [string]$Motivo) {
    if ($SomenteAlertar) { Test-Alerta 'Servico' $Nome $Motivo; return }
    $orig = (Get-CimInstance Win32_Service -Filter "Name='$Nome'" -ErrorAction SilentlyContinue).StartMode
    Stop-Service -Name $Nome -Force -ErrorAction SilentlyContinue
    Set-Service -Name $Nome -StartupType Disabled -ErrorAction SilentlyContinue
    Add-Quarentena 'Servico' $Nome $Motivo @{ Nome = $Nome; InicioOriginal = "$orig"; Exe = $Exe }
    Start-ScanDefender $Exe
}

function Lock-Tarefa($Tarefa, [string]$Exe, [string]$Motivo) {
    $id = "$($Tarefa.TaskPath)$($Tarefa.TaskName)"
    if ($SomenteAlertar) { Test-Alerta 'Tarefa' $id $Motivo; return }
    Disable-ScheduledTask -TaskPath $Tarefa.TaskPath -TaskName $Tarefa.TaskName -ErrorAction SilentlyContinue | Out-Null
    Add-Quarentena 'Tarefa' $id $Motivo @{ TaskPath = $Tarefa.TaskPath; TaskName = $Tarefa.TaskName; Exe = $Exe }
    Start-ScanDefender $Exe
}

function Lock-Run([string]$Chave, [string]$Nome, [string]$Valor, [string]$Motivo) {
    if ($SomenteAlertar) { Test-Alerta 'Inicializacao' "$Chave\$Nome" $Motivo; return }
    Remove-ItemProperty -Path $Chave -Name $Nome -ErrorAction SilentlyContinue
    Add-Quarentena 'Inicializacao' "$Chave\$Nome" $Motivo @{ Chave = $Chave; Nome = $Nome; Valor = $Valor }
    Start-ScanDefender (Get-ExeDeComando $Valor)
}

# ------------------------- Liberar / Apagar / Confirmar -------------------
function Undo-Item($Item) {
    $d = $Item.Desfazer
    switch ($Item.Tipo) {
        'IP'            { Get-NetFirewallRule -DisplayName "$($d.Regra)*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
        'Processo'      { [Guardiao.Proc]::Resume([int]$d.Pid) | Out-Null
                          Get-NetFirewallRule -DisplayName "$($d.Regra)*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
        'Usuario'       { Enable-LocalUser -Name $d.Nome }
        'Administrador' { Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $d.Sid }
        'Servico'       { $t = switch ($d.InicioOriginal) { 'Auto' { 'Automatic' } 'Disabled' { 'Disabled' } default { 'Manual' } }
                          Set-Service -Name $d.Nome -StartupType $t }
        'Tarefa'        { Enable-ScheduledTask -TaskPath $d.TaskPath -TaskName $d.TaskName | Out-Null }
        'Inicializacao' { New-ItemProperty -Path $d.Chave -Name $d.Nome -Value $d.Valor -PropertyType String -Force | Out-Null }
        'Arquivo'       { # devolve o download para onde estava (sem sobrescrever outro arquivo com o mesmo nome)
                          $dest = $d.Original
                          if (Test-Path -LiteralPath $dest) { $dest = Join-Path (Split-Path $dest) ("{0} (liberado){1}" -f [IO.Path]::GetFileNameWithoutExtension($dest), [IO.Path]::GetExtension($dest)) }
                          Move-Item -LiteralPath $d.Guardado -Destination $dest -ErrorAction Stop
                          # você decidiu liberar: o vigia de downloads não deve isolá-lo de novo
                          $it = Get-Item -LiteralPath $dest -ErrorAction SilentlyContinue
                          if ($it -and $script:DownloadsVistos) { $script:DownloadsVistos["$dest|$($it.Length)|$($it.LastWriteTimeUtc.Ticks)"] = $true } }
        'Ameaca'        { # Você decidiu que era alarme falso: o Defender passa a PERMITIR essa ameaça neste PC
                          # (como o "Permitir no dispositivo" da Segurança do Windows) e devolve o arquivo da quarentena dele
                          Add-MpPreference -ThreatIDDefaultAction_Ids ([int64]$d.ThreatID) -ThreatIDDefaultAction_Actions Allow -ErrorAction Stop
                          $volta = @()
                          foreach ($a in @($d.Arquivos)) {
                              if (-not $a -or (Test-Path -LiteralPath $a)) { continue }
                              & $MpCmdRun -Restore -Name "$($d.Nome)" -FilePath "$a" 2>&1 | Out-Null
                              if (-not (Test-Path -LiteralPath $a)) { & $MpCmdRun -Restore -Name "$($d.Nome)" 2>&1 | Out-Null }
                              if (Test-Path -LiteralPath $a) { $volta += [IO.Path]::GetFileName($a) }
                          }
                          if ($volta.Count) { return "ameaca permitida no Defender e arquivo devolvido ($($volta -join ', '))" }
                          return 'ameaca permitida no Defender (nao havia copia na quarentena para devolver)' }
    }
}

function Remove-ArquivoSeguro([string]$Caminho) {
    # Nunca apaga arquivos do Windows / Arquivos de Programas nem arquivos com assinatura válida
    if ([string]::IsNullOrWhiteSpace($Caminho) -or -not (Test-Path -LiteralPath $Caminho)) { return 'arquivo ja nao existe' }
    $protegidas = @($env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
    foreach ($p in $protegidas) { if ($Caminho -like "$p\*") { return "arquivo de sistema preservado ($Caminho)" } }
    try { if ((Get-AuthenticodeSignature -LiteralPath $Caminho).Status -eq 'Valid') { return "arquivo assinado preservado ($Caminho)" } } catch { }
    try { Remove-Item -LiteralPath $Caminho -Force -ErrorAction Stop; return "arquivo apagado ($Caminho)" }
    catch { return "nao foi possivel apagar $Caminho - rode a verificacao do Defender ($_)" }
}

function Remove-Ameaca($Item) {
    $d = $Item.Desfazer
    switch ($Item.Tipo) {
        'IP'            { return 'IP mantido bloqueado permanentemente' }
        'Administrador' { return 'conta mantida fora dos Administradores' }
        'Usuario'       { Remove-LocalUser -Name $d.Nome -ErrorAction Stop; return "usuario $($d.Nome) excluido" }
        'Processo'      { Stop-Process -Id ([int]$d.Pid) -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 800
                          return "processo encerrado; $(Remove-ArquivoSeguro $d.Caminho)" }
        'Servico'       { $exe = $d.Exe
                          if (-not $exe) { $exe = Get-ExeDeComando (Get-CimInstance Win32_Service -Filter "Name='$($d.Nome)'" -ErrorAction SilentlyContinue).PathName }
                          Stop-Service -Name $d.Nome -Force -ErrorAction SilentlyContinue
                          sc.exe delete $d.Nome | Out-Null
                          return "servico removido; $(Remove-ArquivoSeguro $exe)" }
        'Tarefa'        { Unregister-ScheduledTask -TaskPath $d.TaskPath -TaskName $d.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                          return "tarefa excluida; $(Remove-ArquivoSeguro $d.Exe)" }
        'Inicializacao' { return "entrada ja removida; $(Remove-ArquivoSeguro (Get-ExeDeComando $d.Valor))" }
        'Arquivo'       { Remove-Item -LiteralPath $d.Guardado -Force -ErrorAction Stop; return "download suspeito apagado ($([IO.Path]::GetFileName($d.Original)))" }
        'Ameaca'        { # Ameaça ATIVA: o Defender remove. Já na quarentena dele: fica presa lá, criptografada (inofensiva).
                          $ativa = @(Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.IsActive -and "$($_.ThreatID)" -eq "$($d.ThreatID)" }).Count -gt 0
                          if ($ativa) { Remove-MpThreat -ErrorAction SilentlyContinue }
                          $extra = @()
                          foreach ($a in @($d.Arquivos)) {
                              if (-not $a -or -not (Test-Path -LiteralPath $a)) { continue }
                              try { Start-MpScan -ScanType CustomScan -ScanPath $a -ErrorAction Stop } catch { }   # o Defender neutraliza o que sobrou
                              if (Test-Path -LiteralPath $a) { $extra += (Remove-ArquivoSeguro $a) }
                          }
                          $txt = 'ameaca eliminada: fica presa na quarentena do Defender (criptografada, nao roda) ate ele apagar sozinho'
                          if ($ativa) { $txt = 'ameaca ativa removida pelo Defender' }
                          if ($extra.Count) { $txt += '; ' + ($extra -join '; ') }
                          return $txt }
    }
    return 'nada a fazer'
}

function Invoke-AcaoItem([string]$Acao, [string]$Id) {
    $itens = @(Get-Quarentena); $msgs = @()
    foreach ($i in $itens) {
        $alvoOk = ($Id -eq 'todos' -or "$($i.Id)" -eq $Id)
        if (-not $alvoOk -or $i.Estado -ne 'ISOLADO') { continue }
        try {
            switch ($Acao) {
                'liberar'   { $u = @(Undo-Item $i) | Where-Object { $_ -is [string] } | Select-Object -Last 1
                              $i.Estado = 'LIBERADO'; $r = 'isolamento desfeito'; if ($u) { $r = $u } }
                'apagar'    { $r = Remove-Ameaca $i; $i.Estado = 'APAGADO' }
                'confirmar' { $i.Estado = 'AMEACA CONFIRMADA'; $r = 'mantido isolado' }
            }
            Write-Log 'INFO' "$Acao #$($i.Id) [$($i.Tipo)] $($i.Alvo): $r"
            $msgs += "#$($i.Id): $r"
        } catch { $msgs += "#$($i.Id): ERRO - $_" }
    }
    Save-Quarentena $itens
    if (-not $msgs.Count) { $msgs = @('Nenhum item pendente com esse numero.') }
    return ($msgs -join "`n")
}

function Invoke-IsolarRede {
    $placas = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
    if (-not $placas.Count) { return 'Nenhuma placa de rede ativa.' }
    ConvertTo-Json -InputObject @($placas.Name) | Set-Content $ArqRede -Encoding UTF8
    $placas | Disable-NetAdapter -Confirm:$false
    Write-Log 'CRITICO' "REDE ISOLADA: placas desligadas: $($placas.Name -join ', ')"
    return "Computador desconectado da rede ($($placas.Name -join ', '))."
}
function Invoke-RestaurarRede {
    if (Test-Path $ArqRede) {
        $placas = Get-Content $ArqRede -Raw | ConvertFrom-Json   # ver nota em Get-Quarentena
        foreach ($n in @($placas)) { Enable-NetAdapter -Name $n -Confirm:$false }
        Remove-Item $ArqRede
    } else { Get-NetAdapter -Physical | Enable-NetAdapter -Confirm:$false }
    Write-Log 'INFO' 'Rede restaurada'
    return 'Rede reconectada.'
}

# ------------------------------ Verificações ------------------------------
function Get-DadosEvento($Evento) {
    $h = @{}
    foreach ($d in ([xml]$Evento.ToXml()).Event.EventData.Data) { $h[$d.Name] = $d.'#text' }
    return $h
}

$script:EventosVistos = New-Object 'System.Collections.Generic.HashSet[string]'
$script:Falhas = @{}

# ===================== SESSÕES: a atividade começa do zero a cada PC ligado =====================
# Ao ligar o PC, a atividade da sessão anterior é ARQUIVADA (não apagada) em C:\ProgramData\Guardiao\sessoes
# e o WebGuardian relê o registro de segurança desde a hora em que o PC ligou, para mostrar quem entrou na máquina.
$ArqSessao    = Join-Path $Pasta 'sessao.json'
$PastaSessoes = Join-Path $Pasta 'sessoes'
$script:InicioSessao = $null; $script:NovaSessao = $false
$script:EntradasVistas = @{}

function Get-HoraLigado {
    try { return (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime }
    catch { return (Get-Date).AddMilliseconds(-[Environment]::TickCount) }
}

function Start-SessaoAtividade {
    $boot = Get-HoraLigado
    $script:InicioSessao = $boot
    $anterior = $null
    if (Test-Path $ArqSessao) { try { $anterior = (Get-Content $ArqSessao -Raw | ConvertFrom-Json).boot } catch { } }
    $mesma = $false
    if ($anterior) {   # tolerância de 2 min: o Windows às vezes ajusta a hora de boot em alguns segundos
        try { $mesma = [Math]::Abs(([datetime]::ParseExact($anterior, 'yyyy-MM-dd HH:mm:ss', $null) - $boot).TotalMinutes) -lt 2 } catch { }
    }
    if ($mesma) { $script:NovaSessao = $false; return }
    $script:NovaSessao = $true
    if ((Test-Path $ArqLog) -and (Get-Item $ArqLog).Length -gt 0) {
        New-Item -ItemType Directory -Force -Path $PastaSessoes | Out-Null
        $rotulo = (Get-Item $ArqLog).LastWriteTime.ToString('yyyy-MM-dd_HH-mm')
        if ($anterior) { $rotulo = ($anterior -replace ':', '-') -replace ' ', '_' }
        Move-Item $ArqLog (Join-Path $PastaSessoes "atividade_ligado-em_$rotulo.log") -Force
        # guarda as 30 sessões mais recentes
        Get-ChildItem $PastaSessoes -Filter 'atividade_*.log' | Sort-Object LastWriteTime -Descending | Select-Object -Skip 30 | Remove-Item -Force
    }
    @{ boot = $boot.ToString('yyyy-MM-dd HH:mm:ss') } | ConvertTo-Json | Set-Content $ArqSessao -Encoding UTF8
}

function Get-InfoSessao {
    $n = 0; if (Test-Path $PastaSessoes) { $n = @(Get-ChildItem $PastaSessoes -Filter 'atividade_*.log').Count }
    $ini = ''; if ($script:InicioSessao) { $ini = $script:InicioSessao.ToString('yyyy-MM-dd HH:mm:ss') }
    return @{ inicio = $ini; anteriores = $n }
}

$NomesEntrada = @{ 2 = 'entrou no Windows (no próprio PC)'; 7 = 'desbloqueou a tela'; 11 = 'entrou no Windows (senha salva no PC)' }

function Write-Entrada($Evento, $Dados) {
    # Registra quem entrou na máquina (logon local, desbloqueio, senha salva), sem repetir eventos gêmeos do Windows
    $tipo = [int]$Dados.LogonType
    if (-not $NomesEntrada.ContainsKey($tipo) -or "$($Dados.TargetUserSid)" -notlike 'S-1-5-21-*') { return }
    $quem = "$($Dados.TargetDomainName)\$($Dados.TargetUserName)"
    $chave = "$quem|$tipo"
    if (-not $script:EntradasVistas.ContainsKey($chave)) { $script:EntradasVistas[$chave] = New-Object System.Collections.ArrayList }
    foreach ($t in $script:EntradasVistas[$chave]) { if ([Math]::Abs(($Evento.TimeCreated - $t).TotalSeconds) -lt 120) { return } }
    [void]$script:EntradasVistas[$chave].Add($Evento.TimeCreated)
    Write-Log 'INFO' "[Entrada] $quem $($NomesEntrada[$tipo])" $Evento.TimeCreated
}

function Write-SenhaErrada($Evento, $Dados) {
    # Senha errada digitada no próprio PC (tela de entrada / desbloqueio)
    $tipo = [int]$Dados.LogonType
    if (@(2, 7, 11) -notcontains $tipo) { return }
    $quem = "$($Dados.TargetDomainName)\$($Dados.TargetUserName)"
    $chave = "falha|$quem"
    if (-not $script:EntradasVistas.ContainsKey($chave)) { $script:EntradasVistas[$chave] = New-Object System.Collections.ArrayList }
    foreach ($t in $script:EntradasVistas[$chave]) { if ([Math]::Abs(($Evento.TimeCreated - $t).TotalSeconds) -lt 30) { return } }
    [void]$script:EntradasVistas[$chave].Add($Evento.TimeCreated)
    if (@('-', '') -contains "$($Dados.TargetUserName)") {
        # o Windows não informa a conta quando o PIN, a digital ou o rosto não são reconhecidos
        Write-Log 'ALERTA' '[Entrada] Tentativa de entrada recusada no próprio PC (sem nome de usuário: costuma ser PIN, digital ou rosto não reconhecido)' $Evento.TimeCreated
    } else {
        Write-Log 'ALERTA' "[Entrada] Senha errada ao entrar no Windows como $quem" $Evento.TimeCreated
    }
}

function Get-EventosNovos([string]$Log, [int[]]$Ids, [datetime]$Desde) {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Ids; StartTime = $Desde } -ErrorAction SilentlyContinue
    foreach ($e in @($ev)) {
        if ($null -eq $e) { continue }
        if ($script:EventosVistos.Add("$Log-$($e.RecordId)")) { $e }
    }
}

function Test-Logons([datetime]$Desde) {
    # em ordem cronológica (o Windows devolve do mais novo para o mais antigo)
    foreach ($e in @(Get-EventosNovos 'Security' @(4624, 4625, 4720, 4732, 1102) $Desde | Sort-Object TimeCreated)) {
        $d = Get-DadosEvento $e
        switch ($e.Id) {
            4625 {
                $ip = "$($d.IpAddress)"
                Write-SenhaErrada $e $d
                if ($Config.IPsConfiaveis -contains $ip) { break }
                if (-not $script:Falhas.ContainsKey($ip)) { $script:Falhas[$ip] = New-Object System.Collections.ArrayList }
                [void]$script:Falhas[$ip].Add($e.TimeCreated)
                $limite = (Get-Date).AddMinutes(-$Config.JanelaFalhasMin)
                $recentes = @($script:Falhas[$ip] | Where-Object { $_ -gt $limite })
                $script:Falhas[$ip] = [System.Collections.ArrayList]$recentes
                if ($recentes.Count -ge $Config.LimiteFalhasLogon) {
                    Block-Ip $ip "$($recentes.Count) senhas erradas em $($Config.JanelaFalhasMin) min (usuario: $($d.TargetUserName))"
                }
            }
            4624 {
                $tipo = [int]$d.LogonType; $ip = "$($d.IpAddress)"
                Write-Entrada $e $d
                if (($tipo -eq 10 -or $tipo -eq 3) -and -not (Test-IpPrivado $ip)) {
                    Block-Ip $ip "Logon remoto (tipo $tipo) BEM-SUCEDIDO de IP externo como $($d.TargetDomainName)\$($d.TargetUserName)"
                } elseif ($tipo -eq 10 -and -not ($Config.IPsConfiaveis -contains $ip)) {
                    Test-Alerta 'Area de Trabalho Remota' $ip "Logon RDP como $($d.TargetUserName)"
                }
            }
            4720 { Lock-Usuario $d.TargetUserName "Usuario criado por $($d.SubjectUserName)" }
            4732 {
                if ($d.TargetSid -eq 'S-1-5-32-544') {
                    $nome = $d.MemberSid
                    try { $nome = (New-Object System.Security.Principal.SecurityIdentifier $d.MemberSid).Translate([System.Security.Principal.NTAccount]).Value } catch { }
                    Lock-Admin $d.MemberSid $nome "Adicionado aos Administradores por $($d.SubjectUserName)"
                }
            }
            1102 { Write-Log 'CRITICO' "Log de seguranca foi APAGADO por $($d.SubjectUserName)"
                   Show-Alerta 'WebGuardian: CRITICO' 'O log de seguranca foi apagado. Sinal classico de invasor.' }
        }
    }
}

# ------------------ Classificador: ameaça real x item legítimo ------------------
# Decide pela ASSINATURA DIGITAL do que vai rodar (nome e pasta podem ser imitados):
#   'isolar'    -> comando com cara de ataque, ou programa sem assinatura em pasta suspeita
#   'alertar'   -> sem assinatura / desconhecido, ou ferramenta do Windows usada de forma incomum
#   'microsoft' -> programa/componente assinado pela Microsoft (ex.: tarefas SoftLanding)  -> só registro
#   'assinado'  -> assinado por outra empresa conhecida, fora de pasta suspeita            -> só registro
$PadraoAtaque = '(?i)(-e(nc(odedcommand)?)?\s+[a-z0-9+/=]{20,}|frombase64|downloadstring|downloadfile|invoke-webrequest|\biwr\s|\birm\s|invoke-expression|\biex\b|net\.webclient|start-bitstransfer|bitsadmin|certutil.+(-urlcache|-decode)|mshta|-w(indowstyle)?\s+h(idden)?\b.+-e)'
# Endereço remoto nos argumentos: grave só se quem usa é ferramenta de ataque ou programa sem assinatura
$PadraoRemoto = '(?i)(https?://|\\\\[0-9]{1,3}\.[0-9]{1,3}\.)'
# Ferramentas do Windows muito usadas por invasores: assinatura da Microsoft NÃO basta
$Lolbins = @('powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe',
             'msiexec.exe','bitsadmin.exe','certutil.exe','wmic.exe','schtasks.exe','forfiles.exe','msbuild.exe','installutil.exe')

function Resolve-Programa([string]$Exe) {
    # "powershell.exe" sem caminho -> C:\Windows\System32\...
    if ([string]::IsNullOrWhiteSpace($Exe)) { return $null }
    $e = [Environment]::ExpandEnvironmentVariables($Exe.Trim().Trim('"'))
    if ([IO.Path]::IsPathRooted($e)) { return $e }
    foreach ($d in (Join-Path $env:windir 'System32'), $env:windir, (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0')) {
        $c = Join-Path $d $e; if (Test-Path -LiteralPath $c) { return $c }
        if (-not [IO.Path]::HasExtension($e) -and (Test-Path -LiteralPath "$c.exe")) { return "$c.exe" }
    }
    return $e
}

$script:CacheEditor = @{}
function Get-Editor([string]$Caminho) {
    # 'microsoft' | 'assinado:<empresa>' | 'sem-assinatura' | 'inexistente'
    if ([string]::IsNullOrWhiteSpace($Caminho)) { return 'inexistente' }
    if ($script:CacheEditor.ContainsKey($Caminho)) { return $script:CacheEditor[$Caminho] }
    $r = 'inexistente'
    if (Test-Path -LiteralPath $Caminho -PathType Leaf -ErrorAction SilentlyContinue) {
        $r = 'sem-assinatura'
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $Caminho
            if ($s.Status -eq 'Valid') {
                $subj = "$($s.SignerCertificate.Subject)"
                if ($subj -match 'O=Microsoft Corporation') { $r = 'microsoft' }
                else { $cn = [regex]::Match($subj, 'CN="?([^",]+)').Groups[1].Value; $r = "assinado:$cn" }
            }
        } catch { }
    }
    $script:CacheEditor[$Caminho] = $r
    return $r
}

function Get-DllDoCom([string]$ClassId) {
    # Tarefas do tipo ComHandler não chamam .exe: chamam um componente (CLSID) -> descobre a DLL
    if (-not $ClassId) { return $null }
    foreach ($h in 'HKCU:\SOFTWARE\Classes\CLSID', 'HKLM:\SOFTWARE\Classes\CLSID', 'HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID') {
        foreach ($sub in 'InprocServer32', 'LocalServer32') {
            $k = "$h\$ClassId\$sub"
            if (Test-Path -LiteralPath $k) { return Resolve-Programa (Get-ExeDeComando ((Get-Item -LiteralPath $k).GetValue(''))) }
        }
    }
    return $null
}

function Get-Classificacao([string]$Exe, [string]$Argumentos, [string]$ClassId) {
    # Devolve @{ Nivel; Motivo; Arquivo }
    $texto = "$Exe $Argumentos"
    # O próprio WebGuardian (script em C:\ProgramData\WebGuardian, pasta só de Administradores)
    $proprio = [regex]::Escape((Join-Path $Pasta 'Guardiao.ps1'))
    if ($Argumentos -match "-File\s+`"?$proprio`"?(\s|$)" -and $Argumentos -notmatch $PadraoAtaque) {
        return @{ Nivel = 'microsoft'; Arquivo = $null; Motivo = 'o proprio WebGuardian' } }
    if ($ClassId -and -not $Exe) {
        $dll = Get-DllDoCom $ClassId
        if (-not $dll) { return @{ Nivel = 'microsoft'; Arquivo = $null; Motivo = "componente $ClassId nao registrado (nao executa nada por conta propria)" } }
        $Exe = $dll
    }
    $arq = Resolve-Programa $Exe
    if ($texto -match $PadraoAtaque) { return @{ Nivel = 'isolar'; Arquivo = $arq; Motivo = 'comando com padrao de ataque (download, codigo escondido ou script remoto)' } }
    if (Test-Suspeito $arq) { return @{ Nivel = 'isolar'; Arquivo = $arq; Motivo = 'programa sem assinatura em pasta suspeita' } }
    $ed = Get-Editor $arq
    $nome = [IO.Path]::GetFileName("$arq").ToLower()
    if ("$Argumentos" -match $PadraoRemoto) {
        if (($Lolbins -contains $nome) -or $ed -eq 'sem-assinatura' -or $ed -eq 'inexistente') {
            return @{ Nivel = 'isolar'; Arquivo = $arq; Motivo = "$nome buscando algo de um endereco remoto" } }
        return @{ Nivel = 'alertar'; Arquivo = $arq; Motivo = "programa assinado ($ed) usando um endereco remoto; confira se voce reconhece" }
    }
    if ($Lolbins -contains $nome) {
        # Ferramenta do Windows: vale o que ela vai abrir (ex.: "rundll32 pcasvc.dll,..." -> DLL da Microsoft)
        $argsExp = [Environment]::ExpandEnvironmentVariables("$Argumentos")
        $cands = @([regex]::Matches($argsExp, '(?i)"([^"]+?\.(?:dll|exe|ps1|vbs|js|bat|cmd|hta))"|([^\s",;]+?\.(?:dll|exe|ps1|vbs|js|bat|cmd|hta))(?=[\s",;]|$)') |
                   ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value } })
        if ($cands.Count) {
            $eds = @()
            foreach ($cd in $cands) {
                $rc = Resolve-Programa $cd
                if (Test-Suspeito $rc) { return @{ Nivel = 'isolar'; Arquivo = $rc; Motivo = "$nome executando arquivo sem assinatura em pasta suspeita" } }
                $eds += [pscustomobject]@{ Arq = $rc; Ed = (Get-Editor $rc) }
            }
            $ruim = $eds | Where-Object { $_.Ed -eq 'sem-assinatura' -or $_.Ed -eq 'inexistente' } | Select-Object -First 1
            if ($ruim) { return @{ Nivel = 'alertar'; Arquivo = $ruim.Arq; Motivo = "$nome executando $($ruim.Arq) ($($ruim.Ed))" } }
            if (-not ($eds | Where-Object { $_.Ed -ne 'microsoft' })) { return @{ Nivel = 'microsoft'; Arquivo = $arq; Motivo = "$nome abrindo componente da Microsoft" } }
            return @{ Nivel = 'assinado'; Arquivo = $arq; Motivo = "$nome abrindo programa assinado" }
        }
        return @{ Nivel = 'alertar'; Arquivo = $arq; Motivo = "uso de $nome (ferramenta comum em ataques); confira se voce reconhece" }
    }
    switch -Wildcard ($ed) {
        'microsoft'   { return @{ Nivel = 'microsoft'; Arquivo = $arq; Motivo = 'assinado pela Microsoft' } }
        'assinado:*'  { return @{ Nivel = 'assinado'; Arquivo = $arq; Motivo = "assinado por $($ed.Substring(9))" } }
        'inexistente' { return @{ Nivel = 'alertar'; Arquivo = $arq; Motivo = 'o arquivo indicado nao existe' } }
        default       { return @{ Nivel = 'alertar'; Arquivo = $arq; Motivo = 'programa sem assinatura digital' } }
    }
}

function Test-Servicos([datetime]$Desde) {
    foreach ($e in Get-EventosNovos 'System' @(7045) $Desde) {
        $d = Get-DadosEvento $e
        $exe = Get-ExeDeComando $d.ImagePath
        $args0 = "$($d.ImagePath)".Substring([Math]::Min("$($d.ImagePath)".Length, "$exe".Length + 2))
        $c = Get-Classificacao $exe $args0 $null
        switch ($c.Nivel) {
            'isolar'  { Lock-Servico $d.ServiceName $c.Arquivo "Servico novo suspeito ($($c.Motivo)): $($d.ImagePath)" }
            'alertar' { Test-Alerta 'Servico novo' $d.ServiceName "$($c.Motivo): $($d.ImagePath)" }
            default   { Write-Log 'INFO' "Servico novo confiavel ($($c.Motivo)): $($d.ServiceName)" }
        }
    }
}

$script:BaseTarefas = @{}; $script:BaseRun = @{}
$ChavesRun = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
function Get-EntradasRun {
    foreach ($k in $ChavesRun) {
        $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        foreach ($prop in $p.PSObject.Properties) {
            if ($prop.Name -like 'PS*') { continue }
            [pscustomobject]@{ Chave = $k; Nome = $prop.Name; Valor = "$($prop.Value)" }
        }
    }
}
function Initialize-Base {
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $script:BaseTarefas["$($_.TaskPath)$($_.TaskName)"] = $true }
    Get-EntradasRun | ForEach-Object { $script:BaseRun["$($_.Chave)|$($_.Nome)|$($_.Valor)"] = $true }
    Write-Log 'INFO' "Base: $($script:BaseTarefas.Count) tarefas, $($script:BaseRun.Count) entradas de inicializacao"
}
function Test-Persistencia {
    foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $id = "$($t.TaskPath)$($t.TaskName)"
        if ($script:BaseTarefas.ContainsKey($id)) { continue }
        $script:BaseTarefas[$id] = $true
        # Uma tarefa pode ter várias ações: vale a MAIS grave
        $pior = $null; $ordem = @{ isolar = 3; alertar = 2; assinado = 1; microsoft = 0 }
        foreach ($acao in @($t.Actions)) {
            $exe = $null; if ($acao.Execute) { $exe = Get-ExeDeComando $acao.Execute }
            $c = Get-Classificacao $exe "$($acao.Arguments)" "$($acao.ClassId)"
            $c.Texto = "$($acao.Execute) $($acao.Arguments) $($acao.ClassId)".Trim()
            if (-not $pior -or $ordem[$c.Nivel] -gt $ordem[$pior.Nivel]) { $pior = $c }
        }
        if (-not $pior) { $pior = @{ Nivel = 'alertar'; Motivo = 'tarefa sem acao'; Arquivo = $null; Texto = '' } }
        switch ($pior.Nivel) {
            'isolar'  { Lock-Tarefa $t $pior.Arquivo "Tarefa agendada nova suspeita ($($pior.Motivo)): $($pior.Texto)" }
            'alertar' { Test-Alerta 'Tarefa nova' $id "$($pior.Motivo): $($pior.Texto)" }
            default   { Write-Log 'INFO' "Tarefa nova confiavel ($($pior.Motivo)): $id" }
        }
    }
    foreach ($r in Get-EntradasRun) {
        $k = "$($r.Chave)|$($r.Nome)|$($r.Valor)"
        if ($script:BaseRun.ContainsKey($k)) { continue }
        $script:BaseRun[$k] = $true
        $exe = Get-ExeDeComando $r.Valor
        $args0 = "$($r.Valor)".Substring([Math]::Min("$($r.Valor)".Length, "$exe".Length + 2))
        $c = Get-Classificacao $exe $args0 $null
        switch ($c.Nivel) {
            'isolar'  { Lock-Run $r.Chave $r.Nome $r.Valor "Inicializacao nova suspeita ($($c.Motivo)): $($r.Valor)" }
            'alertar' { Test-Alerta 'Inicializacao nova' $r.Nome "$($c.Motivo): $($r.Valor)" }
            default   { Write-Log 'INFO' "Inicializacao nova confiavel ($($c.Motivo)): $($r.Nome)" }
        }
    }
}

$script:PidsIsolados = @{}
function Test-Conexoes {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { -not (Test-IpPrivado $_.RemoteAddress) }
    foreach ($c in $conns) {
        $procId = [int]$c.OwningProcess
        if ($procId -le 4 -or $script:PidsIsolados.ContainsKey($procId)) { continue }
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if (-not $proc -or -not $proc.Path) { continue }
        if (Test-Suspeito $proc.Path) {
            $script:PidsIsolados[$procId] = $true
            Lock-Processo $procId $proc.Path "Programa sem assinatura em pasta suspeita conectado a $($c.RemoteAddress):$($c.RemotePort)"
        }
    }
}

$script:UltimaChecagemDefender = Get-Date
$script:AvisouDefenderOff = $false
function Test-Defender {
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        if (-not $st.RealTimeProtectionEnabled -or -not $st.AntivirusEnabled) {
            $outro = Get-OutroAntivirus
            if ($outro -and $outro.Ligado) {
                # Normal: o Windows desliga o Defender quando outro antivírus (Avast, AVG, Norton...) está ligado
                if ($script:AvisouDefenderOff -ne "outro:$($outro.Nome)") {
                    Write-Log 'INFO' "Antivirus ativo deste PC: $($outro.Nome). O Windows desliga o tempo real do Defender quando outro antivirus esta ligado (normal)."
                    $script:AvisouDefenderOff = "outro:$($outro.Nome)"
                }
                if (-not $outro.EmDia -and -not $script:AvisouOutroVelho) {
                    Write-Log 'ALERTA' "A base de ameacas do $($outro.Nome) esta desatualizada. Abra o $($outro.Nome) e atualize."
                    $script:AvisouOutroVelho = $true
                } elseif ($outro.EmDia) { $script:AvisouOutroVelho = $false }
            } elseif ($script:AvisouDefenderOff -ne 'desligado') {
                $quem = 'O Windows Defender foi desligado! Religue em Seguranca do Windows.'
                $msg = 'Protecao em tempo real do Defender esta DESLIGADA'
                if ($outro) { $quem = "Nenhum antivirus esta ligado: o $($outro.Nome) e o Defender estao desligados."; $msg = "NENHUM antivirus ligado: $($outro.Nome) desligado e Defender desligado" }
                Write-Log 'CRITICO' $msg
                Show-Alerta 'WebGuardian: CRITICO' $quem
                $script:AvisouDefenderOff = 'desligado'
            }
        } else { $script:AvisouDefenderOff = $false }
        foreach ($t in Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt $script:UltimaChecagemDefender }) {
            # Com arquivo: vira decisão (abaixo). Só na memória (AMSI, script bloqueado): não há arquivo para decidir, só alerta.
            if (-not @(Get-ArquivosDeteccao $t).Count) { Test-Alerta 'Defender bloqueou ameaca' "$($t.Resources -join ', ')" "Bloqueada na memoria antes de rodar (ThreatID $($t.ThreatID))" }
        }
        $script:UltimaChecagemDefender = Get-Date
        try { Sync-DecisoesDefender | Out-Null } catch { Write-Log 'INFO' "Erro ao trazer as deteccoes do Defender para as decisoes: $_" }
    } catch { }
}

# ================================ PAINEL HTML ================================
function Format-Data($d) { if ($d) { try { return ([datetime]$d).ToString('dd/MM/yyyy HH:mm') } catch { } }; return '' }

$script:Cache = @{}
function Get-Cacheado([string]$Nome, [int]$Segundos, [scriptblock]$Bloco) {
    # Consultas do Windows (Defender, tarefas, conexões) levam 1-2 s cada; reaproveita por alguns segundos
    $c = $script:Cache[$Nome]
    if ($c -and ((Get-Date) - $c.Quando).TotalSeconds -lt $Segundos) { return , $c.Valor }
    $v = & $Bloco
    $script:Cache[$Nome] = @{ Quando = (Get-Date); Valor = $v }
    return , $v
}

function Get-EstadoPainel {
    $mon = Get-Cacheado 'monitor' 30 {
        $t = Get-ScheduledTask -TaskName $NomeTarefa -ErrorAction SilentlyContinue
        $rodando = ($ModoAtual -eq 'Monitorar') -or
                   (@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
                      Where-Object { $_.CommandLine -like '*Guardiao.ps1*-Monitorar*' }).Count -gt 0)
        $estado = 'NAO INSTALADO'; if ($t) { $estado = "$($t.State)" }
        @{ instalado = [bool]$t; rodando = [bool]$rodando; estado = $estado }
    }
    $def = Get-Cacheado 'defender' 20 { Get-EstadoDefender }
    $conexoes = Get-Cacheado 'conexoes' 8 { Get-ConexoesExternas }

    $log = @()
    if (Test-Path $ArqLog) {
        $n = 0
        $log = @(Get-Content $ArqLog -Tail 200 -Encoding UTF8 | ForEach-Object {
            if ($_ -match '^(\S+ \S+) \[(\w+)\] (.*)$') { $n++; [pscustomobject]@{ quando = $Matches[1]; nivel = $Matches[2]; msg = $Matches[3]; ordem = $n } }
        })
        # mais recente primeiro pela hora do evento (entradas lidas desde que o PC ligou chegam fora de ordem no arquivo)
        $log = @($log | Sort-Object @{ Expression = 'quando'; Descending = $true }, @{ Expression = 'ordem'; Descending = $true } |
                 ForEach-Object { @{ quando = $_.quando; nivel = $_.nivel; msg = $_.msg } })
    }

    $varr = Get-EstadoVarredura
    $scan = ''
    if ($varr -and $varr.ativo) {
        $resta = [Math]::Ceiling($varr.restante / 60)
        $scan = "Verificacao $($varr.tipo) do Defender: $($varr.pct)% (estimado)"
        if ($varr.finalizando) { $scan += ' - finalizando...' } else { $scan += " - faltam cerca de $resta min" }
    } elseif ($script:JobScan -and $script:JobScan.State -eq 'Running') { $scan = 'Verificacao do Defender em andamento...' }

    return @{
        agora       = (Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
        computador  = $env:COMPUTERNAME
        monitor     = $mon
        defender    = $def
        redeIsolada = (Test-Path $ArqRede)
        scan        = $scan
        varredura   = $varr
        downloads   = @(Get-DownloadsPainel)
        baseAtualizando = [bool]($script:AtualizacaoDef -and -not $script:AtualizacaoDef.Fim)
        sessao      = Get-InfoSessao
        versao      = $VersaoGuardiao
        varreduraAuto = $(if (Test-Path $ArqVarreduraAuto) { (Get-Content $ArqVarreduraAuto -Raw).Trim() } else { '' })
        autenticidade = $(if (-not $script:Autenticidade) { try { Update-Autenticidade } catch { } }
                          $a = $script:Autenticidade
                          if ($a) { @{ estado = $a.estado; versao = $a.versao; impressao = $a.impressao; fonte = $a.fonte; problemas = @($a.problemas | Select-Object -First 5) } })
        quarentena  = @(Get-Quarentena | Sort-Object { [int]$_.Id } -Descending | ForEach-Object {
                          @{ id = $_.Id; tipo = "$($_.Tipo)"; alvo = "$($_.Alvo)"; motivo = "$($_.Motivo)"; quando = "$($_.Quando)"; estado = "$($_.Estado)" } })
        log         = $log
        conexoes    = @($conexoes)
    }
}

function Get-EstadoDefender {
    $def = @{ ok = $false; tempoReal = $false; antivirus = $false; assinaturas = ''; idadeAssinaturas = $null; ultimaRapida = ''; ultimaCompleta = ''; ameacas = @() }
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        $def.tempoReal = [bool]$st.RealTimeProtectionEnabled
        $def.antivirus = [bool]$st.AntivirusEnabled
        $def.ok = $def.tempoReal -and $def.antivirus
        $def.assinaturas = Format-Data $st.AntivirusSignatureLastUpdated
        $def.idadeAssinaturas = [int]$st.AntivirusSignatureAge
        $def.ultimaRapida = Format-Data $st.QuickScanEndTime
        $def.ultimaCompleta = Format-Data $st.FullScanEndTime
        $def.versaoBase = "$($st.AntivirusSignatureVersion)"
        $def.horasBase = [Math]::Round(((Get-Date) - $st.AntivirusSignatureLastUpdated).TotalHours, 1)
        # Proteções extras do Defender (o usuário liga pelo painel, se quiser)
        try {
            $pf = Get-MpPreference -ErrorAction Stop
            $def.pua = [int]$pf.PUAProtection          # 0 desligado, 1 bloqueia, 2 só auditoria
            $def.nuvemNivel = [int]$pf.CloudBlockLevel # 0 padrão, 2 alto, 4 alto+, 6 tolerância zero
            $def.nuvem = [int]$pf.MAPSReporting        # 0 desligada, 1 básica, 2 avançada
        } catch { }
        $nomes = @{}
        Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $nomes["$($_.ThreatID)"] = $_.ThreatName }
        # "Limpar lista" no painel só esconde as detecções antigas daqui; o Defender mantém o histórico oficial dele
        $corte = [datetime]::MinValue
        if (Test-Path $ArqAmeacasOcultas) { try { $corte = [datetime]::ParseExact((Get-Content $ArqAmeacasOcultas -Raw).Trim(), 'yyyy-MM-dd HH:mm:ss', $null) } catch { } }
        $def.ameacas = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt $corte } |
                         Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 | ForEach-Object {
            @{ quando = Format-Data $_.InitialDetectionTime; nome = "$($nomes["$($_.ThreatID)"])"; arquivos = (@($_.Resources) -join ', '); resolvido = [bool]$_.ActionSuccess }
        })
    } catch { }
    # Outro antivírus registrado no Windows (Avast, AVG, Norton...): com ele ligado, o Defender desligado é normal
    try { $o = Get-OutroAntivirus; if ($o) { $def.outro = @{ nome = $o.Nome; ligado = [bool]$o.Ligado; emDia = [bool]$o.EmDia } } } catch { }
    return $def
}

function Get-ConexoesExternas {
    $conexoes = @()
    try {
        $conexoes = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-IpPrivado $_.RemoteAddress) } |
            Group-Object OwningProcess | ForEach-Object {
                $pr = Get-Process -Id ([int]$_.Name) -ErrorAction SilentlyContinue
                $cam = ''; if ($pr) { $cam = "$($pr.Path)" }
                @{ pid = [int]$_.Name; nome = "$($pr.ProcessName)"; caminho = $cam; qtd = $_.Count
                   destinos = (@($_.Group | Select-Object -First 3 | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" }) -join ', ')
                   suspeito = (Test-Suspeito $cam) }
            } | Sort-Object { -[int]$_.suspeito }, { $_.nome })
    } catch { }
    return , $conexoes
}

function Send-Resposta($Ctx, [int]$Codigo, [string]$Tipo, [string]$Corpo) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Corpo)
    $Ctx.Response.StatusCode = $Codigo
    $Ctx.Response.ContentType = $Tipo
    $Ctx.Response.Headers.Add('Cache-Control', 'no-store')
    $Ctx.Response.Headers.Add('X-Content-Type-Options', 'nosniff')
    $Ctx.Response.ContentLength64 = $bytes.Length
    $Ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Ctx.Response.OutputStream.Close()
}

$script:Ouvinte = $null; $script:Token = $null; $script:Porta = 0
$script:HtmlPainel = $null; $script:UrlPainel = $null; $script:PedidoAtual = $null
$PastaUsuario  = Join-Path $env:LOCALAPPDATA 'Guardiao'
$ArqGatilho    = Join-Path $PastaUsuario 'abrir-painel'   # atalho antigo
$ArqGatilhoApp = Join-Path $PastaUsuario 'abrir-app'      # WebGuardian.exe pedindo um link de entrada
$ArqUrlApp     = Join-Path $PastaUsuario 'app.url'        # resposta: link com código de uso único
$script:CodigosApp = @{}                                   # código -> validade (60 s, usa uma vez)

function Test-PainelAtivo([int]$Timeout = 5, [switch]$AceitarOcupado) {
    # Já existe painel no ar (normalmente dentro do monitor)? Devolve a URL.
    # Atenção: ao ligar, o monitor leva ~15 s preparando o painel e não responde nesse meio-tempo.
    # Demora NÃO é sinal de painel morto: só apaga o registro se a porta recusar a conexão.
    if (-not (Test-Path $ArqPainel)) { return $null }
    $ativo = $null
    try { $ativo = Get-Content $ArqPainel -Raw | ConvertFrom-Json } catch { return $null }
    $url = "http://127.0.0.1:$($ativo.porta)/?t=$($ativo.token)"
    # 1) Alguém escuta na porta? (o Windows aceita a conexão mesmo com o monitor ocupado)
    if (-not (Test-PortaAberta ([int]$ativo.porta))) {
        Remove-Item $ArqPainel -ErrorAction SilentlyContinue   # ninguém escutando: registro velho
        return $null
    }
    # 2) Responde? Se só estiver ocupado, não é motivo para desistir dele
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$($ativo.porta)/ping" -Headers @{ 'X-Token' = $ativo.token } -TimeoutSec $Timeout | Out-Null
        return $url
    } catch {
        if ($AceitarOcupado) { return $url }   # está no ar, só ocupado: o navegador espera
        return $null
    }
}

function Test-PortaAberta([int]$Porta) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect('127.0.0.1', $Porta, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(3000)) { return $false }
        $c.EndConnect($ar); return $true
    } catch { return $false } finally { $c.Close() }
}

function Wait-PainelAtivo([int]$Segundos = 90) {
    # Espera o monitor recém-iniciado responder (mostra o progresso na janela)
    $fim = (Get-Date).AddSeconds($Segundos)
    while ((Get-Date) -lt $fim) {
        $u = Test-PainelAtivo -Timeout 5
        if ($u) { Write-Host ''; return $u }
        Write-Host '.' -NoNewline
        Start-Sleep 2
    }
    Write-Host ''
    return $null
}

function New-ServidorPainel {
    $arqHtml = Join-Path $DirScript 'painel.html'
    if (-not (Test-Path $arqHtml)) { Write-Log 'INFO' "painel.html nao encontrado em $DirScript"; return $false }
    $script:Token = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    for ($tentativa = 0; $tentativa -lt 10; $tentativa++) {
        $porta = Get-Random -Minimum 49200 -Maximum 49900
        $o = New-Object System.Net.HttpListener
        $o.Prefixes.Add("http://127.0.0.1:$porta/")
        try { $o.Start(); $script:Ouvinte = $o; $script:Porta = $porta; break } catch { }
    }
    if (-not $script:Ouvinte) { Write-Log 'INFO' 'Nao consegui abrir porta para o painel'; return $false }
    $script:HtmlPainel = (Get-Content $arqHtml -Raw -Encoding UTF8).Replace('__TOKEN__', $script:Token)
    $script:UrlPainel = "http://127.0.0.1:$($script:Porta)/?t=$($script:Token)"
    @{ porta = $script:Porta; token = $script:Token } | ConvertTo-Json | Set-Content $ArqPainel -Encoding UTF8
    return $true
}

function Invoke-PedidoPainel($ctx) {
    $req = $ctx.Request
    try {
        # Proteções: só aceita o próprio endereço (evita DNS rebinding) e exige o token
        if ($req.Headers['Host'] -ne "127.0.0.1:$($script:Porta)") { Send-Resposta $ctx 403 'text/plain' 'Proibido'; return }
        $caminho = $req.Url.AbsolutePath
        if ($caminho -eq '/entrar') {
            # Link do app: troca o código de uso único por um cookie de sessão (a chave não vai para o histórico)
            $cod = "$($req.QueryString['c'])"
            $val = $script:CodigosApp[$cod]
            if ($cod -and $val -and (Get-Date) -lt $val) {
                $script:CodigosApp.Remove($cod)
                $ctx.Response.StatusCode = 302
                $ctx.Response.Headers.Add('Set-Cookie', "gsess=$($script:Token); Path=/; HttpOnly; SameSite=Strict")
                $ctx.Response.Headers.Add('Location', '/')
                $ctx.Response.Headers.Add('Cache-Control', 'no-store')
                $ctx.Response.Close(); return
            }
            Send-Resposta $ctx 403 'text/html; charset=utf-8' '<!doctype html><meta charset="utf-8"><title>WebGuardian</title><body style="font:15px Segoe UI;background:#08090a;color:#d0d6e0;padding:40px">Este link de entrada já foi usado ou expirou. Feche esta janela e abra o WebGuardian de novo.</body>'
            return
        }
        if ($caminho -eq '/') {
            $cookie = $req.Cookies['gsess']
            $okCookie = $cookie -and $cookie.Value -eq $script:Token
            if ($req.QueryString['t'] -ne $script:Token -and -not $okCookie) {
                Send-Resposta $ctx 403 'text/html; charset=utf-8' '<!doctype html><meta charset="utf-8"><title>WebGuardian</title><body style="font:15px Segoe UI;background:#08090a;color:#d0d6e0;padding:40px">Sessão encerrada. Feche esta janela e abra o WebGuardian de novo.</body>'
                return
            }
            Send-Resposta $ctx 200 'text/html; charset=utf-8' $script:HtmlPainel; return
        }
        if ($req.Headers['X-Token'] -ne $script:Token) { Send-Resposta $ctx 403 'text/plain' 'Proibido'; return }
        if ($caminho -eq '/ping') { Send-Resposta $ctx 200 'text/plain' 'ok'; return }
        if ($caminho -eq '/api/estado' -and $req.HttpMethod -eq 'GET') {
            Send-Resposta $ctx 200 'application/json; charset=utf-8' (ConvertTo-Json -InputObject (Get-EstadoPainel) -Depth 6 -Compress); return
        }
        if ($caminho -eq '/api/acao' -and $req.HttpMethod -eq 'POST') {
            $leitor = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)
            $corpo = $leitor.ReadToEnd() | ConvertFrom-Json
            $id = "$($corpo.id)"
            $msg = switch ("$($corpo.acao)") {
                'liberar'         { Invoke-AcaoItem 'liberar' $id }
                'apagar'          { Invoke-AcaoItem 'apagar' $id }
                'isolarRede'      { Invoke-IsolarRede }
                'restaurarRede'   { Invoke-RestaurarRede }
                'scanRapido'      { Start-Varredura 'rapida' }
                'scanCompleto'    { Start-Varredura 'completa' }
                'atualizarDef'    { Start-AtualizacaoDefender 'pedido no painel' }
                'limparDownloads' { Clear-DownloadsVerificados }
                'limparAmeacas'   { (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Set-Content $ArqAmeacasOcultas -Encoding ASCII
                                    $script:Cache.Remove('defender')
                                    Write-Log 'INFO' 'Lista de ameacas detectadas limpa no painel (o historico do Defender foi mantido)'
                                    'Lista de ameacas limpa. O historico oficial continua em Seguranca do Windows > Historico de protecao.' }
                'pua'             { # bloqueio de aplicativos potencialmente indesejados (adware em instaladores)
                                    try {
                                        if ($id -eq 'ligar') { Set-MpPreference -PUAProtection Enabled -ErrorAction Stop; Write-Log 'INFO' 'Bloqueio de apps indesejados (PUA) LIGADO pelo usuario'; 'Bloqueio de aplicativos indesejados ligado.' }
                                        else { Set-MpPreference -PUAProtection AuditMode -ErrorAction Stop; Write-Log 'INFO' 'Bloqueio de apps indesejados (PUA) voltou ao modo auditoria pelo usuario'; 'Bloqueio de aplicativos indesejados voltou ao modo so auditoria.' }
                                    } catch { "Erro: o Windows nao permitiu a mudanca ($($_.Exception.Message))" }
                                    $script:Cache.Remove('defender') }
                'nuvem'           { # nível de bloqueio na nuvem da Microsoft
                                    try {
                                        if ($id -eq 'alto') { Set-MpPreference -CloudBlockLevel High -ErrorAction Stop; Write-Log 'INFO' 'Bloqueio na nuvem do Defender em nivel ALTO pelo usuario'; 'Bloqueio na nuvem em nivel alto.' }
                                        else { Set-MpPreference -CloudBlockLevel Default -ErrorAction Stop; Write-Log 'INFO' 'Bloqueio na nuvem do Defender voltou ao padrao pelo usuario'; 'Bloqueio na nuvem voltou ao padrao.' }
                                    } catch { "Erro: o Windows nao permitiu a mudanca ($($_.Exception.Message))" }
                                    $script:Cache.Remove('defender') }
                'scanOffline'     { Write-Log 'INFO' 'Verificacao OFFLINE solicitada - reiniciando'; Start-MpWDOScan; 'O computador vai reiniciar para a verificacao offline.' }
                'iniciarMonitor'  { Start-ScheduledTask -TaskName $NomeTarefa -ErrorAction SilentlyContinue; 'Monitor iniciado.' }
                'limparHistorico' { $Q = @(Get-Quarentena | Where-Object Estado -eq 'ISOLADO'); Save-Quarentena $Q; 'Historico limpo (itens pendentes mantidos).' }
                default           { 'Acao desconhecida.' }
            }
            Send-Resposta $ctx 200 'application/json; charset=utf-8' (ConvertTo-Json -InputObject @{ mensagem = "$msg" } -Compress); return
        }
        Send-Resposta $ctx 404 'text/plain' 'Nao encontrado'
    } catch {
        try { Send-Resposta $ctx 500 'application/json; charset=utf-8' (ConvertTo-Json -InputObject @{ mensagem = "Erro: $_" } -Compress) } catch { }
    }
}

function Step-Painel {
    # Atende os pedidos do navegador que chegaram (não bloqueia). Usado dentro do monitor.
    if (-not $script:Ouvinte) { return }
    if (-not $script:PedidoAtual) { $script:PedidoAtual = $script:Ouvinte.BeginGetContext($null, $null) }
    while ($script:PedidoAtual.IsCompleted) {
        try { Invoke-PedidoPainel ($script:Ouvinte.EndGetContext($script:PedidoAtual)) } catch { }
        $script:PedidoAtual = $script:Ouvinte.BeginGetContext($null, $null)
    }
}

function Test-GatilhoPainel {
    # O atalho da Área de Trabalho cria este arquivo; o monitor abre o painel e apaga o arquivo
    if (Test-Path $ArqGatilho) {
        Remove-Item $ArqGatilho -Force -ErrorAction SilentlyContinue
        Open-Painel
    }
    # O app WebGuardian.exe pediu um link: responde com um código de uso único (60 s)
    if ((Test-Path $ArqGatilhoApp) -and $script:UrlPainel) {
        Remove-Item $ArqGatilhoApp -Force -ErrorAction SilentlyContinue
        foreach ($k in @($script:CodigosApp.Keys)) { if ($script:CodigosApp[$k] -lt (Get-Date)) { $script:CodigosApp.Remove($k) } }
        $cod = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
        $script:CodigosApp[$cod] = (Get-Date).AddSeconds(60)
        $tmp = "$ArqUrlApp.tmp"
        [IO.File]::WriteAllText($tmp, "http://127.0.0.1:$($script:Porta)/entrar?c=$cod")
        Move-Item $tmp $ArqUrlApp -Force
    }
}

function Build-App([string]$Origem) {
    # O WebGuardian.exe não vem pronto no repositório: é compilado neste PC a partir de app\GuardiaoApp.cs
    # (usa o compilador C# que já vem no Windows; nada é baixado).
    $exe = Join-Path $Origem 'WebGuardian.exe'
    if (Test-Path $exe) { return $true }
    $comp = Join-Path $Origem 'app\compilar.ps1'
    if (-not (Test-Path $comp)) { return $false }
    Write-Host 'Compilando o app WebGuardian.exe neste computador...'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $comp | Out-Host
    if (Test-Path $exe) { return $true }
    Write-Host 'Nao foi possivel compilar o app. O painel continua funcionando pelo navegador.' -ForegroundColor Yellow
    return $false
}

function Unblock-Origem([string]$Origem) {
    # Arquivos baixados da internet (ZIP do GitHub) vêm marcados como bloqueados pelo Windows
    Get-ChildItem -LiteralPath $Origem -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
}

function Confirm-OrigemOficial([string]$Origem, [string]$Acao) {
    # Antes de instalar/atualizar: a pasta baixada é a versão oficial, sem nenhum arquivo alterado?
    $v = Test-Autenticidade (Join-Path $Origem 'ASSINATURA') $Origem
    if ($v.estado -eq 'oficial') {
        Write-Host "Versao oficial verificada: $($v.versao), assinatura $($v.impressao) ($($v.conferidos) arquivos conferidos)" -ForegroundColor Green
        return $true
    }
    Write-Host ''
    Write-Host '!!! ATENCAO: ESTA COPIA DO WEBGUARDIAN NAO E A VERSAO OFICIAL OU FOI ALTERADA !!!' -ForegroundColor Red
    foreach ($p in @($v.problemas | Select-Object -First 12)) { Write-Host "  - $p" -ForegroundColor Red }
    Write-Host "Baixe a versao oficial somente em $FonteOficial" -ForegroundColor Yellow
    Write-Log 'ALERTA' "Tentativa de $Acao uma copia NAO oficial do WebGuardian ($($v.estado)): $(@($v.problemas) -join '; ')"
    $resp = $null
    try { $resp = Read-Host "Para $Acao mesmo assim (NAO recomendado), digite CONTINUAR. Para cancelar, so aperte Enter" } catch { }
    if ($resp -ceq 'CONTINUAR') { Write-Log 'ALERTA' "Copia nao oficial aceita pelo usuario para $Acao"; return $true }
    return $false
}

function Copy-AssinaturaInstalada([string]$Origem) {
    # A assinatura vai junto para C:\ProgramData\Guardiao\assinatura: o monitor confere os arquivos instalados
    $dest = Join-Path $Pasta 'assinatura'
    Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue
    $orig = Join-Path $Origem 'ASSINATURA'
    if (Test-Path -LiteralPath (Join-Path $orig 'manifesto.json')) {
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item -LiteralPath (Join-Path $orig 'manifesto.json'), (Join-Path $orig 'manifesto.sig') -Destination $dest -Force -ErrorAction SilentlyContinue
    }
}

$script:Autenticidade = $null
$script:ProxAutenticidade = [datetime]::MinValue
function Update-Autenticidade {
    # Confere os arquivos INSTALADOS contra a assinatura oficial (na partida e a cada 10 min).
    # Pega, por exemplo, um programa malicioso que tente trocar o WebGuardian por uma versão adulterada.
    $mapa = @{ 'WebGuardian.ps1' = (Join-Path $Pasta 'Guardiao.ps1'); 'painel.html' = (Join-Path $Pasta 'painel.html') }
    $v = Test-Autenticidade (Join-Path $Pasta 'assinatura') $Pasta $mapa
    $antes = $script:Autenticidade
    $script:Autenticidade = $v
    $script:ProxAutenticidade = (Get-Date).AddMinutes(10)
    $detalhe = @($v.problemas) -join '; '
    if (-not $antes) {
        if ($v.estado -eq 'oficial') { Write-Log 'INFO' "Versao oficial verificada: $($v.versao), assinatura $($v.impressao)" }
        else { Write-Log 'ALERTA' "Esta instalacao do WebGuardian NAO e a versao oficial ($($v.estado)): $detalhe" }
    } elseif ($antes.estado -eq 'oficial' -and $v.estado -ne 'oficial') {
        Write-Log 'CRITICO' "Arquivos do WebGuardian foram ALTERADOS depois de instalados: $detalhe"
        Show-Alerta 'WebGuardian: CRITICO' 'Os arquivos do WebGuardian foram alterados por alguem ou por algum programa. Reinstale a versao oficial.'
    } elseif ($antes.estado -ne 'oficial' -and $v.estado -eq 'oficial') {
        Write-Log 'INFO' "Versao oficial verificada: $($v.versao), assinatura $($v.impressao)"
    }
}

$NomeAtalhoAntigo = 'Guardi' + [char]0xE3 + 'o.lnk'   # "Guardião.lnk" (versões até 1.6.1)

function Set-AtalhosApp([string]$Exe, [string]$Nome) {
    # Cria os atalhos no Menu Iniciar e na Área de Trabalho
    $shell = New-Object -ComObject WScript.Shell
    foreach ($dir in [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs')) {
        try {
            $lnk = $shell.CreateShortcut((Join-Path $dir "$Nome.lnk"))
            $lnk.TargetPath = $Exe; $lnk.WorkingDirectory = (Split-Path $Exe); $lnk.IconLocation = "$Exe,0"
            $lnk.Description = "$Nome - painel de protecao"
            $lnk.Save()
        } catch { }
    }
}
function Remove-AtalhosApp([string]$Arquivo) {
    foreach ($dir in [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs')) { Remove-Item (Join-Path $dir $Arquivo) -ErrorAction SilentlyContinue }
}

function Install-App([string]$Origem) {
    # Instala o WebGuardian.exe em C:\ProgramData\Guardiao\app (usuários só leem/executam; só Administrador altera)
    $exeOrig = Join-Path $Origem 'WebGuardian.exe'
    if (-not (Test-Path $exeOrig)) { return $false }
    $dirApp = Join-Path $Pasta 'app'
    New-Item -ItemType Directory -Force -Path $dirApp | Out-Null
    icacls $dirApp /grant '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    Copy-Item $exeOrig (Join-Path $dirApp 'WebGuardian.exe') -Force
    Set-AtalhosApp (Join-Path $dirApp 'WebGuardian.exe') 'WebGuardian'
    # nome antigo: troca os atalhos "Guardião" pelos novos (o Guardiao.exe antigo fica só para a volta automática)
    Remove-AtalhosApp $NomeAtalhoAntigo
    Remove-Item (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Painel Guardiao.lnk') -ErrorAction SilentlyContinue
    return $true
}

function Start-Painel {
    # Modo avulso: usado só quando o monitor não está rodando
    $url = Test-PainelAtivo -Timeout 3 -AceitarOcupado
    if ($url) { Start-Process $url; return }
    if (-not (New-ServidorPainel)) { Write-Host 'Nao consegui abrir o painel.' -ForegroundColor Red; Start-Sleep 8; return }
    Start-Process $script:UrlPainel
    Write-Host 'Painel do WebGuardian aberto no navegador (modo avulso, o monitor nao esta rodando).' -ForegroundColor Cyan
    Write-Host 'Pode minimizar esta janela. Ela fecha sozinha 2 minutos depois que voce fechar a aba.'
    try {
        while ($script:Ouvinte.IsListening) {
            $ar = $script:Ouvinte.BeginGetContext($null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne(120000)) { break }
            Invoke-PedidoPainel ($script:Ouvinte.EndGetContext($ar))
        }
    } finally {
        $script:Ouvinte.Stop(); $script:Ouvinte.Close()
        Remove-Item $ArqPainel -ErrorAction SilentlyContinue
    }
}

# ===================== PROTEÇÃO POR SENHA DO DONO DO PC =====================
# Desinstalar (e reinstalar por outra conta) exige a SENHA do Windows de quem instalou.
$ArqConfig = Join-Path $Pasta 'config.json'

if (-not ('Guardiao.Auth' -as [type])) {
    Add-Type -Namespace Guardiao -Name Auth -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern bool LogonUser(string user, string domain, string password, int logonType, int provider, out IntPtr token);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
'@
}

function Get-Dono {
    if (Test-Path $ArqConfig) { try { return (Get-Content $ArqConfig -Raw | ConvertFrom-Json) } catch { } }
    return $null
}

function Test-SenhaDono([string]$Usuario, [string]$Senha, [string]$SidDono) {
    # Valida a senha no próprio Windows e confere se a conta é mesmo a do dono (pelo SID)
    if ([string]::IsNullOrEmpty($Senha)) { return $false }
    $dominio = '.'; $nome = $Usuario
    if ($Usuario -match '^(.+?)\\(.+)$') {
        $dominio = $Matches[1]; $nome = $Matches[2]
        if ($dominio -eq $env:COMPUTERNAME) { $dominio = '.' }
    } elseif ($Usuario -match '@') { $dominio = $null }
    foreach ($tipo in 2, 8) {   # 2 = interativo, 8 = rede (texto claro, só local)
        $tok = [IntPtr]::Zero
        if ([Guardiao.Auth]::LogonUser($nome, $dominio, $Senha, $tipo, 0, [ref]$tok)) {
            try { $sid = (New-Object System.Security.Principal.WindowsIdentity($tok)).User.Value }
            finally { [Guardiao.Auth]::CloseHandle($tok) | Out-Null }
            return ($sid -eq $SidDono)
        }
    }
    return $false
}

function Confirm-SenhaDono([string]$Motivo) {
    $dono = Get-Dono
    if ($dono) { $sidDono = $dono.SidDono; $nomeDono = $dono.UsuarioDono }
    else { $sidDono = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $nomeDono = "$env:USERDOMAIN\$env:USERNAME" }
    for ($i = 1; $i -le 3; $i++) {
        $cred = Get-Credential -UserName $nomeDono -Message "$Motivo`nDigite a SENHA do Windows da conta $nomeDono (nao o PIN). Se a conta for Microsoft, e a senha da conta Microsoft. Tentativa $i de 3."
        if (-not $cred) { Write-Log 'ALERTA' "$Motivo - cancelado pelo usuario"; return $false }
        if (Test-SenhaDono $cred.UserName $cred.GetNetworkCredential().Password $sidDono) {
            Write-Log 'INFO' "$Motivo - senha do dono confirmada"
            return $true
        }
        Write-Log 'ALERTA' "$Motivo - senha incorreta (tentativa $i de 3)"
        Write-Host 'Senha incorreta.' -ForegroundColor Red
    }
    Write-Log 'CRITICO' "$Motivo - BLOQUEADO apos 3 senhas incorretas"
    Show-Alerta 'WebGuardian: CRITICO' 'Alguem tentou desinstalar o WebGuardian com senha errada 3 vezes.'
    return $false
}

# ================================ COMANDOS ================================
switch ($PSCmdlet.ParameterSetName) {

    'Painel' { Start-Painel }

    'Status' {
        $itens = @(Get-Quarentena)
        if (-not $itens.Count) { Write-Host 'Nada em quarentena.' -ForegroundColor Green; break }
        $itens | Format-Table Id, Estado, Tipo, Alvo, Motivo, Quando -AutoSize -Wrap
        Write-Host "Log completo: $ArqLog"
    }

    'Liberar'       { Write-Host (Invoke-AcaoItem 'liberar' $Liberar) }
    'Apagar'        { Write-Host (Invoke-AcaoItem 'apagar' $Apagar) }
    'Confirmar'     { Write-Host (Invoke-AcaoItem 'confirmar' $Confirmar) }
    'IsolarRede'    { Write-Host (Invoke-IsolarRede) -ForegroundColor Red }
    'RestaurarRede' { Write-Host (Invoke-RestaurarRede) -ForegroundColor Green }

    'Instalar' {
        # Dono do PC: quem instalou primeiro. Outra conta só reinstala com a senha do dono.
        $eu = [Security.Principal.WindowsIdentity]::GetCurrent()
        $dono = Get-Dono
        if ($dono -and $dono.SidDono -ne $eu.User.Value) {
            if (-not (Confirm-SenhaDono 'Reinstalacao do WebGuardian por outra conta')) {
                Write-Host 'Instalacao CANCELADA.' -ForegroundColor Red; Read-Host 'Pressione Enter para fechar' | Out-Null; break
            }
        }
        if (-not $dono) {
            @{ SidDono = $eu.User.Value; UsuarioDono = $eu.Name; Desde = (Get-Date -Format 'yyyy-MM-dd HH:mm') } |
                ConvertTo-Json | Set-Content $ArqConfig -Encoding UTF8
        }
        $destino = Join-Path $Pasta 'Guardiao.ps1'
        $origemHtml = Join-Path $PSScriptRoot 'painel.html'
        # Só instala sem perguntar se a pasta for a versão oficial assinada, sem nenhum arquivo alterado
        if ($PSScriptRoot -ne $Pasta -and -not (Confirm-OrigemOficial $PSScriptRoot 'instalar')) {
            Write-Host 'Instalacao CANCELADA. Nada foi alterado no PC.' -ForegroundColor Red; Read-Host 'Pressione Enter para fechar' | Out-Null; break
        }
        if ($PSCommandPath -ne $destino) { Copy-Item $PSCommandPath $destino -Force }
        if ((Test-Path $origemHtml) -and $PSScriptRoot -ne $Pasta) { Copy-Item $origemHtml (Join-Path $Pasta 'painel.html') -Force }
        if ($PSScriptRoot -ne $Pasta) { Copy-AssinaturaInstalada $PSScriptRoot }
        # Ativa auditoria de logon/contas (no Windows Home costuma estar parcial)
        auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null  # Logon
        auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null  # Contas de usuario
        auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null  # Grupos de seguranca
        $acao = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$destino`" -Monitorar"
        $gat  = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
        $prin = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
        $conf = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $NomeTarefa -Action $acao -Trigger $gat -Principal $prin -Settings $conf -Force | Out-Null
        # Reinicia o monitor para carregar a versão nova
        Stop-ScheduledTask -TaskName $NomeTarefa -ErrorAction SilentlyContinue
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*Guardiao.ps1*-Monitorar*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-ScheduledTask -TaskName $NomeTarefa

        # App WebGuardian.exe (atalhos "WebGuardian" no Menu Iniciar e na Área de Trabalho).
        # Sem o .exe na pasta, cai no atalho antigo, que abre o painel no navegador.
        Unblock-Origem $DirScript
        Build-App $DirScript | Out-Null
        $temApp = Install-App $DirScript
        if (-not $temApp) { try {
            $atalho = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Painel Guardiao.lnk'
            $lnk = (New-Object -ComObject WScript.Shell).CreateShortcut($atalho)
            $lnk.TargetPath = 'powershell.exe'
            $cmd = '$g = Join-Path $env:LOCALAPPDATA ''Guardiao\abrir-painel''; New-Item -ItemType File -Force -Path $g | Out-Null; ' +
                   'for ($i = 0; $i -lt 25 -and (Test-Path $g); $i++) { Start-Sleep -Milliseconds 200 }; ' +
                   'if (Test-Path $g) { Remove-Item $g; Start-Process powershell -Verb RunAs -ArgumentList ''-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File "' + $destino + '" -Painel'' }'
            $lnk.Arguments = "-NoProfile -WindowStyle Hidden -Command `"$($cmd.Replace('"', '\"'))`""
            $lnk.WindowStyle = 7
            $lnk.IconLocation = 'imageres.dll,101'
            $lnk.Save()
        } catch { } }

        Write-Log 'INFO' "WebGuardian $VersaoGuardiao instalado (app: $temApp)"
        Write-Host ''
        Write-Host '=============================================================' -ForegroundColor Green
        Write-Host ' WEBGUARDIAN INSTALADO E MONITORANDO' -ForegroundColor Green
        Write-Host ' - Ja esta rodando em segundo plano (inicia sozinho no logon)' -ForegroundColor Green
        Write-Host ' - Icone de escudo perto do relogio: 2 cliques abre o painel' -ForegroundColor Green
        if ($temApp) { Write-Host ' - App "WebGuardian" no Menu Iniciar e na Area de Trabalho' -ForegroundColor Green }
        else { Write-Host ' - Atalho "Painel Guardiao" na Area de Trabalho' -ForegroundColor Green }
        Write-Host '=============================================================' -ForegroundColor Green
        Write-Host 'Abrindo o painel' -NoNewline
        $url = $null
        $url = Wait-PainelAtivo 90
        if ($url) { if ($temApp) { Open-Painel } else { Start-Process $url }; Start-Sleep 2 } else { Start-Painel }
    }

    'Menu' {
        while ($true) {
            Clear-Host
            $pend = @(Get-Quarentena | Where-Object Estado -eq 'ISOLADO').Count
            Write-Host '================ WEBGUARDIAN (modo texto) ================' -ForegroundColor Cyan
            Write-Host " Itens isolados aguardando voce: $pend"
            Write-Host ' 1) Ver itens   2) Liberar   3) Apagar ameaca   4) Abrir painel HTML   0) Sair'
            switch (Read-Host 'Escolha') {
                '1' { & $PSCommandPath -Status }
                '2' { $id = Read-Host 'Numero do item (ou "todos")'; if ($id) { & $PSCommandPath -Liberar $id } }
                '3' { $id = Read-Host 'Numero do item'; if ($id) { & $PSCommandPath -Apagar $id } }
                '4' { Open-Painel }
                '0' { exit }
            }
            Read-Host "`nEnter para voltar" | Out-Null
        }
    }

    'Atualizar' {
        Write-Host '=== ATUALIZAR O WEBGUARDIAN ===' -ForegroundColor Cyan
        $destino = Join-Path $Pasta 'Guardiao.ps1'
        if (-not (Test-Path $destino) -or -not (Get-ScheduledTask -TaskName $NomeTarefa -ErrorAction SilentlyContinue)) {
            Write-Host 'O WebGuardian ainda nao esta instalado neste PC. Use INSTALAR WEBGUARDIAN.bat.' -ForegroundColor Yellow
            Read-Host 'Pressione Enter para fechar' | Out-Null; break
        }
        if ($DirScript -eq $Pasta) {
            Write-Host 'Rode o ATUALIZAR WEBGUARDIAN.bat a partir da pasta onde voce baixou/extraiu a versao nova do WebGuardian.' -ForegroundColor Yellow
            Read-Host 'Pressione Enter para fechar' | Out-Null; break
        }
        # Outra conta só atualiza com a senha do dono (igual à reinstalação)
        $dono = Get-Dono
        if ($dono -and $dono.SidDono -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
            if (-not (Confirm-SenhaDono 'Atualizacao do WebGuardian por outra conta')) { Write-Host 'Atualizacao CANCELADA.' -ForegroundColor Red; Read-Host 'Pressione Enter para fechar' | Out-Null; break }
        }
        $novoHtml = Join-Path $DirScript 'painel.html'
        if (-not (Test-Path $novoHtml) -or -not ((Get-Content $novoHtml -Raw -Encoding UTF8).Contains('__TOKEN__'))) {
            Write-Host "painel.html nao encontrado ou invalido em $DirScript. Nada foi alterado." -ForegroundColor Red
            Read-Host 'Pressione Enter para fechar' | Out-Null; break
        }
        # A versão nova é a oficial, sem nenhum arquivo alterado?
        if (-not (Confirm-OrigemOficial $DirScript 'atualizar com')) {
            Write-Host 'Atualizacao CANCELADA. A versao instalada continua igual.' -ForegroundColor Red; Read-Host 'Pressione Enter para fechar' | Out-Null; break
        }
        $vAtual = 'anterior a 1.5.0'
        $m = Select-String -LiteralPath $destino -Pattern "^\`$VersaoGuardiao\s*=\s*'([^']+)'" | Select-Object -First 1
        if ($m) { $vAtual = $m.Matches[0].Groups[1].Value }
        $mudouScript = (Get-FileHash $destino).Hash -ne (Get-FileHash $PSCommandPath).Hash
        $htmlInst = Join-Path $Pasta 'painel.html'
        $mudouPainel = -not (Test-Path $htmlInst) -or (Get-FileHash $htmlInst).Hash -ne (Get-FileHash $novoHtml).Hash
        Unblock-Origem $DirScript
        Build-App $DirScript | Out-Null
        $novoExe = Join-Path $DirScript 'WebGuardian.exe'; $exeInst = Join-Path $Pasta 'app\WebGuardian.exe'
        $mudouApp = (Test-Path $novoExe) -and (-not (Test-Path $exeInst) -or (Get-FileHash $exeInst).Hash -ne (Get-FileHash $novoExe).Hash)
        if ($mudouApp) { $mudouPainel = $true }
        Write-Host "Versao instalada: $vAtual   ->   versao nova: $VersaoGuardiao"
        Write-Host ("Programa: {0}   Painel: {1}   App: {2}" -f $(if ($mudouScript) { 'muda' } else { 'igual' }), $(if ($mudouPainel) { 'muda' } else { 'igual' }), $(if ($mudouApp) { 'muda' } elseif (Test-Path $novoExe) { 'igual' } else { 'nao incluido' }))
        if (-not $mudouScript -and -not $mudouPainel) {
            Copy-AssinaturaInstalada $DirScript   # o monitor reconfere em até 10 min
            Write-Host 'Ja esta tudo atualizado. Nada a fazer.' -ForegroundColor Green
            Read-Host 'Pressione Enter para fechar' | Out-Null; break
        }

        # 1) backup da versão instalada (para voltar atrás se precisar)
        $rotulo = 'versao-antiga'; if ($m) { $rotulo = "v$vAtual" }
        $bk = Join-Path $Pasta ("backup\" + (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss') + "_$rotulo")
        New-Item -ItemType Directory -Force -Path $bk | Out-Null
        Copy-Item $destino, $htmlInst -Destination $bk -Force -ErrorAction SilentlyContinue
        if (Test-Path $exeInst) { Copy-Item $exeInst -Destination $bk -Force -ErrorAction SilentlyContinue }
        $assInst = Join-Path $Pasta 'assinatura'
        if (Test-Path $assInst) { Copy-Item $assInst -Destination (Join-Path $bk 'assinatura') -Recurse -Force -ErrorAction SilentlyContinue }
        Write-Host "Backup da versao anterior: $bk"

        # 2) para o monitor e o painel antigos
        Stop-ScheduledTask -TaskName $NomeTarefa -ErrorAction SilentlyContinue
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.ProcessId -ne $PID -and ($_.CommandLine -like '*Guardiao.ps1*-Monitorar*' -or $_.CommandLine -like '*Guardiao.ps1*-Painel*') } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Remove-Item $ArqPainel -ErrorAction SilentlyContinue
        Start-Sleep 1

        # 3) copia a versão nova e sobe o monitor
        Copy-Item $PSCommandPath $destino -Force
        Copy-Item $novoHtml $htmlInst -Force
        Copy-AssinaturaInstalada $DirScript
        $temApp = Install-App $DirScript
        if ($temApp) { Write-Host 'App WebGuardian.exe instalado (Menu Iniciar e Area de Trabalho)' }
        Start-ScheduledTask -TaskName $NomeTarefa
        Write-Host 'Iniciando a versao nova (o painel leva uns 15 s para ficar pronto)' -NoNewline
        $url = $null
        $url = Wait-PainelAtivo 90

        if ($url) {
            Write-Log 'INFO' "WebGuardian atualizado de $vAtual para $VersaoGuardiao (backup em $bk)"
            Write-Host ''
            Write-Host "WEBGUARDIAN ATUALIZADO PARA A VERSAO $VersaoGuardiao" -ForegroundColor Green
            if ($temApp) { Open-Painel } else { Start-Process $url }
        } else {
            # 4) a versão nova não subiu: volta a anterior automaticamente
            Write-Host 'A versao nova nao respondeu em 90 s. Voltando para a versao anterior...' -ForegroundColor Red
            Stop-ScheduledTask -TaskName $NomeTarefa -ErrorAction SilentlyContinue
            Copy-Item (Join-Path $bk 'Guardiao.ps1') $destino -Force
            if (Test-Path (Join-Path $bk 'painel.html')) { Copy-Item (Join-Path $bk 'painel.html') $htmlInst -Force }
            Remove-Item $assInst -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path (Join-Path $bk 'assinatura')) { Copy-Item (Join-Path $bk 'assinatura') $assInst -Recurse -Force }
            if (Test-Path (Join-Path $bk 'WebGuardian.exe')) { Copy-Item (Join-Path $bk 'WebGuardian.exe') $exeInst -Force }
            elseif ($temApp) {
                # a versão anterior era o "Guardião": volta o app e os atalhos antigos
                Remove-AtalhosApp 'WebGuardian.lnk'
                Remove-Item $exeInst -Force -ErrorAction SilentlyContinue
                $exeAntigo = Join-Path $Pasta 'app\Guardiao.exe'
                if (Test-Path $exeAntigo) { Set-AtalhosApp $exeAntigo ('Guardi' + [char]0xE3 + 'o') }
                else { Remove-Item (Join-Path $Pasta 'app') -Recurse -Force -ErrorAction SilentlyContinue }
            }
            Start-ScheduledTask -TaskName $NomeTarefa
            Write-Log 'ALERTA' "Atualizacao para $VersaoGuardiao falhou ao iniciar; versao $vAtual restaurada"
            Write-Host "Versao $vAtual restaurada. Nada se perdeu. Me mande o arquivo $ArqLog para eu ver o que houve." -ForegroundColor Yellow
        }
        Read-Host 'Pressione Enter para fechar' | Out-Null
    }

    'Desinstalar' {
        Write-Host '=== DESINSTALAR O WEBGUARDIAN ===' -ForegroundColor Yellow
        if (-not (Confirm-SenhaDono 'Desinstalacao do WebGuardian')) {
            Write-Host 'Desinstalacao CANCELADA. O WebGuardian continua protegendo o PC.' -ForegroundColor Red
            Read-Host 'Pressione Enter para fechar' | Out-Null
            break
        }
        Unregister-ScheduledTask -TaskName $NomeTarefa -Confirm:$false -ErrorAction SilentlyContinue
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*Guardiao.ps1*-Monitorar*' -or $_.CommandLine -like '*Guardiao.ps1*-Painel*' } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Remove-Item (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Painel Guardiao.lnk') -ErrorAction SilentlyContinue
        Remove-AtalhosApp 'WebGuardian.lnk'; Remove-AtalhosApp $NomeAtalhoAntigo
        Get-Process WebGuardian, Guardiao -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $Pasta 'app') -Recurse -Force -ErrorAction SilentlyContinue
        if ((Read-Host 'Remover tambem os BLOQUEIOS de firewall que o WebGuardian criou? (s/n)') -eq 's') {
            Get-NetFirewallRule -Group $GrupoFirewall -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            Write-Host 'Bloqueios de firewall removidos.'
        } else { Write-Host 'Bloqueios de firewall mantidos (IPs e programas continuam bloqueados).' }
        foreach ($arq in 'Guardiao.ps1', 'painel.html', 'painel_ativo.json', 'config.json') {
            Remove-Item (Join-Path $Pasta $arq) -Force -ErrorAction SilentlyContinue
        }
        Write-Log 'INFO' 'WebGuardian DESINSTALADO pelo dono (senha confirmada)'
        Write-Host ''
        Write-Host 'WebGuardian desinstalado. O historico (guardiao.log e quarentena.json) ficou em' -ForegroundColor Green
        Write-Host "$Pasta para consulta." -ForegroundColor Green
        Read-Host 'Pressione Enter para fechar' | Out-Null
    }

    'Monitorar' {
        # PC ligado de novo? arquiva a atividade da sessão anterior e começa do zero
        try { Start-SessaoAtividade } catch { $script:InicioSessao = Get-HoraLigado }
        if ($script:NovaSessao) { Write-Log 'INFO' "Nova sessão: PC ligado em $($script:InicioSessao.ToString('dd/MM/yyyy')) às $($script:InicioSessao.ToString('HH:mm')). A atividade da sessão anterior foi arquivada." $script:InicioSessao }
        Write-Log 'INFO' "WebGuardian $VersaoGuardiao iniciado (intervalo ${IntervaloSegundos}s, somente alertar: $SomenteAlertar)"
        Initialize-Icone
        try { Update-Autenticidade } catch { Write-Log 'INFO' "Erro ao conferir a assinatura oficial: $_" }
        # Painel fica sempre no ar dentro do monitor (abrir = instantâneo)
        if (-not (Test-Path $PastaUsuario)) { New-Item -ItemType Directory -Path $PastaUsuario -Force | Out-Null }
        Remove-Item $ArqGatilho -ErrorAction SilentlyContinue
        if (New-ServidorPainel) {
            Write-Log 'INFO' "Painel disponivel na porta $($script:Porta)"
            try { Get-EstadoPainel | Out-Null } catch { }   # aquece o cache: 1a abertura ja e rapida
        }
        Initialize-Base
        try { Start-VigiaDownloads } catch { Write-Log 'INFO' "Erro ao iniciar a verificacao de downloads: $_" }
        # Sessão nova: lê o registro de segurança desde que o PC ligou (quem entrou, senhas erradas, acessos remotos).
        # Só o WebGuardian reiniciou (ex.: atualização): olha os últimos 5 minutos.
        $desde = (Get-Date).AddMinutes(-5)
        if ($script:NovaSessao -and $script:InicioSessao) { $desde = $script:InicioSessao.AddMinutes(-1) }
        $ciclo = 0
        try {
            while ($true) {
                $agora = Get-Date
                try { Test-Logons    $desde } catch { Write-Log 'INFO' "Erro logons: $_" }
                Step-Painel
                try { Test-Servicos  $desde } catch { Write-Log 'INFO' "Erro servicos: $_" }
                try { Test-Conexoes         } catch { Write-Log 'INFO' "Erro conexoes: $_" }
                Step-Painel
                if ($ciclo % 4 -eq 0) {
                    try { Test-Persistencia } catch { Write-Log 'INFO' "Erro persistencia: $_" }
                    Step-Painel
                    try { Test-Defender     } catch { }
                }
                try { Get-EstadoVarredura | Out-Null } catch { }   # registra o fim da verificação mesmo com o painel fechado
                try { Step-AtualizacaoDefender } catch { Write-Log 'INFO' "Erro na atualizacao do Defender: $_" }   # base sempre em dia
                if ((Get-Date) -ge $script:ProxAutenticidade) { try { Update-Autenticidade } catch { } }   # arquivos instalados intactos?
                try { Step-VarreduraAutomatica } catch { Write-Log 'INFO' "Erro na verificacao automatica: $_" }   # 1x por dia, sem abrir nada
                $desde = $agora.AddSeconds(-10)   # sobreposicao; duplicados sao ignorados pelo RecordId
                $ciclo++
                # Espera atendendo: cliques no icone, atalho, o painel e os downloads
                $fim = (Get-Date).AddSeconds($IntervaloSegundos); $proxDl = Get-Date
                while ((Get-Date) -lt $fim) {
                    [System.Windows.Forms.Application]::DoEvents()
                    Step-Painel
                    Test-GatilhoPainel
                    if ((Get-Date) -ge $proxDl) { try { Step-Downloads } catch { Write-Log 'INFO' "Erro downloads: $_" }; $proxDl = (Get-Date).AddSeconds(1) }
                    Start-Sleep -Milliseconds 100
                }
            }
        } finally {
            Stop-VigiaDownloads
            if ($script:Ouvinte) { $script:Ouvinte.Stop() }
            Remove-Item $ArqPainel -ErrorAction SilentlyContinue
            if ($script:Icone) { $script:Icone.Visible = $false; $script:Icone.Dispose() }
        }
    }
}
