<#
  WebGuardian — ferramenta do MANTENEDOR para assinar uma versão oficial.
  Fonte oficial: https://github.com/LuizZanchetta/WebGuardian

  Quem só usa o WebGuardian NÃO precisa deste arquivo (para conferir uma cópia, use
  "VERIFICAR AUTENTICIDADE.bat"). Aqui não há segredo nenhum: a chave PRIVADA nunca fica
  no repositório. Ela mora no cofre de chaves do Windows, na conta de quem mantém o projeto,
  protegida pelo próprio Windows.

  Uso:
    .\assinar-versao.ps1 -CriarChave                           # só uma vez, no PC do mantenedor
    .\assinar-versao.ps1 -MostrarChave                         # chave pública + impressão digital
    .\assinar-versao.ps1 -Assinar "<pasta>" ["<pasta2>" ...]   # gera ASSINATURA\manifesto.json e .sig
    .\assinar-versao.ps1 -ExportarBackup "<arquivo>"           # cópia da chave, protegida por uma senha que VOCÊ digita
    .\assinar-versao.ps1 -ImportarBackup "<arquivo>"           # restaura a chave (ex.: depois de formatar o PC)
    .\assinar-versao.ps1 -PrepararRelease "<pasta do repo>" [-Versao 1.8.1]
                                                               # notas da release (do CHANGELOG.md) + link já preenchido

  Sem a chave privada ninguém consegue gerar uma assinatura que a chave pública oficial
  (embutida no WebGuardian.ps1) aceite. Quem alterar qualquer arquivo e trocar a chave para
  assinar de novo muda a IMPRESSÃO DIGITAL, que deixa de bater com a publicada na página oficial.
#>
[CmdletBinding(DefaultParameterSetName = 'Mostrar')]
param(
    [Parameter(ParameterSetName = 'Criar')][switch]$CriarChave,
    [Parameter(ParameterSetName = 'Mostrar')][switch]$MostrarChave,
    [Parameter(ParameterSetName = 'Assinar', Mandatory)][string[]]$Assinar,
    [Parameter(ParameterSetName = 'Exportar', Mandatory)][string]$ExportarBackup,
    [Parameter(ParameterSetName = 'Importar', Mandatory)][string]$ImportarBackup,
    [Parameter(ParameterSetName = 'Release', Mandatory)][string]$PrepararRelease,
    [Parameter(ParameterSetName = 'Release')][string]$Versao
)
$ErrorActionPreference = 'Stop'
$NomeCofre = 'WebGuardian-Assinatura-Oficial'

# Arquivos que formam uma versão oficial (caminhos relativos à pasta do WebGuardian)
$Nucleo = @(
    'WebGuardian.ps1', 'painel.html',
    'INSTALAR WEBGUARDIAN.bat', 'ATUALIZAR WEBGUARDIAN.bat', 'DESINSTALAR WEBGUARDIAN.bat', 'VERIFICAR AUTENTICIDADE.bat',
    'app/WebGuardianApp.cs', 'app/compilar.ps1', 'app/app.manifest', 'app/webguardian.ico',
    'ferramentas/assinar-versao.ps1'
)

# Usa EXATAMENTE as mesmas funções de conferência do WebGuardian.ps1 (mesmo cálculo dos dois lados)
$scriptWG = Join-Path (Split-Path $PSScriptRoot) 'WebGuardian.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptWG, [ref]$null, [ref]$null)
foreach ($a in $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -match '^\$(FonteOficial|ChavePublicaOficial|ExtTexto)$' }) { . ([scriptblock]::Create($a.Extent.Text)) }
foreach ($f in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -in 'Get-BytesCanonicos', 'Get-HashWG', 'Get-ImpressaoDigital', 'Test-Autenticidade' }, $false)) { . ([scriptblock]::Create($f.Extent.Text)) }

function Get-Cofre([switch]$Criar) {
    $csp = New-Object Security.Cryptography.CspParameters 24   # PROV_RSA_AES (aceita SHA-256)
    $csp.KeyContainerName = $NomeCofre
    if (-not $Criar) { $csp.Flags = [Security.Cryptography.CspProviderFlags]::UseExistingKey }
    try { $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider 3072, $csp }
    catch { if ($Criar) { throw } ; return $null }
    $rsa.PersistKeyInCsp = $true
    return $rsa
}

function Show-Chave($rsa) {
    $pub = $rsa.ToXmlString($false)
    Write-Host ''
    Write-Host "Impressao digital oficial: $(Get-ImpressaoDigital $pub)" -ForegroundColor Green
    Write-Host 'Chave publica (vai embutida no WebGuardian.ps1, em $ChavePublicaOficial):'
    Write-Host $pub
}

function Protect-Backup([byte[]]$Dados, [Security.SecureString]$Senha) {
    $sal = New-Object byte[] 16; $iv = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($sal); $rng.GetBytes($iv)
    $senhaTxt = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Senha))
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes $senhaTxt, $sal, 300000, ([Security.Cryptography.HashAlgorithmName]::SHA256)
    $chaves = $kdf.GetBytes(64); $senhaTxt = $null
    $aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $chaves[0..31]; $aes.IV = $iv
    $cifrado = $aes.CreateEncryptor().TransformFinalBlock($Dados, 0, $Dados.Length)
    $corpo = [byte[]]($sal + $iv + $cifrado)
    $mac = (New-Object Security.Cryptography.HMACSHA256 (, [byte[]]$chaves[32..63])).ComputeHash($corpo)
    return [byte[]]([Text.Encoding]::ASCII.GetBytes('WGBK1') + $mac + $corpo)
}

function Unprotect-Backup([byte[]]$Arq, [Security.SecureString]$Senha) {
    if ([Text.Encoding]::ASCII.GetString($Arq, 0, 5) -ne 'WGBK1') { throw 'Arquivo de backup invalido.' }
    $mac = $Arq[5..36]; $corpo = [byte[]]$Arq[37..($Arq.Length - 1)]
    $sal = [byte[]]$corpo[0..15]; $iv = [byte[]]$corpo[16..31]; $cifrado = [byte[]]$corpo[32..($corpo.Length - 1)]
    $senhaTxt = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Senha))
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes $senhaTxt, $sal, 300000, ([Security.Cryptography.HashAlgorithmName]::SHA256)
    $chaves = $kdf.GetBytes(64); $senhaTxt = $null
    $conf = (New-Object Security.Cryptography.HMACSHA256 (, [byte[]]$chaves[32..63])).ComputeHash($corpo)
    if ([BitConverter]::ToString($conf) -ne [BitConverter]::ToString($mac)) { throw 'Senha errada ou backup danificado.' }
    $aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $chaves[0..31]; $aes.IV = $iv
    return $aes.CreateDecryptor().TransformFinalBlock($cifrado, 0, $cifrado.Length)
}

switch ($PSCmdlet.ParameterSetName) {
    'Criar' {
        if (Get-Cofre) { Write-Host 'A chave oficial ja existe neste PC. Nada foi alterado.' -ForegroundColor Yellow; Show-Chave (Get-Cofre); break }
        $rsa = Get-Cofre -Criar
        Write-Host 'Chave oficial RSA-3072 criada no cofre de chaves do Windows desta conta.' -ForegroundColor Green
        Write-Host 'Faca um backup com -ExportarBackup e guarde fora deste PC (pendrive, por exemplo).' -ForegroundColor Yellow
        Show-Chave $rsa
    }
    'Mostrar' {
        $rsa = Get-Cofre
        if (-not $rsa) { Write-Host 'Este PC nao tem a chave oficial. Use -CriarChave (so o mantenedor) ou -ImportarBackup.' -ForegroundColor Yellow; break }
        Show-Chave $rsa
    }
    'Assinar' {
        $rsa = Get-Cofre
        if (-not $rsa) { throw 'Este PC nao tem a chave oficial: nao da para assinar.' }
        if ($rsa.ToXmlString($false) -ne $ChavePublicaOficial) { throw 'A chave deste PC nao e a mesma embutida no WebGuardian.ps1 ($ChavePublicaOficial). Nada foi assinado.' }
        foreach ($pasta in $Assinar) {
            $pasta = (Resolve-Path -LiteralPath $pasta).Path
            $wg = Get-Content -LiteralPath (Join-Path $pasta 'WebGuardian.ps1') -Raw -Encoding UTF8
            if ($wg -notmatch "(?m)^\`$VersaoGuardiao\s*=\s*'([^']+)'") { throw "Versao nao encontrada em $pasta\WebGuardian.ps1" }
            $versao = $Matches[1]
            $linhas = foreach ($n in $Nucleo) {
                $cam = Join-Path $pasta ($n -replace '/', '\')
                if (-not (Test-Path -LiteralPath $cam)) { throw "Falta o arquivo $n em $pasta" }
                '    "{0}": "{1}"' -f $n, (Get-HashWG $cam)
            }
            $json = "{`n  `"produto`": `"WebGuardian`",`n  `"versao`": `"$versao`",`n  `"fonteOficial`": `"$FonteOficial`",`n" +
                    "  `"impressaoDigital`": `"$(Get-ImpressaoDigital $ChavePublicaOficial)`",`n  `"assinadoEm`": `"$(Get-Date -Format 'yyyy-MM-dd HH:mm')`",`n" +
                    "  `"arquivos`": {`n" + ($linhas -join ",`n") + "`n  }`n}`n"
            $bytes = [Text.Encoding]::UTF8.GetBytes($json)   # sem BOM, quebras LF
            $dirAss = Join-Path $pasta 'ASSINATURA'
            New-Item -ItemType Directory -Force $dirAss | Out-Null
            [IO.File]::WriteAllBytes((Join-Path $dirAss 'manifesto.json'), $bytes)
            $sig = $rsa.SignData((Get-BytesCanonicos $bytes), 'SHA256')
            [IO.File]::WriteAllText((Join-Path $dirAss 'manifesto.sig'), [Convert]::ToBase64String($sig) + "`n")
            $conf = Test-Autenticidade $dirAss $pasta
            if ($conf.estado -ne 'oficial') { throw "Conferencia falhou em ${pasta}: $($conf.estado) $($conf.problemas -join '; ')" }
            Write-Host "Assinado: $pasta  (versao $versao, $($conf.conferidos) arquivos, $($conf.impressao))" -ForegroundColor Green
        }
    }
    'Exportar' {
        $rsa = Get-Cofre
        if (-not $rsa) { throw 'Este PC nao tem a chave oficial.' }
        $s1 = Read-Host 'Crie uma senha para o backup (guarde-a bem)' -AsSecureString
        $s2 = Read-Host 'Repita a senha' -AsSecureString
        $t1 = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($s1))
        $t2 = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($s2))
        if ($t1 -cne $t2 -or $t1.Length -lt 10) { throw 'As senhas nao conferem ou tem menos de 10 caracteres.' }
        $t1 = $null; $t2 = $null
        [IO.File]::WriteAllBytes($ExportarBackup, (Protect-Backup ([Text.Encoding]::UTF8.GetBytes($rsa.ToXmlString($true))) $s1))
        Write-Host "Backup criado: $ExportarBackup  (NUNCA coloque este arquivo no GitHub)" -ForegroundColor Green
    }
    'Release' {
        # Notas da release no GitHub: a seção da versão no CHANGELOG.md + como instalar + autenticidade
        $pasta = (Resolve-Path -LiteralPath $PrepararRelease).Path
        if (-not $Versao) {
            $wg = Get-Content -LiteralPath (Join-Path $pasta 'WebGuardian.ps1') -Raw -Encoding UTF8
            if ($wg -notmatch "(?m)^\`$VersaoGuardiao\s*=\s*'([^']+)'") { throw 'Versao nao encontrada no WebGuardian.ps1' }
            $Versao = $Matches[1]
            # Só a versão ATUAL precisa estar assinada nesta pasta (versões antigas: a assinatura está no commit da etiqueta)
            $conf = Test-Autenticidade (Join-Path $pasta 'ASSINATURA') $pasta
            if ($conf.estado -ne 'oficial' -or $conf.versao -ne $Versao) { throw "A pasta nao e a versao oficial $Versao assinada ($($conf.estado) $($conf.versao)). Assine antes." }
        }
        $log = Get-Content -LiteralPath (Join-Path $pasta 'CHANGELOG.md') -Raw -Encoding UTF8
        $m = [regex]::Match($log, "(?ms)^## $([regex]::Escape($Versao))\b[^\r\n]*\r?\n(.*?)(?=^## |\z)")
        if (-not $m.Success) { throw "A versao $Versao nao esta no CHANGELOG.md. Escreva as notas antes." }
        $notas = $m.Groups[1].Value.Trim()
        $destaque = ''; if ($notas -match '^\*\*(.+?)\*\*') { $destaque = $Matches[1] }
        $titulo = "WebGuardian $Versao"; if ($destaque) { $titulo += " - $destaque" }
        $imp = Get-ImpressaoDigital $ChavePublicaOficial
        $corpo = @"
$notas

---

### Como instalar ou atualizar
1. Em **Assets**, logo abaixo, baixe **Source code (zip)**.
2. Clique com o botão direito no ZIP → **Propriedades** → marque **Desbloquear** → **OK**. Depois extraia.
3. Dê dois cliques em **``VERIFICAR AUTENTICIDADE.bat``**. Precisa aparecer **VERSÃO OFICIAL $Versao** e a impressão digital **``$imp``**.
4. Primeira vez: **``INSTALAR WEBGUARDIAN.bat``**. Já tem o WebGuardian: **``ATUALIZAR WEBGUARDIAN.bat``** (guarda um backup e volta sozinho para a versão anterior se algo der errado).

### Autenticidade
Versão assinada digitalmente. Impressão digital oficial: **``$imp``**.
Baixe somente daqui: $FonteOficial
"@
        $arq = Join-Path $env:TEMP "WebGuardian-release-v$Versao.md"
        [IO.File]::WriteAllText($arq, $corpo.Replace("`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
        $url = "$FonteOficial/releases/new?tag=v$Versao&title=$([uri]::EscapeDataString($titulo))&body=$([uri]::EscapeDataString($corpo.Replace("`r`n", "`n")))"
        Write-Host "Titulo: $titulo" -ForegroundColor Green
        Write-Host "Notas:  $arq"
        Write-Host "Antes de publicar: a etiqueta v$Versao precisa estar no GitHub (git push origin v$Versao)." -ForegroundColor Yellow
        Write-Host 'Link da release ja preenchida:'
        Write-Output $url
    }
    'Importar' {
        if (Get-Cofre) { throw 'Este PC ja tem uma chave oficial. Nada foi alterado.' }
        $s = Read-Host 'Senha do backup' -AsSecureString
        $xml = [Text.Encoding]::UTF8.GetString((Unprotect-Backup ([IO.File]::ReadAllBytes($ImportarBackup)) $s))
        $rsa = Get-Cofre -Criar; $rsa.FromXmlString($xml); $rsa.PersistKeyInCsp = $true
        Write-Host 'Chave oficial restaurada neste PC.' -ForegroundColor Green
        Show-Chave $rsa
    }
}
