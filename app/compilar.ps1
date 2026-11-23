# Compila o app do WebGuardian -> ..\WebGuardian.exe
# Versão oficial. Fonte oficial: https://github.com/LuizZanchetta/WebGuardian
# Assinatura digital oficial: WG-D0C5-ACA9-5777-6D53-ED11 (confira com VERIFICAR AUTENTICIDADE.bat)
# Usa só o que já vem no Windows: compilador C# do .NET Framework 4.8 (csc.exe).
# Uso: powershell -ExecutionPolicy Bypass -File app\compilar.ps1

$ErrorActionPreference = 'Stop'
$aqui  = Split-Path -Parent $MyInvocation.MyCommand.Path
$saida = Join-Path (Split-Path -Parent $aqui) 'WebGuardian.exe'
$icone = Join-Path $aqui 'webguardian.ico'

# ---------- 1) Ícone: escudo com check sobre quadrado azul (cores do painel) ----------
function New-IconeWebGuardian([string]$Arquivo) {
    Add-Type -AssemblyName System.Drawing
    $tamanhos = 16, 24, 32, 48, 64, 128, 256
    $pngs = @()
    foreach ($t in $tamanhos) {
        $bmp = New-Object System.Drawing.Bitmap $t, $t, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'; $g.Clear([System.Drawing.Color]::Transparent)
        $s = $t / 24.0
        # quadrado arredondado azul
        $r = [Math]::Max(2.0, 5.5 * $s); $m = 0.5 * $s; $w = $t - 2 * $m
        $fundo = New-Object System.Drawing.Drawing2D.GraphicsPath
        $fundo.AddArc($m, $m, 2*$r, 2*$r, 180, 90); $fundo.AddArc($m + $w - 2*$r, $m, 2*$r, 2*$r, 270, 90)
        $fundo.AddArc($m + $w - 2*$r, $m + $w - 2*$r, 2*$r, 2*$r, 0, 90); $fundo.AddArc($m, $m + $w - 2*$r, 2*$r, 2*$r, 90, 90); $fundo.CloseFigure()
        $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush ([System.Drawing.PointF]::new(0, 0)), ([System.Drawing.PointF]::new(0, $t)),
                ([System.Drawing.Color]::FromArgb(255, 74, 128, 236)), ([System.Drawing.Color]::FromArgb(255, 47, 96, 214))
        $g.FillPath($grad, $fundo)
        # escudo (mesmo desenho do painel), centralizado
        $esc = New-Object System.Drawing.Drawing2D.GraphicsPath
        $pts = @(@(12,4.6), @(6.2,7.0), @(6.2,11.2)) | ForEach-Object { [System.Drawing.PointF]::new($_[0]*$s, $_[1]*$s) }
        $esc.AddLine($pts[0], $pts[1]); $esc.AddLine($pts[1], $pts[2])
        $esc.AddBezier([System.Drawing.PointF]::new(6.2*$s, 11.2*$s), [System.Drawing.PointF]::new(6.2*$s, 15.1*$s), [System.Drawing.PointF]::new(8.7*$s, 18.3*$s), [System.Drawing.PointF]::new(12*$s, 19.5*$s))
        $esc.AddBezier([System.Drawing.PointF]::new(12*$s, 19.5*$s), [System.Drawing.PointF]::new(15.3*$s, 18.3*$s), [System.Drawing.PointF]::new(17.8*$s, 15.1*$s), [System.Drawing.PointF]::new(17.8*$s, 11.2*$s))
        $esc.AddLine([System.Drawing.PointF]::new(17.8*$s, 11.2*$s), [System.Drawing.PointF]::new(17.8*$s, 7.0*$s)); $esc.CloseFigure()
        $g.FillPath([System.Drawing.Brushes]::White, $esc)
        # check azul dentro do escudo
        $caneta = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 47, 96, 214)), ([Math]::Max(1.4, 1.9 * $s))
        $caneta.StartCap = 'Round'; $caneta.EndCap = 'Round'; $caneta.LineJoin = 'Round'
        $g.DrawLines($caneta, [System.Drawing.PointF[]]@([System.Drawing.PointF]::new(9.3*$s, 12.1*$s), [System.Drawing.PointF]::new(11.3*$s, 14.1*$s), [System.Drawing.PointF]::new(14.9*$s, 10.2*$s)))
        $g.Dispose()
        if ($t -ge 256) {
            # 256 px em PNG (padrão do Windows)
            $ms = New-Object System.IO.MemoryStream; $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
            $dados = $ms.ToArray()
        } else {
            # tamanhos menores em bitmap clássico (DIB 32 bits + máscara), lido por todas as partes do Windows
            $ms = New-Object System.IO.MemoryStream; $w2 = New-Object System.IO.BinaryWriter $ms
            $w2.Write([UInt32]40); $w2.Write([Int32]$t); $w2.Write([Int32]($t * 2)); $w2.Write([UInt16]1); $w2.Write([UInt16]32)
            $w2.Write([UInt32]0); $w2.Write([UInt32]0); $w2.Write([Int32]0); $w2.Write([Int32]0); $w2.Write([UInt32]0); $w2.Write([UInt32]0)
            for ($y = $t - 1; $y -ge 0; $y--) { for ($x = 0; $x -lt $t; $x++) { $c = $bmp.GetPixel($x, $y); $w2.Write([Byte]$c.B); $w2.Write([Byte]$c.G); $w2.Write([Byte]$c.R); $w2.Write([Byte]$c.A) } }
            $linhaMasc = [int]([Math]::Ceiling($t / 32.0) * 4)
            $w2.Write((New-Object byte[] ($linhaMasc * $t)))   # máscara AND vazia (a transparência vem do alfa)
            $w2.Flush(); $dados = $ms.ToArray()
        }
        $bmp.Dispose()
        $pngs += ,@($t, $dados)
    }
    # Formato .ico (bitmaps + PNG de 256 px)
    $fs = [System.IO.File]::Create($Arquivo); $bw = New-Object System.IO.BinaryWriter $fs
    $bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$pngs.Count)
    $offset = 6 + 16 * $pngs.Count
    foreach ($p in $pngs) {
        $d = if ($p[0] -ge 256) { 0 } else { $p[0] }
        $bw.Write([Byte]$d); $bw.Write([Byte]$d); $bw.Write([Byte]0); $bw.Write([Byte]0)
        $bw.Write([UInt16]1); $bw.Write([UInt16]32); $bw.Write([UInt32]$p[1].Length); $bw.Write([UInt32]$offset)
        $offset += $p[1].Length
    }
    foreach ($p in $pngs) { $bw.Write($p[1]) }
    $bw.Close()
}
if (-not (Test-Path $icone)) { New-IconeWebGuardian $icone; Write-Host "Icone criado: $icone" }

# ---------- 2) Compilação ----------
$csc = Get-ChildItem "$env:windir\Microsoft.NET\Framework64\v4*\csc.exe" | Sort-Object FullName | Select-Object -Last 1
if (-not $csc) { throw 'Compilador C# do .NET Framework 4 nao encontrado.' }
$opcoes = @('/nologo', '/target:winexe', '/optimize+', '/platform:anycpu', '/codepage:65001', "/out:$saida",
          "/win32icon:$icone", "/win32manifest:$(Join-Path $aqui 'app.manifest')",
          '/reference:System.Windows.Forms.dll', '/reference:System.Drawing.dll',
          (Join-Path $aqui 'WebGuardianApp.cs'))
& $csc.FullName @opcoes
if ($LASTEXITCODE -ne 0) { throw "Falha na compilacao (codigo $LASTEXITCODE)" }
$v = (Get-Item $saida).VersionInfo
Write-Host ("Compilado: {0}  ({1:N0} KB, versao {2})" -f $saida, ((Get-Item $saida).Length / 1KB), $v.FileVersion) -ForegroundColor Green
