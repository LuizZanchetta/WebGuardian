# 🛡️ WebGuardian

Monitor de acesso indevido e de downloads para **Windows 10 e 11**. Ele vigia o computador o
tempo todo e **isola** o que parece invasão ou golpe (sem apagar nada) até você decidir, num
app próprio, se aquilo era seguro (**Liberar**) ou uma ameaça (**Apagar**). Trabalha junto
com o Windows Defender.

> **Tudo roda só no seu computador.** Não há servidor, conta, nem envio de dados seus para a
> internet. Cada pessoa que instala tem o seu WebGuardian independente.

**Versão atual: 2.1.0**

### ⬇️ [Baixar o WebGuardian 2.1.0 (versão mais recente)](https://github.com/LuizZanchetta/WebGuardian/archive/refs/tags/v2.1.0.zip)

O que mudou nesta versão e nas anteriores: **[Releases](https://github.com/LuizZanchetta/WebGuardian/releases/latest)**.
Depois de baixar, siga a [Instalação](#instalação).

> [!IMPORTANT]
> **Versão oficial:** só existe uma fonte oficial do WebGuardian:
> **https://github.com/LuizZanchetta/WebGuardian**
>
> Toda versão oficial é **assinada digitalmente**. Impressão digital da assinatura oficial:
>
> ### `WG-D0C5-ACA9-5777-6D53-ED11`
>
> Recebeu o WebGuardian por outro site, link, e-mail ou mensagem? **Não instale** antes de
> conferir ([veja como](#como-saber-se-a-sua-cópia-é-oficial)). Uma cópia alterada de um
> programa que roda como Administrador pode fazer muito mal ao seu PC.

---

## O que ele vigia

| Situação | O que o WebGuardian faz |
|---|---|
| Várias senhas erradas seguidas vindas do mesmo IP (força bruta) | Bloqueia o IP no Firewall do Windows |
| Login remoto bem-sucedido vindo de um IP de fora da sua rede | Bloqueia o IP no Firewall |
| Usuário novo criado no Windows | Desativa o usuário |
| Alguém adicionado ao grupo Administradores | Remove do grupo |
| Programa sem assinatura, rodando de Temp/Downloads/AppData, conectado ou tentando conectar à internet, ou com uma porta aberta esperando conexões de fora | **Congela** o programa e bloqueia a internet dele |
| Tarefa agendada, serviço ou programa de inicialização novo e suspeito | Desativa / remove (guarda backup para desfazer) |
| **Qualquer arquivo baixado** (inclusive instaladores) | Passa pelas regras contra golpes e pelo Windows Defender assim que termina de baixar |
| Windows Defender desligado, ameaça detectada, log de segurança apagado | Alerta |
| **Proxy** configurado, linhas novas no arquivo **hosts**, **DNS** trocado à mão, **acesso remoto (RDP)** ligado (truques para desviar você a sites falsos ou abrir o PC ao invasor) | **Desfaz na hora** e pergunta: Liberar (aceitar) ou Apagar (manter desfeito) |
| Regra nova no **firewall** liberando entrada para programa suspeito | Desativa a regra |
| **Extensão nova** no Edge, Chrome, Brave, Opera ou Firefox | Alerta com o nome da extensão |
| **Pendrive, celular ou teclado USB** conectado pela primeira vez | Alerta (teclado novo é alerta crítico: pode ser um pendrive que digita comandos). O mesmo modelo em outra porta USB só fica registrado |

### Verificação de downloads
O WebGuardian vigia a pasta **Downloads** (todos os arquivos) e também a **Área de Trabalho**
e **Documentos** (só arquivos com a "marca de download" que o Windows grava em tudo o que vem
da internet). Ele espera o download terminar (ignora `.crdownload`, `.part` etc.) e não mexe
em arquivos que estão "só na nuvem" do OneDrive.

**1. Regras contra truques de golpe (funcionam sem internet)** — o que é grave vai direto
para a quarentena, antes de você conseguir abrir:

| Truque | Exemplo | Ação |
|---|---|---|
| Extensão falsa | `boleto.pdf.exe`, `foto.jpg.scr` | **Isola** |
| Caractere invisível que inverte o nome | `fatura[RLO]fdp.exe` (aparece como "fatura**exe.pdf**") | **Isola** |
| Muitos espaços escondendo a extensão | `contrato.pdf          .exe` | **Isola** |
| Protetor de tela / painel de controle baixado | `.scr`, `.pif`, `.cpl` | **Isola** |
| Scripts e atalhos baixados | `.js`, `.vbs`, `.hta`, `.wsf`, `.lnk`, `.jar`… | Alerta |
| Imagem de disco | `.iso`, `.img`, `.vhd` | Alerta |
| ZIP protegido por senha (antivírus não enxerga dentro) | `arquivo.zip` com senha | Alerta |

**2. Windows Defender** verifica o arquivo. A **base de ameaças do Defender** (milhões de
vírus conhecidos, mantida pela Microsoft) é atualizada pelo WebGuardian **a cada 3 horas** e
também quando um programa é baixado com a base desatualizada.

| Resultado | Significado |
|---|---|
| **Limpo** | Nenhuma ameaça; se for programa, mostra quem o assinou |
| **Sem assinatura** | Nenhuma ameaça conhecida, mas o programa não tem assinatura digital: só execute se confiar na origem |
| **Suspeito** | Tipo de arquivo comum em golpes; o Defender não achou ameaça conhecida |
| **Isolado** | Truque de golpe: o arquivo foi para a quarentena (aba **Decisões**) |
| **Ameaça bloqueada** | O Defender encontrou e bloqueou o arquivo (inclusive pela proteção em tempo real) |
| **Não verificado** | O Defender não conseguiu verificar (nunca é marcado como limpo) |

A lista de downloads conferidos pode ser limpa a qualquer momento (**Limpar lista**).

**3. Proteções extras do Defender (opcionais, você liga no painel):**
- **Bloqueio de aplicativos indesejados** — bloqueia adware, barras de ferramentas e "ofertas"
  escondidas em instaladores (por padrão o Windows só registra).
- **Bloqueio na nuvem em nível alto** — o Defender consulta a nuvem da Microsoft de forma mais
  rigorosa e bloqueia arquivos desconhecidos suspeitos no primeiro contato.

### Funciona com outros antivírus (Avast, AVG, Norton, Kaspersky…)
Quando outro antivírus está ligado, o **próprio Windows desliga** a proteção em tempo real do
Defender. Isso é normal, e o WebGuardian reconhece a situação:
- não dá alarme de "Defender desligado": mostra **qual antivírus protege o PC**;
- avisa se **nenhum** antivírus estiver ligado, ou se a base do outro antivírus estiver desatualizada;
- **downloads e verificações rápida/completa são feitos pelo outro antivírus, a pedido do
  WebGuardian, sem precisar abrir a tela dele**. O WebGuardian usa o AMSI, a interface oficial do
  Windows para um programa pedir uma análise ao antivírus instalado (Avast, AVG, Kaspersky, ESET e outros
  a suportam). A porcentagem da verificação é real: arquivos conferidos de um total;
- se o outro antivírus apontar uma ameaça, o WebGuardian **isola o arquivo** até você decidir;
- as **regras contra golpes** e a conferência de **assinatura digital** continuam valendo;
- se o outro antivírus não atender pedidos pelo AMSI, o download aparece como **Sem bloqueio**
  (sem afirmar "Limpo") e as verificações ficam pela tela dele.

**Verificação automática:** uma verificação rápida roda sozinha **uma vez por dia**, em segundo
plano, 20 minutos depois de ligar o PC, com o Defender ou com o outro antivírus. Você só é
avisado se algo for encontrado. Com o Defender, ela é pulada se ele já fez a dele nas últimas 24 h.

> **Alarme falso do outro antivírus:** alguns antivírus (por exemplo, a detecção por
> comportamento do Avast, "IDP.*") podem desconfiar do WebGuardian. Ele faz coisas que um
> programa de proteção precisa fazer e que um vírus também faria (rodar escondido como
> Administrador, congelar programas, mexer no firewall), e o app não tem assinatura digital de
> empresa. Confira a cópia com `VERIFICAR AUTENTICIDADE.bat`; sendo a versão oficial, restaure da
> quarentena, adicione `C:\ProgramData\Guardiao` às exceções e, se puder, reporte o alarme falso
> ao fabricante do antivírus.

### Como ele separa ameaça real de alarme falso
O WebGuardian julga pela **assinatura digital** do que vai rodar (nome e pasta podem ser
imitados por um invasor):

- **Assinado pela Microsoft** (ex.: tarefas internas do Windows) → só registra, sem aviso.
- **Assinado por empresa conhecida** (NVIDIA, Steam, Discord…) → só registra.
- **Sem assinatura / desconhecido** → alerta.
- **Comando com cara de ataque** (código escondido, download de script, `mshta`,
  programa sem assinatura em Temp/Downloads) → **isola**.

Ferramentas do Windows muito usadas em ataques (PowerShell, `cmd`, `rundll32`, `mshta`…)
não ganham passe livre só por serem da Microsoft: o WebGuardian confere o que elas vão abrir.

---

## Requisitos

- Windows 10 ou 11 (Home ou Pro)
- Conta com permissão de **Administrador**
- Microsoft Edge (já vem no Windows) — usado para desenhar a janela do app
- Nada para instalar: o app é compilado na sua máquina com o compilador C# que já vem no
  Windows (.NET Framework 4.8)

---

## Instalação

1. Baixe pelo link **⬇️ Baixar o WebGuardian** no topo desta página (é sempre a versão mais
   recente) ou em **[Releases](https://github.com/LuizZanchetta/WebGuardian/releases/latest)** → **Source code (zip)**.
2. **Antes de extrair:** clique com o botão direito no ZIP → **Propriedades** → marque
   **Desbloquear** → OK. (Arquivos baixados vêm bloqueados pelo Windows.)
3. Extraia para uma pasta sua (ex.: `Documentos\WebGuardian`). **Guarde essa pasta**: ela é
   usada para atualizar e desinstalar.
4. Dê dois cliques em **`VERIFICAR AUTENTICIDADE.bat`**. Ele precisa mostrar **VERSÃO
   OFICIAL** e a impressão digital **`WG-D0C5-ACA9-5777-6D53-ED11`**.
5. Dê dois cliques em **`INSTALAR WEBGUARDIAN.bat`** e clique em **Sim** no aviso de
   Administrador.

O instalador:
- confere a assinatura oficial de novo e **recusa** uma cópia alterada (só instala se você
  digitar `CONTINUAR`, o que não é recomendado);
- copia o WebGuardian para `C:\ProgramData\Guardiao` (pasta que só Administradores alteram;
  o nome interno da pasta foi mantido para compatibilidade com versões anteriores);
- compila o app `WebGuardian.exe` no seu PC;
- cria o atalho **WebGuardian** no Menu Iniciar e na Área de Trabalho;
- deixa o monitor rodando e iniciando sozinho a cada logon;
- registra **a sua conta** como dona do WebGuardian neste PC.

---

## Usando

Abra pelo atalho **WebGuardian** ou dê dois cliques no **escudo perto do relógio**.

| Aba | O que mostra |
|---|---|
| **Resumo** | Estado geral do PC, camadas de proteção, ações de emergência, **acessos e alertas desta sessão** e últimos downloads |
| **Decisões** | Itens isolados pelo WebGuardian **e ameaças detectadas pelo Defender** esperando você: **Liberar** (era seguro) ou **Apagar ameaça** |
| **Atividade** | Tudo o que o WebGuardian registrou **desde que o PC foi ligado** |
| **Conexões** | Programas conectados à internet agora (suspeitos em destaque) |
| **Antivírus** | Antivírus ativo (Defender ou outro, como o Avast), base de ameaças, proteções extras, verificações, ameaças e downloads verificados |
| **Histórico** | Decisões já tomadas, **Exportar relatório** (HTML para salvar em PDF + planilha CSV na Área de Trabalho) e a lista de **programas confiáveis** (os que você liberou; vale só para o mesmo arquivo) |
| **Agente IA** | Conversa com o agente, o que ele fez sozinho (com **Desfazer**), resumos do dia e a **autonomia** dele (regras de emergência) |

### Agente do painel
O agente acompanha o WebGuardian e explica o que ele encontra: dentro de cada item em
**Decisões** aparece a análise dele (veredito, confiança, o que viu e a recomendação), e na aba
**Agente IA** você conversa com ele.

- **Funciona só no seu PC, por regras, sem internet.** Não usa modelo de IA na nuvem, não tem
  chave de API e não envia nada, nem metadados.
- Pergunte do seu jeito ("está tudo bem?", "qem entrou no pc hj?", "o anydesk está aberto?",
  "o que é proxy?"). Ele entende erros de digitação, várias perguntas numa mensagem e o fio da
  conversa: "e ontem?", "e às 14h?", "por quê?", "mais detalhes", "fui eu", "não fui eu".
- **Autonomia:** "Só sugere", "Age em emergência" (padrão) ou "Automático". Em emergência ele
  pode desconectar a internet, congelar um programa suspeito ou bloquear um IP, conforme as regras
  ligadas. **Liberar e apagar ficam sempre com você**, e tudo o que ele faz sozinho pode ser
  desfeito.

### Atividade por sessão: quem acessou a máquina
Cada vez que o PC é **ligado**, a atividade começa do zero: a da sessão anterior é
**arquivada** (não apagada) em `C:\ProgramData\Guardiao\sessoes\` — as 30 últimas sessões
ficam guardadas. Se só o WebGuardian reiniciar (por exemplo, numa atualização), nada é
arquivado.

Ao ligar, o WebGuardian lê o registro de segurança do Windows **desde a hora em que o PC
ligou** e mostra, com a hora real de cada um:
- quem **entrou no Windows** (no próprio PC ou com senha salva);
- quem **desbloqueou a tela**;
- **senhas erradas** digitadas na tela de entrada;
- **acessos remotos** (que geram alerta ou bloqueio).

Contas internas do Windows são ignoradas. As listas de **ameaças detectadas** e de
**histórico de decisões** têm o botão **Limpar lista** — limpar as ameaças só esconde do
painel; o histórico oficial continua em *Segurança do Windows › Histórico de proteção*.

### Teclas rápidas

| Tecla | Ação |
|---|---|
| `Ctrl` + `Shift` + `D` | **Desconectar da internet** (ou reconectar) |
| `Ctrl` + `Shift` + `V` | Verificação rápida do Defender |
| `Ctrl` + `Shift` + `O` | Verificação offline (reinicia o PC) |
| `Ctrl` + `Shift` + `R` | Ir para as decisões pendentes |
| `1` a `7` | Trocar de aba (`7` é o Agente IA) |
| `?` | Mostrar os atalhos |

Desconectar e verificação offline pedem confirmação: o foco já fica no botão de confirmar,
então **atalho + Enter** resolve numa emergência; **Esc** cancela.

### Porcentagem das verificações
Durante uma verificação rápida ou completa aparece uma barra com a porcentagem e o tempo
restante; ao terminar, a barra fecha e um aviso mostra o resultado. O Windows Defender **não
informa o progresso real** a outros programas, então o valor é **estimado** pela duração da
última verificação do mesmo tipo neste PC (sem histórico: tempo típico para a rápida e
tamanho do disco para a completa).

---

## Atualizar

Baixe a versão nova em **[Releases](https://github.com/LuizZanchetta/WebGuardian/releases/latest)**
(o que mudou está nas notas de cada release e no [CHANGELOG](CHANGELOG.md)), extraia (lembre de **Desbloquear** o ZIP) e dê dois cliques em
**`ATUALIZAR WEBGUARDIAN.bat`**. A partir da 2.0, quem confere a assinatura da versão nova é o
**WebGuardian já instalado** (que fica numa pasta protegida): ele mostra uma janela do Windows com
a versão e a assinatura conferida e só atualiza se você clicar em **Confirmar**. Uma cópia
adulterada é recusada sem nem perguntar. A atualização mostra a versão instalada e a nova, guarda um backup em
`C:\ProgramData\Guardiao\backup\` e, se a versão nova não iniciar, **volta sozinho para a
anterior**. Quem tinha o "Guardião" (até 1.6.1) é atualizado normalmente: os atalhos antigos
viram **WebGuardian** e histórico, quarentena e bloqueios são mantidos.

## Desinstalar

Dê dois cliques em **`DESINSTALAR WEBGUARDIAN.bat`**. É pedida a **senha do Windows da conta
dona** (não serve o PIN; em conta Microsoft é a senha da conta Microsoft). Depois de 3
senhas erradas a desinstalação é bloqueada e um alerta é registrado. Você escolhe se mantém
ou remove os bloqueios de firewall criados. O histórico fica em `C:\ProgramData\Guardiao`.

---

## Como saber se a sua cópia é oficial

Cada versão oficial traz a pasta **`ASSINATURA`**:
- `manifesto.json`: a "digital" (SHA-256) de cada arquivo do WebGuardian;
- `manifesto.sig`: a **assinatura digital** (RSA-3072) desse manifesto.

A assinatura só pode ser feita com a **chave privada oficial**, que nunca é publicada. A chave
pública que confere a assinatura vai dentro do `WebGuardian.ps1`. Com isso:

| Se alguém... | O que acontece |
|---|---|
| muda **um único caractere** de qualquer arquivo | a conferência acusa **Alterado: nome-do-arquivo** |
| apaga ou falsifica a assinatura | a conferência acusa **assinatura falsa** ou **sem assinatura** |
| troca a chave para assinar uma cópia falsa | a **impressão digital muda** e não bate com `WG-D0C5-ACA9-5777-6D53-ED11` |

O WebGuardian confere a assinatura em três momentos:
1. **`VERIFICAR AUTENTICIDADE.bat`**: confere a pasta baixada antes de instalar (não precisa
   de Administrador). Também lista programas a mais que não fazem parte da versão oficial.
2. **Instalar e Atualizar**: recusam uma cópia alterada.
3. **Depois de instalado**, a cada 10 minutos: se algum programa ou alguém alterar os arquivos
   instalados, o WebGuardian dá um **alerta crítico**. O rodapé do painel mostra o selo
   **Versão oficial · WG-D0C5-…** e um aviso vermelho aparece no topo se algo não conferir.

**Limite honesto:** o `VERIFICAR AUTENTICIDADE.bat` roda o código da própria cópia, e uma
cópia falsificada pode mentir. Por isso a regra de ouro é **baixar só daqui** e conferir a
impressão digital. Para uma conferência **independente da cópia**, cole no PowerShell o
código abaixo. A chave pública vem desta página oficial, não da cópia baixada:

<details>
<summary>Conferência independente (PowerShell)</summary>

```powershell
$pasta = "$HOME\Downloads\WebGuardian-main"   # troque pela pasta onde você extraiu o ZIP
$chave = '<RSAKeyValue><Modulus>19puAGxzdUppr2DZy93JLUAm/eCjVMxpfqWjb82ODNVTYJCuoJNFPPGfU2lQScv0xkW4Ix2HUrHq3jDPqKQ2lrwAvhf8ALLicns8qY0sKpvs04n2bf2PEvsxFLg1HjfPvSMXbuQAYc0Ca2IudLeyB5YYIb9I6mVNPKzwUQ8+D0FX1Nc9OWnSMJTNaRhPLB4kAwsIXTKI2IL4QR4AVWgnZIqbslXYTEX7MUZv2QQ1K4LyIztLgU0ksRjO0Kpx9dKODlPB0AIIyhiPedg+FDmeTQQW3Dg3O6J4+qy9XXPmdY9KsUVG0eP7qW8iDR4mQ9PmGu7Jvqp13PWgZLhfi4Quy0E9DSyECvPF4vpKOCHmBLOGzmCO+asy4FOZnujU8iIpETPZWVVxsc7sE+ixSMkyVW+Kr43Bu2krnqRQqJdILbadsLnACIZKZ0Vj8BO6LfqpoMDtRW644UAKa26klQ4f2TtIsOXorE/wTh7EBms1VM8qY2dFaMHA8GHr/KXwobjN</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'
$ler = { param($p) $b = [IO.File]::ReadAllBytes($p); if ($p -notmatch '\.ico$') { $l = [Text.Encoding]::GetEncoding(28591); $b = $l.GetBytes($l.GetString($b).Replace("`r`n", "`n")) }; , $b }
$man = & $ler "$pasta\ASSINATURA\manifesto.json"
$rsa = New-Object Security.Cryptography.RSACryptoServiceProvider; $rsa.FromXmlString($chave)
if (-not $rsa.VerifyData($man, 'SHA256', [Convert]::FromBase64String((Get-Content "$pasta\ASSINATURA\manifesto.sig" -Raw).Trim()))) { Write-Host 'ASSINATURA FALSA: NAO INSTALE' -ForegroundColor Red } else {
  $sha = [Security.Cryptography.SHA256]::Create()
  ([Text.Encoding]::UTF8.GetString($man) | ConvertFrom-Json).arquivos.PSObject.Properties | ForEach-Object {
    $h = -join ($sha.ComputeHash((& $ler (Join-Path $pasta $_.Name))) | ForEach-Object { $_.ToString('x2') })
    if ($h -eq $_.Value) { Write-Host "OK        $($_.Name)" -ForegroundColor Green } else { Write-Host "ALTERADO  $($_.Name)" -ForegroundColor Red } } }
```
Tudo **OK** = versão oficial. Qualquer **ALTERADO**, **ASSINATURA FALSA** ou erro de arquivo
faltando = não instale.
</details>

Achou uma cópia alterada sendo divulgada como WebGuardian? Abra uma *issue* aqui no
repositório para avisar.

---

## Segurança e privacidade

- O painel só responde em `127.0.0.1` (dentro do próprio PC), exige uma chave secreta
  gerada a cada início e recusa pedidos de outros sites.
- A janela do app roda como **usuário comum** e entra com um **código de uso único**
  (válido por 60 s); a chave não fica no histórico.
- O app só aceita links do próprio PC no formato esperado.
- **Ações sensíveis pedem confirmação numa janela do Windows** aberta pelo próprio WebGuardian
  (que roda como Administrador): **Liberar** itens isolados, **reconectar** a internet e **baixar**
  proteções do Defender. O Windows não deixa um programa comum clicar numa janela de
  Administrador, então um vírus no seu usuário não consegue se liberar sozinho. Sem resposta em
  1 minuto, a janela cancela.
- Nenhum dado seu é enviado para a internet. As únicas comunicações externas são a atualização da
  base do próprio Windows Defender, feita pelo Windows, e **uma consulta por dia** à página pública
  de Releases do GitHub oficial, para avisar quando sai versão nova (só lê; nada é enviado e nada é
  instalado sozinho).
- O **agente do painel** lê os registros do WebGuardian aqui mesmo e não usa a internet.
  Pausar o agente, desligar uma regra dele, deixá-lo em "Só sugere" e desfazer uma ação dele
  também pedem a confirmação do Windows.
- Configurações de segurança do Windows (proteções extras do Defender) só mudam quando
  **você** clica no botão correspondente.

## ⚠️ Avisos

- O WebGuardian **isola** programas, usuários, IPs e downloads. Ele pode bloquear algo
  legítimo — por isso nada é apagado sem você mandar, e tudo pode ser desfeito na aba
  **Decisões** (Liberar devolve o download para onde ele estava).
- O botão **Apagar ameaça** nunca apaga arquivos do Windows, de *Arquivos de Programas* ou
  com assinatura digital válida.
- Ele **não substitui** um antivírus: complementa o Windows Defender.
- Um invasor que já tenha controle de Administrador pode derrubar qualquer ferramenta de
  proteção, inclusive esta. Se você suspeita de invasão: desconecte da internet, troque
  suas senhas **usando outro aparelho** e rode a **verificação offline** do Defender.
- O `WebGuardian.exe` é compilado no seu PC e **não tem assinatura digital** — é normal para
  um projeto pessoal.

---

## Estrutura

```
WebGuardian.ps1              monitor, painel local, instalação, atualização e desinstalação
painel.html                  interface do painel (arquivo único, sem dependências externas)
INSTALAR WEBGUARDIAN.bat     instala (pede Administrador)
ATUALIZAR WEBGUARDIAN.bat    aplica uma versão nova, com backup e volta automática
DESINSTALAR WEBGUARDIAN.bat  remove (pede a senha do dono)
VERIFICAR AUTENTICIDADE.bat  confere se a cópia é a versão oficial (sem Administrador)
CHANGELOG.md                 notas de atualização de cada versão (as mesmas das Releases)
ASSINATURA/                  manifesto com o SHA-256 de cada arquivo + assinatura digital oficial
ferramentas/assinar-versao.ps1  usado só pelo mantenedor para assinar versões (a chave privada não está aqui)
app/WebGuardianApp.cs        código do app WebGuardian.exe (C#, .NET Framework 4.8)
app/compilar.ps1             compila o app (o instalador chama sozinho)
app/app.manifest             manifesto do app (roda sem privilégio de Administrador)
app/webguardian.ico          ícone
docs/DESIGN.md               sistema visual do painel
```

Para compilar o app manualmente:
```powershell
powershell -ExecutionPolicy Bypass -File app\compilar.ps1
```

## Histórico de versões

Notas completas de cada versão: [CHANGELOG](CHANGELOG.md) e [Releases](https://github.com/LuizZanchetta/WebGuardian/releases).

- **2.1.0** — agente no painel (local, sem internet): análise de cada item isolado, conversa que
  entende o contexto, resumo do dia e regras de emergência; sem janela preta ao ligar o PC; mesmo
  teclado em outra porta USB não é mais alerta crítico; drivers do Windows sem alarme falso.
- **2.0.0** — visual novo do painel; confirmação pelo Windows para ações sensíveis; atualização
  conferida pela cópia instalada; vigia proxy, hosts, DNS, acesso remoto, firewall, extensões de
  navegador e dispositivos USB; aviso de versão nova; relatório exportável; programas confiáveis.
- **1.9.1** — detecção de conexões: portas dos fundos, tentativas de conexão, número de processo
  reaproveitado e programa trocado; sem alarme falso com rede de casa e VPN.
- **1.9.0** — ameaças detectadas pelo Defender aparecem na aba **Decisões**: liberar (alarme
  falso: permite e devolve o arquivo) ou apagar, sem abrir a Segurança do Windows.
- **1.8.2** — verificação pelo antivírus ativo (Avast, AVG, Kaspersky…) sem abrir a tela dele:
  downloads e verificações rápida/completa com porcentagem real; verificação rápida automática
  uma vez por dia; botão de download da versão mais recente no topo da página.
- **1.8.1** — compatível com outros antivírus (Avast, AVG, Norton…): sem alarme falso de
  "Defender desligado", painel mostra o antivírus ativo, downloads conferidos pelo antivírus
  ativo e alerta se nenhum antivírus estiver ligado.
- **1.8.0** — primeira versão pública: **assinatura digital oficial** com conferência de
  autenticidade (`VERIFICAR AUTENTICIDADE.bat`, na instalação, na atualização e a cada 10 min
  nos arquivos instalados); selo de versão oficial no painel.
- **1.7.1** — atividade por sessão (arquivada a cada PC ligado) mostrando quem entrou na
  máquina, desbloqueios e senhas erradas; botão **Limpar lista** em ameaças detectadas e no
  histórico de decisões.
- **1.7.0** — novo nome **WebGuardian**; regras contra truques de golpe em downloads com
  quarentena de arquivos; base do Defender atualizada a cada 3 h; proteções extras do Defender
  no painel; botão para limpar a lista de downloads; barra de verificação fecha ao terminar;
  correção da lista de quarentena com vários itens.
- **1.6.1** — verificação automática de todo download; porcentagem das verificações.
- **1.6.0** — app com janela própria; painel em abas com teclas de emergência.
- **1.5.0** — classificação por assinatura digital (menos alarmes falsos); atualizador.

## Licença

[MIT](LICENSE) — uso livre, **sem garantia**. Use por sua conta e risco.
