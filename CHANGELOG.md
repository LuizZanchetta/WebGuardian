# Notas de atualização do WebGuardian

Cada versão é publicada em [Releases](https://github.com/LuizZanchetta/WebGuardian/releases) com a etiqueta `vX.Y.Z`. Toda versão oficial é assinada digitalmente: a impressão digital precisa ser **`WG-D0C5-ACA9-5777-6D53-ED11`**.

## 1.8.2 — 2026-11-23

**Verificação pelo antivírus ativo, sem abrir a tela dele**

Com o Avast (ou AVG, Kaspersky, ESET…) ligado, o WebGuardian agora pede ao próprio antivírus que confira os arquivos, pela interface oficial do Windows para isso (AMSI). Não precisa abrir o app do antivírus.

- **Downloads verificados de verdade pelo outro antivírus**: "Limpo" quando ele confere e não acha nada; se ele apontar uma ameaça, o WebGuardian **isola o arquivo** até você decidir.
- **Verificação rápida e completa pelo outro antivírus**, direto do painel ou pelo atalho de emergência, com **porcentagem real** (arquivos conferidos de um total).
- **Verificação rápida automática uma vez por dia**, em segundo plano, 20 minutos depois de ligar o PC. Você só é avisado se algo for encontrado. Com o Defender, ela é pulada se ele já fez a dele nas últimas 24 h.
- Se o outro antivírus não atender pedidos pelo AMSI, o WebGuardian não afirma "Limpo": mostra "Sem bloqueio" e orienta a usar a tela dele.
- GitHub: link **Baixar o WebGuardian** no topo da página principal, sempre com a versão mais recente.

## 1.8.1 — 2026-11-23

**Compatível com outros antivírus (Avast, AVG, Norton, Kaspersky…)**

Quando outro antivírus está ligado, o próprio Windows desliga a proteção em tempo real do Defender. Antes o WebGuardian tratava isso como problema; agora ele reconhece o outro antivírus como a proteção do PC.

- **Sem alarme falso** de "Defender desligado": o painel mostra qual antivírus protege o PC.
- **Alerta crítico se nenhum antivírus estiver ligado**, e aviso se a base do outro antivírus estiver desatualizada.
- **Downloads:** com outro antivírus no lugar, quem confere o arquivo é ele, em tempo real. O painel mostra **Sem bloqueio** (não "Limpo", porque não dá para perguntar o resultado ao outro antivírus). As regras contra golpes e a conferência de assinatura digital continuam valendo.
- Programa que some logo depois de baixado aparece como **provavelmente bloqueado** pelo outro antivírus.
- Verificações rápida e completa: o painel orienta a usar a tela do outro antivírus.
- README: seção sobre outros antivírus e o que fazer em caso de alarme falso (ex.: "IDP" do Avast).

## 1.8.0 — 2026-11-23

**Primeira versão pública, assinada digitalmente**

- Assinatura digital oficial (RSA-3072) em toda versão: pasta `ASSINATURA` com a "digital" (SHA-256) de cada arquivo.
- **`VERIFICAR AUTENTICIDADE.bat`**: confere se a cópia é a oficial antes de instalar (sem Administrador) e aponta programas a mais na pasta.
- Instalar e Atualizar **recusam uma cópia alterada**.
- Depois de instalado, o WebGuardian confere os próprios arquivos a cada 10 minutos e dá **alerta crítico** se alguém ou algum programa os alterar.
- Selo **Versão oficial** no rodapé do painel e aviso vermelho se algo não conferir.
- Conferência independente pelo PowerShell, explicada no README.

## 1.7.1

- Atividade por sessão: a cada PC ligado a atividade começa do zero (a anterior é arquivada) e mostra quem entrou na máquina, desbloqueios e senhas erradas.
- Botão **Limpar lista** em ameaças detectadas e no histórico de decisões.

## 1.7.0

- Novo nome **WebGuardian**.
- Regras contra truques de golpe em downloads, com quarentena de arquivos.
- Base do Defender atualizada a cada 3 horas; proteções extras do Defender no painel.
- Botão para limpar a lista de downloads; barra de verificação fecha ao terminar.

## 1.6.1

- Verificação automática de todo download, inclusive instaladores.
- Porcentagem das verificações rápida e completa.

## 1.6.0

- App com janela própria; painel em abas com teclas de emergência.

## 1.5.0

- Classificação por assinatura digital (menos alarmes falsos); atualizador. 