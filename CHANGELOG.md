# Notas de atualização do WebGuardian

Cada versão é publicada em [Releases](https://github.com/LuizZanchetta/WebGuardian/releases) com a etiqueta `vX.Y.Z`. Toda versão oficial é assinada digitalmente: a impressão digital precisa ser **`WG-D0C5-ACA9-5777-6D53-ED11`**.

## 2.0.0 — 2026-11-24

**Visual novo, mais segurança e novas vigilâncias**

A versão 2 traz o painel redesenhado e fecha este ciclo com uma revisão de segurança completa. As próximas atualizações virão com o tempo.

### Segurança (correções da revisão)
- **Confirmação pelo Windows nas ações sensíveis.** Liberar itens isolados, reconectar a internet e baixar proteções do Defender agora pedem confirmação numa janela do Windows aberta pelo próprio WebGuardian, que roda como Administrador. Antes, um programa comum no seu usuário conseguia a chave do painel e poderia, por exemplo, liberar a si mesmo. O Windows não deixa um programa comum clicar numa janela de Administrador. Sem resposta em 1 minuto, a janela cancela; Enter e Esc também cancelam.
- **Atualização conferida pela cópia instalada.** O `ATUALIZAR WEBGUARDIAN.bat` agora só deixa um pedido: quem confere a assinatura da versão nova é o WebGuardian já instalado, numa pasta protegida, com a chave oficial dele. A cópia é conferida de novo depois de copiada, e você confirma numa janela do Windows. Uma cópia adulterada é recusada sem nem perguntar.
- Pedidos grandes demais ao painel são recusados, e apagar uma ameaça não trava mais o monitor.

### Vigilância nova
- **Truques de golpe na configuração:** proxy configurado, linhas novas no arquivo **hosts**, **DNS** trocado à mão e **acesso remoto (RDP)** ligado. A mudança é desfeita na hora e vira decisão: **Liberar** aceita, **Apagar** mantém desfeita. Placas de rede novas (como a de uma VPN) não geram alarme.
- **Firewall:** regra nova liberando entrada para um programa suspeito é desativada.
- **Extensões novas** no Edge, Chrome, Brave, Opera, Opera GX e Firefox: alerta com o nome da extensão.
- **Pendrive, celular, placa de rede USB e teclado novos:** alerta. Teclado novo é **alerta crítico**, porque pode ser um pendrive que digita comandos sozinho.

### Mais praticidade
- **Aviso de versão nova:** uma consulta por dia às Releases do GitHub oficial. O WebGuardian só avisa (no painel e na tela); quem decide atualizar é você.
- **Programas confiáveis:** o que você libera entra numa lista, na aba Histórico, e não é isolado de novo. Vale só para o mesmo arquivo (conferido pela "digital" SHA-256): se ele for trocado, volta a ser vigiado. Dá para tirar da lista.
- **Exportar relatório:** gera na Área de Trabalho um relatório (abre no navegador; Ctrl+P salva em PDF) e uma planilha com as decisões, para guardar ou mostrar a um técnico.
- **Avisos que levam direto às Decisões:** clicar no aviso abre o app já na aba Decisões quando há algo esperando você.

### Visual
- **Painel redesenhado**, com cara de console: barra superior com o caminho da aba, o estado "Ao vivo", o atalho para as decisões e o botão **Desconectar da internet** sempre à mão.
- Aba do antivírus agora se chama **Antivírus** (pode ser o Defender ou outro, como o Avast); botão de **ajuda** com os atalhos; modo claro e escuro; adapta-se a telas pequenas.
- Continua um arquivo único que roda só no seu PC: nada é carregado da internet.

## 1.9.1 — 2026-11-23

**Detecção de conexões mais completa e sem alarmes falsos com a rede de casa**

Uma revisão da detecção de conexões (programa sem assinatura, em pasta suspeita, falando com a internet) achou brechas e alarmes falsos possíveis. Todos foram corrigidos.

- **Porta dos fundos:** programa sem assinatura em pasta suspeita que deixa uma porta **aberta esperando conexões de fora** agora é congelado e bloqueado, mesmo antes de alguém se conectar.
- **Tentativas de conexão:** programa suspeito **tentando** falar com a internet (por exemplo, com um servidor do invasor fora do ar) agora é pego, não só depois que a conexão abre.
- **Número de processo reaproveitado:** o Windows reutiliza esses números; antes, um programa novo que recebesse o número de um já isolado passava sem conferência. Agora cada programa é identificado pelo caminho e pela hora em que começou.
- **Programa trocado no mesmo lugar:** se um programa assinado for substituído por outro sem assinatura no mesmo caminho, a assinatura é conferida de novo.
- **Sem alarme falso com a rede de casa:** endereços da rede local escritos no formato `::ffff:192.168…` deixaram de ser tratados como internet (TV, impressora, celular na mesma rede).
- **Sem alarme falso com VPN/operadora:** a faixa `100.64.0.0/10` (ex.: Tailscale, rede da operadora) não é mais tratada como internet.
- Com outro antivírus no lugar do Defender (Avast etc.), o programa congelado agora é conferido **por esse antivírus**.
- Conferido nas conexões reais de um PC: 125 conexões e portas avaliadas, nenhum alarme falso.

## 1.9.0 — 2026-11-23

**Ameaças do antivírus na aba Decisões: você decide pelo WebGuardian**

Antes, quando o Windows Defender pegava uma ameaça, ela só aparecia como "Neutralizada" na aba Defender, e para decidir o que fazer era preciso abrir a Segurança do Windows. Agora a decisão é feita direto no WebGuardian.

- **Toda ameaça que o Defender detecta num arquivo vira uma decisão** na aba Decisões, com aviso na tela. Ela aparece em até 1 minuto depois da detecção, mesmo com o app fechado.
- **Liberar** (alarme falso): o Defender passa a permitir aquela ameaça neste PC, como o "Permitir no dispositivo" da Segurança do Windows, e devolve o arquivo da quarentena dele para o lugar de antes. O painel pede confirmação com aviso.
- **Apagar ameaça**: se a ameaça ainda estiver ativa, o Defender a remove (e o que sobrar do arquivo é apagado). Se ela já estiver na quarentena do Defender, continua presa lá, criptografada e sem poder rodar, até o Defender apagá-la sozinho. O painel explica isso, sem fingir que apagou.
- **Ameaça ativa** (que o Defender não conseguiu neutralizar) aparece como **Severidade crítica**, no topo da fila.
- **Uma decisão por ameaça e arquivo**: várias detecções do mesmo arquivo não viram várias decisões. Se a mesma ameaça voltar depois de você decidir, ela vira uma decisão nova.
- Ao atualizar, as detecções dos **últimos 7 dias** também entram na fila (as escondidas pelo "Limpar lista" continuam escondidas).
- Bloqueios só na memória (um script barrado antes de rodar) não têm arquivo para decidir e continuam como alerta.
- Ameaças apontadas pelo **Avast e outros antivírus** em downloads e verificações pedidas pelo WebGuardian já iam para Decisões e continuam indo.

## 1.8.2 — 2026-11-23

**Verificação pelo antivírus ativo, sem abrir a tela dele**

Com o Avast (ou AVG, Kaspersky, ESET…) ligado, o WebGuardian agora pede ao próprio antivírus que confira os arquivos, pela interface oficial do Windows para isso (AMSI). Não precisa abrir o app do antivírus.

- **Downloads verificados de verdade pelo outro antivírus**: "Limpo" quando ele confere e não acha nada; se ele apontar uma ameaça, o WebGuardian **isola o arquivo** até você decidir.
- **Verificação rápida e completa pelo outro antivírus**, direto do painel ou pelo atalho de emergência, com **porcentagem real** (arquivos conferidos de um total).
- **Verificação rápida automática uma vez por dia**, em segundo plano, 20 minutos depois de ligar o PC. Você só é avisado se algo for encontrado. Com o Defender, ela é pulada se ele já fez a dele nas últimas 24 h.
- Se o outro antivírus não atender pedidos pelo AMSI, o WebGuardian não afirma "Limpo": mostra "Sem bloqueio" e orienta a usar a tela dele.- GitHub: link **Baixar o WebGuardian** no topo da página principal, sempre com a versão mais recente.

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