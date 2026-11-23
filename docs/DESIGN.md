# DESIGN.md — Painel WebGuardian (v3)

Painel local de segurança que roda em `127.0.0.1` e abre na janela do app `WebGuardian.exe`.
Organizado em abas (Resumo, Decisões, Atividade, Conexões, Defender, Histórico); a aba
Resumo traz o estado do PC, o diagrama de camadas de proteção, as ações de emergência com
teclas rápidas e os últimos alertas.

**Direção:** interface densa de app, inspirada no sistema visual do Linear: uma escada
de superfícies e linhas finas no lugar de sombras, um único acento azul (sem violeta) e
cor só para estado. Barra lateral com seções e atalhos 1–6, barra superior com caminho
e indicador "Ao vivo", e painéis no lugar de cartões soltos.

**Restrição mantida:** arquivo único, sem nenhum acesso à internet. As fontes Geist e
Geist Mono (SIL OFL) estão embutidas em base64. A mesma API `/api/estado` e `/api/acao`
e a mesma chave `__TOKEN__` do `Guardiao.ps1`. Os dados aparecem sempre via
`textContent`, para não executar nada vindo de nomes de programas ou caminhos.

## Cor

| Token | Escuro | Claro | Papel |
|---|---|---|---|
| `--canvas` | `#08090a` | `#f8f9fa` | Fundo |
| `--s1` `--s2` `--s3` | `#0f1012` `#141518` `#1a1b1e` | `#fff` `#f4f5f6` `#f0f1f2` | Painéis, hover, item ativo |
| `--line` `--line-2` `--line-3` | `#202226` `#2c2e33` `#3a3c42` | `#e9eaec` `#dcdee1` `#c9ccd1` | Linhas e contornos |
| `--ink` … `--ink-4` | `#f7f8f8` → `#62666d` | `#0f1011` → `#8f949b` | Texto, do principal ao mais apagado |
| `--accent` / `--accent-fill` | `#6b9bf2` / `#3c6fe0` | `#2f6bea` | Único acento: botão principal, foco, marca |
| `--ok` `--warn` `--bad` | `#4cb782` `#f2a54a` `#eb5757` | `#1d8a55` `#b36b00` `#d02e2e` | Estado |

## Tipografia

Geist (texto, títulos e números, peso 400–600) e Geist Mono (IPs, caminhos, horários,
atalhos). Corpo de 14px, títulos de painel de 14/600, estado geral de 22/600, números de
22/500 com algarismos tabulares.

## Forma e componentes

- Raios 4 · 6 · 8 · 10; painéis com linha de 1px e um fio de luz no topo, sem sombra.
  Sombra só no modal e no aviso.
- Botões de 32px (40px em tela de toque): normal, primário (um por área), perigo em
  contorno, perigo preenchido (só no modal) e discreto.
- Fila de decisões em estilo de lista de tarefas, com ícone de prioridade (barras, ou
  quadrado com "!" para crítico), número, título, gravidade, camada, alvo em mono e
  motivo. O tempo e os botões Liberar e Apagar ameaça ficam à direita.
- Painel de camadas de proteção, atividade agrupada por dia, conexões com filtro
  Todas/Suspeitas e tabela com caminho e PID, painel do Defender com ameaças, e
  histórico.
- Modal com foco preso nos botões, Esc para cancelar e clique fora para fechar. Aviso no
  canto.
- No celular: a barra lateral vira abas no topo, e o modal abre como folha embaixo.
