"""Casos de aceite do classificador de bump.

Roda como script solto (sem pytest) de propósito: ele é executado dentro do
workflow `dependencias-em-dia.yml`, antes de o classificador ter permissão de
decidir merge. Se um caso falhar, o job inteiro falha e nada é mesclado.

O caso que importa é o terceiro: um grupo com um minor e um major. Era
exatamente ele que a primeira versão do job deixava passar, porque classificava
pelo título do PR e um PR agrupado não tem versão no título.
"""

import io
import sys
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import classificar_bump as cb  # noqa: E402

CASOS = [
    (
        "minor em requirements",
        "-cryptography==49.0.1\n+cryptography==49.2.0\n",
        True,
    ),
    (
        "major em requirements",
        "-cryptography==49.0.1\n+cryptography==50.0.0\n",
        False,
    ),
    (
        "grupo com um minor e um major (o caso que o titulo escondia)",
        "-cryptography==49.0.1\n+cryptography==50.0.0\n-rich==14.1.0\n+rich==14.2.0\n",
        False,
    ),
    (
        "grupo so com minor",
        "-cryptography==49.0.1\n+cryptography==49.2.0\n-rich==14.1.0\n+rich==14.2.0\n",
        True,
    ),
    (
        "action fixada por SHA com versao no comentario, major",
        "-  uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.1.0\n"
        "+  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v7.0.1\n",
        False,
    ),
    (
        "action fixada por SHA, minor",
        "-  uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0\n"
        "+  uses: actions/setup-python@e797f83a9e0a2c9d1d2e9e5e4e1e0e0e0e0e0e0e # v5.8.0\n",
        True,
    ),
    (
        "item de lista YAML com major — a linha real de um workflow",
        "-      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v7.0.1\n"
        "+      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v8.0.0\n",
        False,
    ),
    (
        "grupo: item de lista com MAJOR + linha sem traço com minor",
        "-      - uses: actions/checkout@aaaaaaa # v7.0.1\n"
        "+      - uses: actions/checkout@bbbbbbb # v8.0.0\n"
        "-        uses: actions/dependency-review-action@ccccccc # v5.0.0\n"
        "+        uses: actions/dependency-review-action@ddddddd # v5.1.0\n",
        False,
    ),
    (
        "pom.xml minor",
        "-    <version>3.2.5</version>\n+    <version>3.2.7</version>\n",
        True,
    ),
    (
        "pom.xml major",
        "-    <version>3.2.5</version>\n+    <version>4.0.0</version>\n",
        False,
    ),
    (
        "diff sem versao legivel (so changelog) — fail-closed",
        "-alguma coisa\n+outra coisa\n",
        False,
    ),
    (
        "versao so de um lado — nao comparavel, fail-closed",
        "+novopacote==1.0.0\n",
        False,
    ),
    (
        "package.json minor",
        '-  "react": "^18.2.0",\n+  "react": "^18.3.1",\n',
        True,
    ),
    (
        "package.json major",
        '-  "react": "^18.2.0",\n+  "react": "^19.0.0",\n',
        False,
    ),
    # --- Tag simples (`@v5`), a forma mais comum de fixar uma action ---------
    #
    # O classificador exigia `major.minor` para reconhecer uma versão. `v5` não
    # tem minor: a linha não casava com padrão nenhum e a troca ficava
    # *invisível* — nem em `comuns`, nem em `orfas`, nem numa explicação. O
    # primeiro caso abaixo é o que realmente aconteceu em produção
    # (observatorio-da-superficie#1, 2026-08-15): o job disse "nenhuma troca de
    # versão pôde ser lida" para um diff que só fazia checkout@v5 -> @v7.
    (
        "action em tag simples, major",
        "-      - uses: actions/checkout@v5\n+      - uses: actions/checkout@v7\n",
        False,
    ),
    (
        "action em tag simples, minor",
        "-      - uses: actions/setup-python@v6.1\n+      - uses: actions/setup-python@v6.4\n",
        True,
    ),
    (
        "FALHA ABERTA: minor legível ao lado de major invisível em tag simples",
        "-hypothesis==6.122.1\n+hypothesis==6.165.0\n"
        "-      - uses: actions/checkout@v5\n+      - uses: actions/checkout@v7\n",
        False,
    ),
    (
        "SHA que começa com dígito não pode ser lido como versão",
        "-      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.1.0\n"
        "+      - uses: actions/checkout@91bd71901bbe5b1630ceea73d27597364c9af683 # v5.2.0\n",
        True,
    ),
    (
        "dependência com versão ilegível não pode ser invisível",
        "-hypothesis==6.122.1\n+hypothesis==6.165.0\n-pacote==alfa\n+pacote==beta\n",
        False,
    ),
    # --- Dependência entre aspas (pyproject.toml) --------------------------
    #
    # Segunda casca da mesma classe da tag simples, encontrada em auditoria no
    # mesmo dia em que a primeira foi fechada. Em `pyproject.toml` a dependência
    # é item de lista de string: `  "typer>=0.27",`. Com a aspa na frente, o
    # padrão de requirements (nome no começo) não casa e o de package.json
    # (`"nome": "versão"`) também não — a troca ficava invisível.
    #
    # Custo real medido: `esteira#17` eram três patches em pyproject e o
    # classificador respondeu "nenhuma troca de versão pôde ser lida". Recusou —
    # mas por cegueira, não por prova. O terceiro caso é o que importa: ao lado
    # de uma linha legível, o major entre aspas era aprovado.
    (
        "dependência entre aspas no pyproject, patch",
        '-  "typer>=0.27",\n+  "typer>=0.27.1",\n',
        True,
    ),
    (
        "dependência entre aspas no pyproject, major",
        '-  "typer>=0.27",\n+  "typer>=1.0",\n',
        False,
    ),
    (
        "FALHA ABERTA: patch legível ao lado de major entre aspas",
        '-hypothesis==6.122.1\n+hypothesis==6.165.0\n-  "typer>=0.27",\n+  "typer>=1.0",\n',
        False,
    ),
    (
        "grupo de patches entre aspas — o caso real do esteira#17",
        '-  "typer>=0.27",\n+  "typer>=0.27.1",\n'
        '-  "ruff>=0.16.1",\n+  "ruff>=0.16.2",\n'
        '-  "hypothesis>=6.165.0",\n+  "hypothesis>=6.165.2",\n',
        True,
    ),
]

falhas = 0
for nome, diff, esperado in CASOS:
    pode, explicacoes = cb.classificar(diff)
    marca = "ok " if pode == esperado else "FALHA"
    if pode != esperado:
        falhas += 1
    print(f"[{marca}] {nome}: mesclaria={pode} (esperado {esperado})")
    if pode != esperado:
        for e in explicacoes:
            print(f"          {e}")

print()
print(f"{len(CASOS) - falhas}/{len(CASOS)} casos corretos")
sys.exit(1 if falhas else 0)
