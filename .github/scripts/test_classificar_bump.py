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
