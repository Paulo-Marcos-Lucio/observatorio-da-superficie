#!/usr/bin/env python3
"""Decide se um PR de dependência é comprovadamente não-major.

Sai com 0 apenas quando **todas** as trocas de versão encontradas no diff são
não-major e pelo menos uma foi encontrada. Qualquer outra situação sai com 1.

A assimetria é deliberada. As três respostas possíveis de um classificador
assim são "é major", "não é major" e "não sei", e as duas últimas não podem ser
colapsadas: a automação mescla sozinha, e mesclar por não-saber é como reportar
ausência por não ter medido.

A primeira versão deste job classificava pelo título do PR. Um PR agrupado
("Bump the pip group with 2 updates") não tem versão nenhuma no título — dois
pacotes poderiam subir de major e o regex não veria nada, o que naquele desenho
significava "pode mesclar".

Formatos reconhecidos no diff unificado:

* ``pacote==1.2.3`` e ``pacote>=1.2.3`` — requirements.txt / pyproject
* ``"pacote": "^1.2.3"`` — package.json
* ``<version>1.2.3</version>`` — pom.xml
* ``uses: dono/acao@v3`` — GitHub Actions
* ``dono/acao@<sha>  # v3.1.0`` — Actions fixada por SHA, versão no comentário
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

VERSAO = r"(\d+)\.(\d+)(?:\.(\d+))?"

PADROES = [
    # nome==1.2.3 / nome>=1.2.3 / nome~=1.2.3
    re.compile(rf"^(?P<chave>[A-Za-z0-9._-]+)\s*[=><~!]=+\s*v?{VERSAO}"),
    # "nome": "^1.2.3"  |  "nome": "~1.2.3"
    re.compile(rf'^"?(?P<chave>[@A-Za-z0-9._/-]+)"?\s*:\s*"[\^~>=<]*v?{VERSAO}'),
    # <version>1.2.3</version>  (a chave vem do artifactId mais próximo, se houver)
    re.compile(rf"^<version>v?{VERSAO}</version>"),
    # uses: dono/acao@v3.1.0
    re.compile(rf"^uses:\s*(?P<chave>[\w.-]+/[\w./-]+)@v?{VERSAO}"),
    # dono/acao@sha  # v3.1.0   (action fixada por SHA, versão no comentário)
    re.compile(rf"^(?:uses:\s*)?(?P<chave>[\w.-]+/[\w./-]+)@[0-9a-f]{{7,40}}\s*#\s*v?{VERSAO}"),
]


def _extrair(linha: str) -> tuple[str, tuple[int, int]] | None:
    """Nome e (major, minor) de uma linha de diff, se ela declarar versão."""
    corpo = linha[1:].strip()
    for padrao in PADROES:
        achado = padrao.match(corpo)
        if achado:
            grupos = achado.groupdict()
            chave = grupos.get("chave") or "<version>"
            numeros = [g for g in achado.groups() if g is not None and g.isdigit()]
            # os dois primeiros grupos numéricos após a chave são major e minor
            if grupos.get("chave"):
                numeros = numeros[:]
            if len(numeros) < 2:
                return None
            return chave.lower(), (int(numeros[0]), int(numeros[1]))
    return None


def classificar(diff: str) -> tuple[bool, list[str]]:
    """(pode_mesclar, explicações)."""
    removidas: dict[str, tuple[int, int]] = {}
    adicionadas: dict[str, tuple[int, int]] = {}

    for linha in diff.splitlines():
        if linha.startswith("---") or linha.startswith("+++"):
            continue
        if linha.startswith("-"):
            extraido = _extrair(linha)
            if extraido:
                removidas[extraido[0]] = extraido[1]
        elif linha.startswith("+"):
            extraido = _extrair(linha)
            if extraido:
                adicionadas[extraido[0]] = extraido[1]

    comuns = sorted(set(removidas) & set(adicionadas))

    if not comuns:
        return False, [
            "nenhuma troca de versão pôde ser lida do diff — "
            "sem prova de que é não-major, não mescla"
        ]

    explicacoes = []
    majores = []
    for chave in comuns:
        antes, agora = removidas[chave], adicionadas[chave]
        if agora[0] != antes[0]:
            majores.append(chave)
            explicacoes.append(
                f"MAJOR: {chave} {antes[0]}.{antes[1]} -> {agora[0]}.{agora[1]}"
            )
        else:
            explicacoes.append(
                f"ok: {chave} {antes[0]}.{antes[1]} -> {agora[0]}.{agora[1]}"
            )

    # Versão que só aparece de um lado é troca que não conseguimos comparar.
    orfas = sorted((set(removidas) ^ set(adicionadas)))
    if orfas:
        explicacoes.append(
            "não comparável (aparece só de um lado do diff): " + ", ".join(orfas[:8])
        )
        return False, explicacoes

    return not majores, explicacoes


def principal(argv: list[str]) -> int:
    if len(argv) != 2:
        print("uso: classificar_bump.py <arquivo.diff>", file=sys.stderr)
        return 2

    diff = Path(argv[1]).read_text(encoding="utf-8", errors="replace")
    pode, explicacoes = classificar(diff)

    for linha in explicacoes:
        print(f"  {linha}")

    return 0 if pode else 1


if __name__ == "__main__":
    raise SystemExit(principal(sys.argv))
