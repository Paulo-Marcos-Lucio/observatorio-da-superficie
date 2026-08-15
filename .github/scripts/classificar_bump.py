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
* ``uses: dono/acao@v3`` e ``uses: dono/acao@v3.1.0`` — GitHub Actions
* ``dono/acao@<sha>  # v3.1.0`` — Actions fixada por SHA, versão no comentário

Qualquer linha que *pareça* declarar dependência e não caia em nenhum desses
formatos é registrada como ilegível e impede a mescla. Ver ``SUSPEITAS``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# A minor é opcional. `actions/checkout@v5` é a forma mais comum de fixar uma
# action, e exigir `major.minor` deixava justamente essa de fora: o padrão não
# casava, `_extrair` devolvia None e a troca sumia do diff sem deixar rastro.
# Sem minor, a versão é lida como `.0` — que é o que `v5` significa para efeito
# de comparação de major.
VERSAO = r"(?P<maj>\d+)(?:\.(?P<min>\d+))?(?:\.(?P<pat>\d+))?"

PADROES = [
    # nome==1.2.3 / nome>=1.2.3 / nome~=1.2.3
    re.compile(rf"^(?P<chave>[A-Za-z0-9._-]+)\s*[=><~!]=+\s*v?{VERSAO}"),
    # "nome": "^1.2.3"  |  "nome": "~1.2.3"
    re.compile(rf'^"?(?P<chave>[@A-Za-z0-9._/-]+)"?\s*:\s*"[\^~>=<]*v?{VERSAO}'),
    # <version>1.2.3</version>  (a chave vem do artifactId mais próximo, se houver)
    re.compile(rf"^<version>v?{VERSAO}</version>"),
    # uses: dono/acao@v3  |  uses: dono/acao@v3.1.0
    #
    # O `(?![\w.])` no fim não é enfeite. Com a minor opcional, um SHA que começa
    # com dígito (`@08c6903cd8…`) casaria aqui como major `08`, e a linha nunca
    # chegaria no padrão de SHA logo abaixo — a action fixada por SHA passaria a
    # ser lida como versão 8.0. O lookahead exige que a versão termine ali: `v5`
    # e `v5.1.0` casam, prefixo de SHA não.
    re.compile(rf"^uses:\s*(?P<chave>[\w.-]+/[\w./-]+)@v?{VERSAO}(?![\w.])"),
    # dono/acao@sha  # v3.1.0   (action fixada por SHA, versão no comentário)
    #
    # A vírgula final dentro do `re.compile(` é a vírgula mágica do formatador:
    # ela trava a forma explodida nos seis repositórios, que rodam este mesmo
    # arquivo com line-length diferente. Sem ela o arquivo fica com um hash em
    # cada repo, e "as seis cópias são idênticas" deixa de ser verificável num
    # decisor de merge automático.
    re.compile(
        rf"^(?:uses:\s*)?(?P<chave>[\w.-]+/[\w./-]+)@[0-9a-f]{{7,40}}\s*#\s*v?{VERSAO}(?![\w.])",
    ),
]

# Linhas que declaram dependência mesmo quando nenhum padrão acima consegue ler
# a versão. Existem para transformar *invisível* em *ilegível*.
#
# A diferença decide merge. Uma troca invisível não entra em lugar nenhum: nem
# em `comuns`, nem em `orfas`. Bastava uma segunda linha legível e não-major no
# mesmo diff — um `hypothesis` subindo de patch, digamos — para o job concluir
# "não-major comprovado" e mesclar sozinho um `actions/checkout@v5 -> @v7`.
# Marcada como ilegível, a mesma linha recusa a mescla e diz qual é.
#
# É o mesmo princípio que governa as sondas do Observatório: não medir não é
# medir ausência.
SUSPEITAS = [
    re.compile(r"^uses:\s*[\w.-]+/[\w./-]+@"),
    re.compile(r"^[A-Za-z0-9._-]+\s*[=><~!]=+\s*\S"),
    re.compile(r"^<version>.+</version>"),
]

# Constante, e não literal no ponto de uso, por um motivo mecânico: os seis
# repositórios rodam o mesmo arquivo com line-length diferente (108 aqui, 100
# nos outros), e um literal nesta altura de indentação fica formatado de um
# jeito em cada um — o `ruff format --check` de um reprova o do outro.
_SEM_VERSAO_LEGIVEL = (
    "nenhuma troca de versão pôde ser lida do diff — sem prova de que é não-major, não mescla"
)


def _corpo(linha: str) -> str:
    """Conteúdo da linha de diff, sem o sinal e sem o marcador de item YAML.

    O marcador precisa sair antes do casamento. A linha real de um workflow é
    ``      - uses: acao@sha # v7.0.1``; depois do ``strip()`` ela começa com
    ``- uses:``, e um padrão ancorado em ``^uses:`` não casa.
    """
    return re.sub(r"^-\s+", "", linha[1:].strip())


def _extrair(linha: str) -> tuple[str, tuple[int, int]] | None:
    """Nome e (major, minor) de uma linha de diff, se ela declarar versão."""
    corpo = _corpo(linha)
    for padrao in PADROES:
        achado = padrao.match(corpo)
        if achado:
            chave = achado.groupdict().get("chave") or "<version>"
            return chave.lower(), (int(achado.group("maj")), int(achado.group("min") or 0))
    return None


def _parece_dependencia(linha: str) -> bool:
    """A linha declara dependência, mesmo que a versão não tenha sido lida?"""
    corpo = _corpo(linha)
    return any(padrao.match(corpo) for padrao in SUSPEITAS)


def classificar(diff: str) -> tuple[bool, list[str]]:
    """(pode_mesclar, explicações)."""
    removidas: dict[str, tuple[int, int]] = {}
    adicionadas: dict[str, tuple[int, int]] = {}
    ilegiveis: list[str] = []

    for linha in diff.splitlines():
        if linha.startswith("---") or linha.startswith("+++"):
            continue
        if not linha.startswith(("-", "+")):
            continue

        extraido = _extrair(linha)
        if extraido is None:
            if _parece_dependencia(linha):
                ilegiveis.append(_corpo(linha))
            continue

        alvo = removidas if linha.startswith("-") else adicionadas
        alvo[extraido[0]] = extraido[1]

    if ilegiveis:
        return False, [
            "linha de dependência sem versão legível — sem prova de que é "
            "não-major, não mescla: " + "; ".join(sorted(set(ilegiveis))[:4])
        ]

    comuns = sorted(set(removidas) & set(adicionadas))

    if not comuns:
        return False, [_SEM_VERSAO_LEGIVEL]

    explicacoes = []
    majores = []
    for chave in comuns:
        antes, agora = removidas[chave], adicionadas[chave]
        if agora[0] != antes[0]:
            majores.append(chave)
            explicacoes.append(f"MAJOR: {chave} {antes[0]}.{antes[1]} -> {agora[0]}.{agora[1]}")
        else:
            explicacoes.append(f"ok: {chave} {antes[0]}.{antes[1]} -> {agora[0]}.{agora[1]}")

    # Versão que só aparece de um lado é troca que não conseguimos comparar.
    orfas = sorted(set(removidas) ^ set(adicionadas))
    if orfas:
        explicacoes.append(
            "não comparável (aparece só de um lado do diff): " + ", ".join(orfas[:8]),
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
