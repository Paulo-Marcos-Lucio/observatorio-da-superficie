#!/usr/bin/env python3
"""Gera o painel (README.md) e o diário de mudanças a partir da série coletada.

Duas saídas, com propósitos diferentes:

* ``README.md`` — o estado de agora. É reescrito a cada coleta.
* ``diario/AAAA-MM-DD.md`` — o que *mudou*. Só é escrito quando de fato mudou
  alguma coisa, porque um diário que registra "nada mudou" todo dia não é um
  diário, é ruído.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

RAIZ = Path(__file__).resolve().parent.parent
DADOS = RAIZ / "dados"
DIARIO = RAIZ / "diario"

# `coleta.py` mora no mesmo diretório. Quando este arquivo roda como script
# (`python coletor/painel.py`, o jeito como o workflow e o operador o
# invocam), o Python já põe `coletor/` no início do `sys.path` sozinho — mas
# sob pytest não, e os testes deste repositório importam os dois módulos
# depois de inserir o caminho manualmente. Repetir a inserção aqui torna o
# import seguro nos dois casos, sem depender de quem importou primeiro.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import coleta  # noqa: E402


def _instantaneo_e_parcial(n_observacoes: int, esperados: int) -> bool:
    """Um instantâneo com menos alvos do que `alvos.yml` declara agora é
    amostra de depuração (execução local com `--host`), não um estado do
    mundo — ver `coletas`. `esperados == 0` (arquivo ilegível ou vazio)
    desliga o filtro em vez de descartar a série inteira: falha aberta, não
    fechada, porque perder um instantâneo real é pior que deixar passar um
    parcial que este código não conseguiu reconhecer.
    """
    return esperados > 0 and n_observacoes < esperados


def _sem_parciais(
    historico: list[tuple[str, dict[str, Any]]], esperados: int
) -> list[tuple[str, dict[str, Any]]]:
    """Tira da lista os instantâneos parciais — ver `_instantaneo_e_parcial`."""
    return [
        (nome, c)
        for nome, c in historico
        if not _instantaneo_e_parcial(len(c.get("observacoes", [])), esperados)
    ]


def coletas() -> list[tuple[str, dict[str, Any]]]:
    """Todas as coletas *completas*, da mais antiga para a mais nova.

    Uma execução local com `--host` grava um instantâneo parcial na mesma
    série append-only das coletas de produção. Em 2026-08-12 isso fez os
    quatro alvos ausentes da amostra parecerem "saíram da lista de
    observação" e, na coleta seguinte, "voltarem" como alvo novo — oito
    afirmações falsas sobre organizações de terceiros, num repositório
    público (CAMPO-11). Um instantâneo parcial serve para depurar; comparado
    como se fosse um estado do mundo, ele inventa entrada e saída que nunca
    houve. Ficar fora daqui vale tanto para o diário quanto para o README:
    os dois partem desta mesma lista.
    """
    arquivos = sorted(DADOS.glob("*/*/*.json"))
    bruto = []
    for arquivo in arquivos:
        try:
            bruto.append((arquivo.stem, json.loads(arquivo.read_text(encoding="utf-8"))))
        except json.JSONDecodeError:
            continue
    esperados = len(coleta.ler_alvos(RAIZ / "alvos.yml"))
    return _sem_parciais(bruto, esperados)


def por_alvo(coleta: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {o["alvo"]: o for o in coleta.get("observacoes", [])}


def sonda_de(observacao: dict[str, Any], nome: str) -> dict[str, Any] | None:
    return next((s for s in observacao["sondas"] if s["sonda"] == nome), None)


def _ok(observacao: dict[str, Any], nome: str) -> dict[str, Any] | None:
    """A sonda, se e somente se ela foi conclusiva."""
    sonda = sonda_de(observacao, nome)
    return sonda if sonda and sonda["status"] == "ok" else None


# --------------------------------------------------------------------------
# comparação
# --------------------------------------------------------------------------


# Trechos que mudam a cada requisição sem que nada tenha mudado no alvo. Sem
# neutralizá-los, o diário acusaria "a CSP mudou" duas vezes por dia para
# sempre — e um diário que grita todo dia é um diário que ninguém lê. É a mesma
# disciplina de falso-positivo que a suíte aplica em detector: o que dispara
# sempre não informa nada.
_RUIDO = (
    # nonce de CSP: rotaciona por resposta, é assim que ele funciona
    (re.compile(r"'nonce-[A-Za-z0-9+/=_-]+'"), "'nonce-…'"),
    # hash de subrecurso e report-uri com identificador de sessão
    (re.compile(r"'sha(256|384|512)-[A-Za-z0-9+/=]+'"), "'sha…'"),
    (re.compile(r"\breport-uri\s+\S+"), "report-uri …"),
)


def _normalizar(valor: str) -> str:
    """Apaga o que muda por requisição, preserva o que muda por decisão."""
    for padrao, marca in _RUIDO:
        valor = padrao.sub(marca, valor)
    return valor


def _mudanca_de_endereco(antes: list[str] | None, agora: list[str] | None) -> bool:
    """Houve migração, ou é só o balanceamento devolvendo outro IP?

    Um domínio grande devolve um subconjunto rotativo dos seus endereços a cada
    consulta. Comparar as listas cruas acusaria mudança em toda coleta. O sinal
    que interessa é **zero interseção**: quando nenhum endereço de antes
    aparece agora, o host de fato se mudou.
    """
    antes_c, agora_c = set(antes or []), set(agora or [])
    if antes_c == agora_c:
        return False
    if not antes_c or not agora_c:
        return True
    return not (antes_c & agora_c)


def comparar(antes: dict[str, Any], agora: dict[str, Any]) -> list[str]:
    """Diferenças observáveis entre duas leituras do mesmo alvo.

    Uma sonda que era conclusiva e virou inconclusiva (ou o contrário) é
    reportada como mudança de *visibilidade*, nunca como mudança do alvo. O
    alvo pode não ter mexido em nada; quem mudou fomos nós, que deixamos de
    enxergar.
    """
    mudancas: list[str] = []

    for nome in (
        "porta80",
        "cabecalhos",
        "tls",
        "security_txt",
        "dns",
        "transparencia_certificados",
    ):
        s_antes, s_agora = sonda_de(antes, nome), sonda_de(agora, nome)
        if not s_antes or not s_agora:
            continue
        # `pulada` não é mudança do alvo nem perda de visibilidade: é uma sonda
        # que não roda toda hora, por decisão declarada.
        if "pulada" in (s_antes["status"], s_agora["status"]):
            continue
        if s_antes["status"] != s_agora["status"]:
            if s_agora["status"] == "inconclusivo":
                mudancas.append(
                    f"sonda `{nome}` deixou de ser conclusiva "
                    f"({s_agora.get('motivo', '?')}) — isto é perda de visibilidade "
                    f"nossa, não afirmação sobre o alvo"
                )
            else:
                mudancas.append(f"sonda `{nome}` voltou a ser conclusiva")

    a_cab, b_cab = _ok(antes, "cabecalhos"), _ok(agora, "cabecalhos")
    if a_cab and b_cab:
        antigos, novos = a_cab["cabecalhos"], b_cab["cabecalhos"]
        for nome in sorted(set(novos) - set(antigos)):
            mudancas.append(f"passou a enviar `{nome}`")
        for nome in sorted(set(antigos) - set(novos)):
            mudancas.append(f"**parou de enviar `{nome}`**")
        for nome in sorted(set(antigos) & set(novos)):
            antes_n, agora_n = _normalizar(antigos[nome]), _normalizar(novos[nome])
            if antes_n != agora_n:
                mudancas.append(
                    f"`{nome}` mudou de valor\n"
                    f"  - antes: `{antigos[nome][:180]}`\n"
                    f"  - agora: `{novos[nome][:180]}`"
                )

        cookies_antes = {c["nome"]: c for c in a_cab.get("cookies", [])}
        cookies_agora = {c["nome"]: c for c in b_cab.get("cookies", [])}
        for nome in sorted(set(cookies_agora) - set(cookies_antes)):
            c = cookies_agora[nome]
            mudancas.append(
                f"cookie novo `{nome}` (Secure={c['secure']}, "
                f"HttpOnly={c['httponly']}, SameSite={c['samesite']})"
            )
        for nome in sorted(set(cookies_antes) & set(cookies_agora)):
            if cookies_antes[nome] != cookies_agora[nome]:
                mudancas.append(f"flags do cookie `{nome}` mudaram")

    a_tls, b_tls = _ok(antes, "tls"), _ok(agora, "tls")
    if a_tls and b_tls:
        if a_tls["expira_em"] != b_tls["expira_em"]:
            mudancas.append(
                f"certificado renovado — expira em {b_tls['expira_em']} "
                f"(emissor {b_tls['emissor']})"
            )
        if a_tls["versao"] != b_tls["versao"]:
            mudancas.append(f"TLS negociado mudou: {a_tls['versao']} → {b_tls['versao']}")
        if b_tls["dias_para_expirar"] <= 14 < a_tls["dias_para_expirar"]:
            mudancas.append(
                f"⚠ certificado entra em {b_tls['dias_para_expirar']} dias para expirar"
            )

    a_dns, b_dns = _ok(antes, "dns"), _ok(agora, "dns")
    if a_dns and b_dns:
        # Endereço só vira entrada de diário em alvo próprio.
        #
        # Num domínio grande atrás de anycast/CDN, o conjunto de IPs devolvido
        # troca por completo entre duas consultas sem que ninguém tenha mexido
        # em nada — é a infraestrutura respirando. Reportar isso encheria o
        # diário de evento que o leitor não pode agir sobre.
        #
        # Em alvo próprio é o oposto: o Paulo controla o DNS, e o endereço
        # mudar sem ele saber é exatamente o que um observatório existe para
        # avisar. O dado continua gravado na série para os dois casos; o que
        # muda é o que merece ser narrado.
        if agora.get("classe") == "proprio":
            for campo, rotulo in (("a", "A"), ("aaaa", "AAAA")):
                if _mudanca_de_endereco(a_dns.get(campo), b_dns.get(campo)):
                    mudancas.append(
                        f"**registro {rotulo} trocou por completo** — nenhum endereço de "
                        f"antes responde agora: `{a_dns.get(campo)}` → `{b_dns.get(campo)}`"
                    )

        # MX e CAA não rotacionam: mudança aqui é decisão de configuração.
        for campo, rotulo in (("mx", "MX"), ("caa", "CAA")):
            if sorted(a_dns.get(campo) or []) != sorted(b_dns.get(campo) or []):
                mudancas.append(
                    f"registro {rotulo} mudou: `{a_dns.get(campo)}` → `{b_dns.get(campo)}`"
                )
        for campo in ("spf", "dmarc"):
            if a_dns.get(campo) != b_dns.get(campo):
                mudancas.append(f"{campo.upper()} mudou")

    a_ct, b_ct = _ok(antes, "transparencia_certificados"), _ok(agora, "transparencia_certificados")
    if a_ct and b_ct:
        delta = b_ct["n_nomes_distintos"] - a_ct["n_nomes_distintos"]
        if delta > 0:
            mudancas.append(
                f"**{delta} nome(s) novo(s) em log de Transparência de Certificados** "
                f"— superfície nova publicada"
            )

    return mudancas


# --------------------------------------------------------------------------
# painel
# --------------------------------------------------------------------------


def simbolo(valor: bool | None) -> str:
    return {True: "✅", False: "—", None: "·"}[valor]


def _marca_security_txt(stxt: dict[str, Any] | None) -> str:
    """Três estados, três marcas — existe e segue a RFC não é a mesma coisa."""
    if not stxt:
        return "·"
    if stxt.get("conforme_rfc9116"):
        return "✅"
    if stxt.get("existe"):
        return "⚠ fora da RFC"
    return "—"


def linha_da_tabela(observacao: dict[str, Any]) -> str:
    cab = _ok(observacao, "cabecalhos")
    tls = _ok(observacao, "tls")
    stxt = _ok(observacao, "security_txt")

    if not cab:
        sonda = sonda_de(observacao, "cabecalhos") or {}
        nota_rodape = (
            "barrado na borda" if "borda de proteção" in sonda.get("motivo", "") else "inconclusivo"
        )
        cert = f"{tls['dias_para_expirar']}d" if tls else "·"
        # O motivo explica a NOTA, então ele vai na coluna da nota. Na primeira
        # versão ele caía na nona célula — a de `security.txt` — e o README
        # publicado dizia "security.txt: barrado na borda" quando o que fora
        # barrado era a raiz. E o resultado real da sonda de security.txt, que
        # pode ter sido conclusivo, era jogado fora.
        return (
            f"| `{observacao['alvo']}` | {observacao['classe']} | {nota_rodape} | "
            f"· | · | · | · | · | {_marca_security_txt(stxt)} | {cert} |"
        )

    presentes = cab["cabecalhos"]
    csp = cab.get("csp")
    csp_meta = cab.get("csp_meta")

    if csp:
        marca_csp = "✅"
    elif csp_meta:
        marca_csp = "⚠ meta"
    else:
        marca_csp = "—"

    nota = observacao["postura"]["nota"]
    cert = f"{tls['dias_para_expirar']}d" if tls else "·"

    return (
        f"| `{observacao['alvo']}` "
        f"| {observacao['classe']} "
        f"| **{nota if nota is not None else '·'}** "
        f"| {simbolo('strict-transport-security' in presentes)} "
        f"| {marca_csp} "
        f"| {simbolo('x-frame-options' in presentes or bool(csp and csp['tem_frame_ancestors']))} "
        f"| {simbolo('x-content-type-options' in presentes)} "
        f"| {simbolo('referrer-policy' in presentes)} "
        f"| {_marca_security_txt(stxt)} "
        f"| {cert} |"
    )


def _resumo_da_serie() -> tuple[str, int]:
    """(momento da última coleta, quantas coletas) lidos da série.

    O painel não pode datar-se pelo último instantâneo: instantâneo só é
    gravado quando algo muda, então um período estável faria o README parecer
    parado enquanto a coleta seguia rodando de hora em hora.
    """
    serie = DADOS / "serie.jsonl"
    if not serie.exists():
        return "—", 0
    momentos = set()
    for linha in serie.read_text(encoding="utf-8").splitlines():
        if not linha.strip():
            continue
        try:
            momentos.add(json.loads(linha)["coletado_em"])
        except (json.JSONDecodeError, KeyError):
            continue
    return (max(momentos) if momentos else "—"), len(momentos)


def gerar_readme(historico: list[tuple[str, dict[str, Any]]]) -> str:
    marca, ultima = historico[-1]
    observacoes = sorted(
        ultima["observacoes"],
        key=lambda o: (o["classe"] != "proprio", -(o["postura"]["nota"] or -1)),
    )

    total_sondas = sum(
        1 for o in ultima["observacoes"] for s in o["sondas"] if s["status"] != "pulada"
    )
    conclusivas = sum(1 for o in ultima["observacoes"] for s in o["sondas"] if s["status"] == "ok")
    ultima_coleta, n_coletas = _resumo_da_serie()

    partes = [
        "# Observatório da Superfície",
        "",
        "Leitura diária e passiva da superfície pública de um punhado de alvos —",
        "cabeçalhos de segurança, TLS, DNS e Transparência de Certificados —",
        "guardada como série temporal para que a **mudança** fique visível.",
        "",
        "Um relatório de segurança tirado num dia só diz como o alvo estava naquele dia.",
        "O que interessa é a deriva: o cabeçalho que sumiu numa migração, o certificado",
        "que passou a ser emitido por outro fornecedor, o subdomínio de homologação que",
        "apareceu num log de Transparência. Isso só aparece medindo todo dia e comparando.",
        "",
        f"**Última coleta:** {ultima_coleta} · "
        f"**{n_coletas} coletas** na série (de hora em hora) · "
        f"**{len(historico)} instantâneos** guardados",
        "",
        f"O quadro abaixo é do instantâneo de `{ultima['coletado_em']}`, "
        f"com {conclusivas}/{total_sondas} sondas conclusivas. Instantâneo com os",
        "cabeçalhos inteiros só é guardado quando alguma coisa muda — a série",
        "registra todas as horas, mas 23 KB de cabeçalhos idênticos por hora",
        "seriam 193 MB por ano de histórico para dizer que nada aconteceu.",
        "",
        "## Postura observada",
        "",
        "| Alvo | Classe | Nota | HSTS | CSP | Enquadr. | nosniff "
        "| Referrer | security.txt | Cert. |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    partes += [linha_da_tabela(o) for o in observacoes]
    partes += [
        "",
        "`·` significa **inconclusivo**: a sonda não conseguiu medir. Não é o mesmo que",
        "ausente, e este projeto nunca escreve um pelo outro.",
        "",
        "`⚠ meta` significa CSP entregue por `<meta http-equiv>` em vez de cabeçalho.",
        "Vale contra XSS, mas o navegador **descarta** `frame-ancestors`, `report-uri` e",
        "`sandbox` nessa forma — quem confia nela para barrar enquadramento não está",
        "barrando nada.",
        "",
    ]

    proprios = [o for o in observacoes if o["classe"] == "proprio"]
    if proprios:
        partes += ["## O que o observatório encontra na própria casa", ""]
        for o in proprios:
            postura = o["postura"]
            partes.append(f"### `{o['alvo']}` — nota {postura['nota']}")
            partes.append("")
            for rotulo, valor in postura.get("ganhos", []):
                partes.append(f"- `+{valor}` {rotulo}")
            for rotulo, valor in postura.get("perdas", []):
                partes.append(f"- `{valor}` {rotulo}")
            partes.append("")

    diarios = sorted(DIARIO.glob("*.md"), reverse=True)[:10] if DIARIO.exists() else []
    if diarios:
        partes += ["## Diário de mudanças", "", "Dias em que a superfície observada mudou:", ""]
        partes += [f"- [{d.stem}](diario/{d.name})" for d in diarios]
        partes.append("")

    partes += [
        "## Como isto funciona",
        "",
        "- `alvos.yml` — a lista, com a justificativa de admissão de cada alvo.",
        "- `coletor/coleta.py` — as sondas. Só biblioteca padrão do Python, para que",
        "  continue rodando daqui a um ano sem manutenção de dependência.",
        "- `dados/serie.jsonl` — série append-only, uma linha por alvo por coleta.",
        "- `dados/AAAA/MM/*.json` — o instantâneo bruto de cada coleta.",
        "- `diario/` — o texto do que mudou, quando mudou.",
        "- [`REGRAS-DE-ENGAJAMENTO.md`](REGRAS-DE-ENGAJAMENTO.md) — o que é coletado, o que",
        "  nunca é coletado, e como pedir a remoção de um alvo.",
        "",
        "Nenhum valor de cookie é gravado, em nenhuma hipótese. Nenhuma sonda envia",
        "requisição que altere estado. Nenhum alvo é observado sem política pública que",
        "autorize a observação.",
        "",
        "---",
        "",
        "<sub>Painel gerado por `coletor/painel.py`. A coleta é automática; a lista de alvos,",
        "as regras e a leitura dos achados são decisão humana.</sub>",
        "",
    ]
    return "\n".join(partes)


def gerar_diario(anterior: dict[str, Any], atual: dict[str, Any]) -> tuple[str, str] | None:
    """Devolve (nome_do_arquivo, conteudo) se houve mudança; senão None."""
    antes, agora = por_alvo(anterior), por_alvo(atual)
    blocos: list[str] = []

    for alvo in sorted(set(antes) & set(agora)):
        mudancas = comparar(antes[alvo], agora[alvo])
        if mudancas:
            blocos.append(f"### `{alvo}`\n\n" + "\n".join(f"- {m}" for m in mudancas))

    for alvo in sorted(set(agora) - set(antes)):
        blocos.append(f"### `{alvo}`\n\n- alvo novo, primeira observação")

    for alvo in sorted(set(antes) - set(agora)):
        blocos.append(f"### `{alvo}`\n\n- alvo saiu da lista de observação")

    if not blocos:
        return None

    momento = atual["coletado_em"]
    dia = momento[:10]
    conteudo = (
        f"# Mudanças observadas em {dia}\n\n"
        f"Comparação entre a coleta de `{anterior['coletado_em']}` e a de `{momento}`.\n\n"
        + "\n\n".join(blocos)
        + "\n"
    )
    return f"{dia}.md", conteudo


def principal() -> int:
    historico = coletas()
    if not historico:
        print("nenhuma coleta encontrada")
        return 1

    (RAIZ / "README.md").write_text(gerar_readme(historico), encoding="utf-8")
    print("README.md gerado")

    if len(historico) >= 2:
        diario = gerar_diario(historico[-2][1], historico[-1][1])
        if diario:
            nome, conteudo = diario
            DIARIO.mkdir(exist_ok=True)
            destino = DIARIO / nome
            if destino.exists():
                anterior = destino.read_text(encoding="utf-8")
                corpo = conteudo.split("\n\n", 2)[-1]
                destino.write_text(anterior.rstrip() + "\n\n---\n\n" + corpo, encoding="utf-8")
            else:
                destino.write_text(conteudo, encoding="utf-8")
            print(f"diario/{nome} escrito")
        else:
            print("nada mudou desde a coleta anterior — diário não escrito")

    return 0


if __name__ == "__main__":
    raise SystemExit(principal())
