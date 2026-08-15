#!/usr/bin/env python3
"""Coletor do Observatório da Superfície.

Observa, uma vez por execução, a superfície pública de cada alvo declarado em
``alvos.yml`` e grava o resultado numa série temporal append-only.

Doutrina desta ferramenta, herdada da suíte:

  *Inconclusivo não é ausência.*

Quando uma sonda falha — timeout, DNS que não resolve, crt.sh fora do ar — o
registro fica com ``status: "inconclusivo"`` e um motivo textual. Nunca é
gravado "ausente", porque não medir e medir-e-não-achar são fatos diferentes e
confundi-los é o defeito que este projeto existe para não cometer.

Só a biblioteca padrão. Nenhuma dependência externa, de propósito: o coletor
precisa continuar rodando daqui a um ano sem manutenção de dependência.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

RAIZ = Path(__file__).resolve().parent.parent

# Sem acento, e isto não é preferência de estilo: field-value de cabeçalho HTTP
# é US-ASCII. Os 4 bytes latin-1 que "cabeçalhos públicos; requisições" punha na
# rede (0xE7 0xFA 0xE7 0xF5) fazem a Cloudflare responder 403 na raiz de
# owasp.org e de www.cloudflare.com — cabeçalho malformado tem assinatura de
# ataque. Medido em 2026-08-15, mesma URL e mesmo minuto, só mudando o acento:
# com acento, 403 servido pela cloudflare; em ASCII, 200 com CSP e HSTS.
#
# Não é contornar bloqueio. Mesma identidade, mesma URL, mesma frequência: é
# parar de mandar cabeçalho quebrado.
AGENTE = (
    "ObservatorioDaSuperficie/1.0 "
    "(+https://github.com/Paulo-Marcos-Lucio/observatorio-da-superficie; "
    "coleta passiva de cabecalhos publicos; 4 requisicoes por hora)"
)

# Fonte única do que o coletor põe na rede. Cabeçalho novo entra aqui, e o
# invariante de ASCII em `_abrir` passa a cobri-lo sozinho.
CABECALHOS_ENVIADOS = {"User-Agent": AGENTE}

TEMPO_LIMITE = 15

# Cabeçalhos observados. A ordem é a da leitura humana: transporte, conteúdo,
# enquadramento, referência, permissões, isolamento, e por fim o que o servidor
# revela de si mesmo sem precisar.
CABECALHOS = [
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "server",
    "x-powered-by",
    "x-aspnet-version",
]


# --------------------------------------------------------------------------
# infraestrutura
# --------------------------------------------------------------------------


class SemRedirecionamento(urllib.request.HTTPRedirectHandler):
    """Impede o urllib de seguir redirecionamento.

    A cadeia de redirecionamento é dado observável — quem sobe de :80 para
    :443 e com qual código — e seguir o redirect apaga esse dado.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _abrir(
    url: str,
    metodo: str = "GET",
    tentativas: int = 3,
    espera: float = 4.0,
    limite: int = 65536,
    cabecalhos_extra: dict[str, str] | None = None,
) -> tuple[int, dict[str, list[str]], bytes]:
    """Abre a URL sem seguir redirect, com repetição em falha de transporte.

    Falha de transporte (timeout, conexão recusada, 5xx) é repetida: a rede do
    executor é intermitente e um timeout não diz nada sobre o alvo. Já 3xx e
    4xx são *resposta* — voltam de primeira, sem repetição.
    """
    cabecalhos = {**CABECALHOS_ENVIADOS, **(cabecalhos_extra or {})}

    # Byte não-ASCII em field-value é cabeçalho malformado, e WAF trata isso
    # como ataque: o alvo responde 403 e a sonda mede a página de bloqueio em
    # vez do site. Barrar aqui, antes da rede, faz o `@sonda` registrar
    # `inconclusivo` com o motivo em vez de publicar um 403 como se fosse
    # resposta do alvo — a mesma doutrina que já vale para o resto: não medir
    # não é medir ausência.
    for nome, valor in cabecalhos.items():
        if not valor.isascii():
            raise ValueError(
                f"cabeçalho {nome!r} tem byte não-ASCII e não pode ir para a rede: {valor!r}"
            )

    pedido = urllib.request.Request(url, method=metodo, headers=cabecalhos)
    abridor = urllib.request.build_opener(SemRedirecionamento)
    ultimo: Exception | None = None

    for tentativa in range(tentativas):
        try:
            with abridor.open(pedido, timeout=TEMPO_LIMITE) as resposta:
                return resposta.status, _agrupar(resposta.headers), resposta.read(limite)
        except urllib.error.HTTPError as erro:
            if erro.code >= 500 and tentativa < tentativas - 1:
                ultimo = erro
                time.sleep(espera * (tentativa + 1))
                continue
            corpo = b""
            with contextlib.suppress(Exception):  # corpo ausente é normal
                corpo = erro.read(limite)
            return erro.code, _agrupar(erro.headers), corpo
        except Exception as erro:  # noqa: BLE001 - timeout, DNS, TLS, reset
            ultimo = erro
            if tentativa < tentativas - 1:
                time.sleep(espera * (tentativa + 1))

    raise ultimo if ultimo else RuntimeError("falha sem exceção registrada")


def _agrupar(headers) -> dict[str, list[str]]:
    """Agrupa cabeçalhos repetidos (Set-Cookie aparece N vezes) em listas."""
    saida: dict[str, list[str]] = {}
    for nome, valor in headers.items():
        saida.setdefault(nome.lower(), []).append(valor)
    return saida


def sonda(nome: str):
    """Decorador que transforma exceção em registro `inconclusivo`.

    É aqui que a doutrina vira código: nenhuma sonda pode devolver silêncio.
    """

    def envelope(funcao):
        def executar(alvo: str) -> dict[str, Any]:
            try:
                dados = funcao(alvo)
                return {"sonda": nome, "status": "ok", **dados}
            except Exception as erro:  # noqa: BLE001 - queremos capturar tudo
                return {
                    "sonda": nome,
                    "status": "inconclusivo",
                    "motivo": f"{type(erro).__name__}: {erro}"[:300],
                }

        # O nome da sonda fica acessível de fora do envelope. Sem isto,
        # `funcao.__name__` vira "executar" para quem inspeciona a lista de
        # sondas — e a sonda pulada seria registrada na série com o nome do
        # decorador em vez do nome dela.
        executar.sonda_nome = nome
        executar.__name__ = funcao.__name__
        executar.__doc__ = funcao.__doc__
        return executar

    return envelope


# --------------------------------------------------------------------------
# sondas
# --------------------------------------------------------------------------


# Códigos com que uma borda de proteção costuma responder a um cliente que ela
# não reconhece. Ver `_bloqueio_de_borda`.
CODIGOS_DE_BORDA = {401, 403, 405, 406, 409, 429, 451, 503}

# Cabeçalhos que qualquer CDN saudável emite. Servem para enriquecer o motivo
# quando o código já indica recusa — nunca, sozinhos, para declarar bloqueio.
_ASSINATURAS_FRACAS = (
    "cf-ray",
    "x-akamai-transformed",
    "x-sucuri-id",
)

# Cabeçalhos que só aparecem quando a borda decidiu barrar. `cf-mitigated` é
# emitido pela Cloudflare exatamente ao aplicar desafio; `x-iinfo` é o carimbo
# da página de incidente da Imperva.
_ASSINATURAS_FORTES = (
    "cf-mitigated",
    "x-iinfo",
)

_TEXTOS_DE_BORDA = (
    "attention required",
    "just a moment",
    "access denied",
    "request blocked",
    "verifying you are human",
    "checking your browser",
    "enable javascript and cookies",
    "incapsula incident",
    "the requested url was rejected",
    "acesso negado",
)


def _bloqueio_de_borda(
    codigo: int, cabecalhos: dict[str, list[str]], corpo: bytes = b""
) -> dict[str, Any] | None:
    """A resposta veio da aplicação ou de uma borda que barrou o cliente?

    Esta é a armadilha central de qualquer leitura de superfície feita por
    script: um WAF que barra o cliente devolve a *sua própria* resposta, com os
    *seus próprios* cabeçalhos. Quem mede sem distinguir acaba publicando a
    postura do WAF e atribuindo ela ao alvo — e como a página de bloqueio
    costuma ser pobre em cabeçalho, o alvo aparece com nota baixa que não é
    dele.

    Um 403 na raiz de um site que existe para servir uma página inicial não é
    postura, é recusa. O tratamento correto é `inconclusivo`, não nota ruim.

    **Nem todo bloqueio vem com código de recusa.** A primeira versão desta
    função saía com ``return None`` antes de olhar qualquer coisa quando o
    código não era 4xx/5xx — e por essa porta passava justamente a forma mais
    comum de bloqueio moderno: a Imperva devolve a página "Request
    unsuccessful. Incapsula incident ID" com **HTTP 200**, e o F5 ASM faz o
    mesmo com "The requested URL was rejected". A decisão agora é por
    evidência, não por código.
    """
    texto = corpo[:8192].decode("utf-8", "replace").lower()
    servidor = " ".join(cabecalhos.get("server", [])).lower()

    fortes = [a for a in _ASSINATURAS_FORTES if a in cabecalhos]
    textos = [m for m in _TEXTOS_DE_BORDA if m in texto]

    # Um 200 só é declarado bloqueio com evidência de alta especificidade: um
    # cabeçalho que a borda só emite ao barrar, OU o texto da própria página de
    # bloqueio. `cf-ray` e `server: cloudflare` não bastam — eles aparecem em
    # milhões de respostas saudáveis, e usá-los aqui transformaria metade da
    # web em "inconclusivo".
    if codigo not in CODIGOS_DE_BORDA and not fortes and not textos:
        return None

    indicios = [f"HTTP {codigo} na raiz"]

    for nome in ("cloudflare", "akamai", "sucuri", "imperva", "incapsula", "awselb"):
        if nome in servidor:
            indicios.append(f"Server: {servidor}")
            break

    for assinatura in fortes + [a for a in _ASSINATURAS_FRACAS if a in cabecalhos]:
        indicios.append(f"cabeçalho `{assinatura}` presente")

    if textos:
        indicios.append(f"corpo contém {textos[0]!r}")

    return {"bloqueado": True, "indicios": indicios}


@sonda("porta80")
def sondar_porta80(alvo: str) -> dict[str, Any]:
    """A porta 80 redireciona para HTTPS? Com qual código? Para onde?"""
    codigo, cabecalhos, corpo = _abrir(f"http://{alvo}/")
    bloqueio = _bloqueio_de_borda(codigo, cabecalhos, corpo)
    if bloqueio:
        # Sem isto, um 403 do WAF viraria "não sobe para HTTPS" — uma afirmação
        # sobre o alvo que a medição não sustenta.
        raise RuntimeError(
            "resposta veio de uma borda de proteção, não da aplicação: "
            + "; ".join(bloqueio["indicios"])
        )

    destino = cabecalhos.get("location", [None])[0]
    return {
        "codigo": codigo,
        "destino": destino,
        "sobe_para_https": bool(destino and destino.lower().startswith("https://")),
        "redireciona": 300 <= codigo < 400,
    }


@sonda("cabecalhos")
def sondar_cabecalhos(alvo: str) -> dict[str, Any]:
    """Cabeçalhos de segurança na resposta HTTPS da raiz — e a CSP em `<meta>`."""
    codigo, cabecalhos, corpo = _abrir(f"https://{alvo}/")

    bloqueio = _bloqueio_de_borda(codigo, cabecalhos, corpo)
    if bloqueio:
        raise RuntimeError(
            "resposta veio de uma borda de proteção, não da aplicação: "
            + "; ".join(bloqueio["indicios"])
            + " — os cabeçalhos desta resposta são do WAF e não descrevem o alvo"
        )

    # Dois valores por cabeçalho, e a distinção não é cosmética: o corte em 600
    # existe para o painel não virar uma parede de texto, mas ANALISAR o valor
    # cortado é publicar coisa falsa. A CSP da Mozilla tem mais de 600
    # caracteres, e nas duas primeiras coletas deste repositório ela foi lida
    # como se acabasse no corte — numa `tem_frame_ancestors=True`, na outra
    # `False`, só porque a diretiva caiu de lado diferente da tesoura.
    presentes: dict[str, str] = {}
    integros: dict[str, list[str]] = {}
    for nome in CABECALHOS:
        if nome in cabecalhos:
            integros[nome] = cabecalhos[nome]
            presentes[nome] = " | ".join(cabecalhos[nome])[:600]

    csp_meta = _ler_csp_meta(corpo)

    return {
        "truncado_para_exibicao": sorted(
            n for n, v in integros.items() if len(" | ".join(v)) > 600
        ),
        "codigo": codigo,
        "cabecalhos": presentes,
        "cookies": _ler_cookies(cabecalhos.get("set-cookie", [])),
        # A análise sempre come o valor íntegro, nunca o cortado.
        "hsts": _ler_hsts(_primeiro(integros.get("strict-transport-security"))),
        "csp": _ler_csp_multipla(integros.get("content-security-policy")),
        "csp_meta": csp_meta,
    }


def _primeiro(valores: list[str] | None) -> str | None:
    """O primeiro valor de um cabeçalho repetido.

    Para HSTS é o que o navegador faz: cabeçalho duplicado, vale o primeiro.
    """
    return valores[0] if valores else None


# Diretivas que o navegador IGNORA quando a CSP chega por `<meta http-equiv>`
# em vez de cabeçalho. Fonte: CSP Level 3, §"Restrictions on meta element".
# É a pegadinha central: um site servido por hospedagem estática costuma pôr a
# CSP no HTML achando que está protegido contra enquadramento — e não está,
# porque `frame-ancestors` só vale no cabeçalho.
DIRETIVAS_IGNORADAS_EM_META = {"frame-ancestors", "report-uri", "sandbox"}


def _ler_csp_meta(corpo: bytes) -> dict[str, Any] | None:
    """Procura `<meta http-equiv="Content-Security-Policy" content="...">`.

    Duas armadilhas de parsing, ambas já custaram caro aqui:

    1. O valor de uma CSP é **cheio de apóstrofo** (`'self'`, `'none'`,
       `'unsafe-inline'`). Um padrão que capture `["']([^"']+)["']` para na
       primeira palavra-chave e devolve `default-src ` — política truncada,
       análise errada, e nenhum erro levantado. A captura precisa casar a aspa
       de abertura com a de fechamento por retrovisor.
    2. A ordem dos atributos no HTML é livre: `content` pode vir antes de
       `http-equiv`. Exigir uma ordem faz o parser perder páginas válidas.

    Só os primeiros 64 KB do corpo chegam aqui. Uma CSP declarada depois disso
    passa despercebida — mas CSP em `<meta>` precisa estar antes de qualquer
    conteúdo para valer, então na prática ela está no topo do `<head>`.
    """
    html = corpo.decode("utf-8", "replace")

    bruta: str | None = None
    for etiqueta in re.finditer(r"<meta\b[^>]*>", html, re.I):
        texto = etiqueta.group(0)
        if not re.search(r"""http-equiv\s*=\s*["']?\s*content-security-policy\b""", texto, re.I):
            continue
        conteudo = re.search(r"""content\s*=\s*(["'])(.*?)\1""", texto, re.I | re.S)
        if conteudo:
            bruta = conteudo.group(2)
            break

    if bruta is None:
        return None

    lida = _ler_csp(bruta)
    if lida is None:
        return None

    declaradas = {p.strip().split(None, 1)[0].lower() for p in bruta.split(";") if p.strip()}
    lida["ignoradas_por_estar_em_meta"] = sorted(declaradas & DIRETIVAS_IGNORADAS_EM_META)
    return lida


def _ler_cookies(brutos: list[str]) -> list[dict[str, Any]]:
    """Lê as flags dos cookies **sem jamais guardar o valor**.

    O valor de um cookie de sessão é credencial. Este repositório é público e
    a série fica versionada para sempre; guardar valor seria criar um vazamento
    permanente por descuido. Só o nome e as flags são observáveis úteis.
    """
    lidos = []
    for bruto in brutos:
        pedacos = [p.strip() for p in bruto.split(";")]
        nome = pedacos[0].split("=", 1)[0] if pedacos else "?"
        flags = {p.split("=", 1)[0].lower() for p in pedacos[1:]}
        samesite = next(
            (p.split("=", 1)[1] for p in pedacos[1:] if p.lower().startswith("samesite=")),
            None,
        )
        lidos.append(
            {
                "nome": nome,
                "secure": "secure" in flags,
                "httponly": "httponly" in flags,
                "samesite": samesite,
                # o valor NÃO é coletado, por decisão de projeto
            }
        )
    return lidos


def _ler_hsts(valor: str | None) -> dict[str, Any] | None:
    """Lê o HSTS distinguindo três estados que não podem virar um só.

    * **sem `max-age`** — o cabeçalho é inválido e o navegador o descarta
      inteiro. Não é HSTS curto, é HSTS nenhum.
    * **`max-age=0`** — é a instrução explícita para o navegador **apagar** a
      política já armazenada. É o que um site emite ao fazer rollback de HSTS.
      Tratar isso como "HSTS presente, só que curto" e dar crédito parcial é
      pontuar a ausência de uma proteção pela existência do texto que a remove.
    * **`max-age>0`** — HSTS de verdade.
    """
    if not valor:
        return None

    idade = re.search(r"max-age\s*=\s*\"?(\d+)\"?", valor, re.I)
    if idade is None:
        return {
            "max_age_segundos": None,
            "max_age_dias": None,
            "valido": False,
            "desligado": False,
            "include_subdomains": False,
            "preload": False,
            "motivo": "cabeçalho sem max-age — o navegador descarta a política inteira",
        }

    segundos = int(idade.group(1))
    return {
        "max_age_segundos": segundos,
        "max_age_dias": round(segundos / 86400, 1),
        "valido": True,
        "desligado": segundos == 0,
        "include_subdomains": "includesubdomains" in valor.lower(),
        "preload": "preload" in valor.lower(),
        **(
            {"motivo": "max-age=0 manda o navegador APAGAR a política — HSTS desligado"}
            if segundos == 0
            else {}
        ),
    }


def _ler_csp_multipla(valores: list[str] | None) -> dict[str, Any] | None:
    """Lê CSP quando o cabeçalho aparece mais de uma vez.

    O navegador aplica **todas** as políticas: um recurso precisa ser permitido
    por cada uma delas, o que na prática é a interseção do que é liberado. Ler
    as políticas concatenadas com um separador inventado (`" | "`) cola a
    última diretiva de uma na primeira da outra e produz uma política que não
    existe em lugar nenhum.
    """
    if not valores:
        return None

    lidas = [p for p in (_ler_csp(v) for v in valores) if p]
    if not lidas:
        return None
    if len(lidas) == 1:
        return lidas[0]

    combinada = {
        "n_politicas": len(lidas),
        "n_diretivas": sum(p["n_diretivas"] for p in lidas),
    }
    # Uma restrição vale se QUALQUER política a impõe (todas são aplicadas).
    for campo in (
        "tem_default_src",
        "tem_frame_ancestors",
        "tem_object_src",
        "usa_nonce",
        "usa_strict_dynamic",
    ):
        combinada[campo] = any(p[campo] for p in lidas)
    # Uma frouxidão conta se QUALQUER política a contém.
    for campo in ("usa_unsafe_inline", "usa_unsafe_eval"):
        combinada[campo] = any(p[campo] for p in lidas)
    return combinada


def _ler_csp(valor: str | None) -> dict[str, Any] | None:
    if not valor:
        return None
    diretivas = {}
    for pedaco in valor.split(";"):
        pedaco = pedaco.strip()
        if not pedaco:
            continue
        partes = pedaco.split(None, 1)
        diretivas[partes[0].lower()] = partes[1] if len(partes) > 1 else ""
    texto = valor.lower()
    return {
        "n_diretivas": len(diretivas),
        "tem_default_src": "default-src" in diretivas,
        "tem_frame_ancestors": "frame-ancestors" in diretivas,
        "tem_object_src": "object-src" in diretivas,
        "usa_unsafe_inline": "'unsafe-inline'" in texto,
        "usa_unsafe_eval": "'unsafe-eval'" in texto,
        "usa_nonce": "'nonce-" in texto,
        "usa_strict_dynamic": "'strict-dynamic'" in texto,
    }


@sonda("tls")
def sondar_tls(alvo: str) -> dict[str, Any]:
    """Handshake TLS: versão negociada, cifra, emissor e validade do certificado."""
    contexto = ssl.create_default_context()
    with (
        socket.create_connection((alvo, 443), timeout=TEMPO_LIMITE) as bruto,
        contexto.wrap_socket(bruto, server_hostname=alvo) as seguro,
    ):
        certificado = seguro.getpeercert()
        versao = seguro.version()
        cifra = seguro.cipher()

    def campo(secao: str, chave: str) -> str | None:
        for grupo in certificado.get(secao, ()):
            for nome, valor in grupo:
                if nome == chave:
                    return valor
        return None

    expira = datetime.strptime(certificado["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    sans = [v for t, v in certificado.get("subjectAltName", ()) if t == "DNS"]

    return {
        "versao": versao,
        "cifra": cifra[0] if cifra else None,
        "bits": cifra[2] if cifra else None,
        "emissor": campo("issuer", "organizationName"),
        "expira_em": expira.date().isoformat(),
        "dias_para_expirar": (expira - datetime.now(UTC)).days,
        "n_sans": len(sans),
    }


@sonda("security_txt")
def sondar_security_txt(alvo: str) -> dict[str, Any]:
    """`/.well-known/security.txt` — quem publica canal de divulgação de falha.

    Três estados diferentes, que não podem ser colapsados em dois:

    * **404** — o arquivo não existe. Aqui a ausência é conclusiva: o caminho é
      padronizado (RFC 9116) e existe justamente para ser buscado.
    * **200 sem `Contact:`** — o arquivo existe mas não segue a RFC. É o caso da
      Mozilla, que publica um texto livre. Dizer "não publicado" seria falso.
    * **403/503** — a borda barrou. Não sabemos. Vira inconclusivo.
    """
    codigo, cabecalhos, corpo = _abrir(f"https://{alvo}/.well-known/security.txt")

    bloqueio = _bloqueio_de_borda(codigo, cabecalhos, corpo)
    if bloqueio:
        raise RuntimeError(
            "resposta veio de uma borda de proteção: " + "; ".join(bloqueio["indicios"])
        )

    texto = corpo.decode("utf-8", "replace") if codigo == 200 else ""
    campos = {
        linha.split(":", 1)[0].strip().lower()
        for linha in texto.splitlines()
        if ":" in linha and not linha.strip().startswith("#")
    }
    return {
        "codigo": codigo,
        "existe": codigo == 200 and bool(texto.strip()),
        "conforme_rfc9116": codigo == 200 and "contact" in campos,
        "campos": sorted(campos)[:12],
    }


# RCODEs de DNS, para que o motivo do inconclusivo diga o que houve.
_RCODE = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


@sonda("dns")
def sondar_dns(alvo: str) -> dict[str, Any]:
    """DNS por DoH (Cloudflare). Registro público, consulta passiva."""
    raiz = ".".join(alvo.split(".")[-2:]) if alvo.count(".") >= 1 else alvo

    def consultar(nome: str, tipo: str) -> list[str]:
        """Consulta DoH que distingue "não há registro" de "não consegui saber".

        O RCODE vem no campo ``Status`` do JSON, e o HTTP é 200 mesmo quando o
        resolvedor falhou. Ler só ``Answer`` faz SERVFAIL e REFUSED virarem
        lista vazia, indistinguível de ausência real — que é exatamente a
        confusão que este projeto existe para não cometer. Aqui o erro vira
        exceção, e o decorador ``@sonda`` a converte em `inconclusivo`.

        NOERROR (0) e NXDOMAIN (3) são conclusivos: o primeiro diz "o nome
        existe e não tem esse tipo de registro", o segundo diz "o nome não
        existe". Nos dois casos a lista vazia é uma afirmação legítima.

        O resultado sai **ordenado**: o resolvedor rotaciona a ordem do RRset a
        cada consulta, e comparar listas na ordem de chegada faria o diário
        publicar "o registro CAA mudou" duas vezes por dia para sempre.
        """
        url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode(
            {"name": nome, "type": tipo}
        )
        codigo, _, corpo = _abrir(url, cabecalhos_extra={"accept": "application/dns-json"})
        if codigo != 200:
            raise RuntimeError(f"resolvedor DoH respondeu HTTP {codigo} para {tipo} {nome}")

        resposta = json.loads(corpo)
        estado = resposta.get("Status")
        if estado not in (0, 3):
            raise RuntimeError(
                f"consulta {tipo} de {nome} voltou RCODE {estado} "
                f"({_RCODE.get(estado, 'desconhecido')}) — não sabemos, não é ausência"
            )

        return sorted(r["data"] for r in resposta.get("Answer", []) if "data" in r)

    txt = consultar(raiz, "TXT")
    dmarc = consultar(f"_dmarc.{raiz}", "TXT")

    return {
        "dominio_raiz": raiz,
        # Sem fatiar: fatiar um conjunto sem ordem estável guarda um subconjunto
        # diferente a cada coleta e inventa mudança que nunca houve. A mozilla.org
        # tem 11 registros CAA, e o `[:8]` anterior já produziu uma entrada falsa
        # de "registro CAA mudou" no diário público.
        "a": consultar(alvo, "A"),
        "aaaa": consultar(alvo, "AAAA"),
        "mx": consultar(raiz, "MX"),
        "caa": consultar(raiz, "CAA"),
        "spf": next((t for t in txt if "v=spf1" in t.lower()), None),
        "dmarc": next((t for t in dmarc if "v=dmarc1" in t.lower()), None),
        "n_txt": len(txt),
    }


@sonda("transparencia_certificados")
def sondar_ct(alvo: str) -> dict[str, Any]:
    """Certificados novos em log de Transparência (crt.sh).

    Certificado novo para um domínio é o sinal mais barato de superfície nova:
    subdomínio que apareceu, ambiente de homologação exposto, fornecedor que
    entrou. É registro público e a consulta não toca no alvo.
    """
    raiz = ".".join(alvo.split(".")[-2:]) if alvo.count(".") >= 1 else alvo
    url = "https://crt.sh/?" + urllib.parse.urlencode(
        {"q": f"%.{raiz}", "output": "json", "exclude": "expired"}
    )
    # crt.sh cai com frequência e devolve 502. Vale mais paciência aqui do que
    # nas outras sondas; e se mesmo assim não vier, vira inconclusivo — nunca
    # "zero certificados", que seria uma afirmação falsa sobre o mundo.
    codigo, _, corpo = _abrir(url, tentativas=3, espera=6.0, limite=8_000_000)
    if codigo != 200:
        raise RuntimeError(f"crt.sh respondeu HTTP {codigo}")
    entradas = json.loads(corpo)

    corte = (datetime.now(UTC) - timedelta(days=7)).date().isoformat()
    nomes = set()
    recentes = 0
    for entrada in entradas:
        for nome in str(entrada.get("name_value", "")).splitlines():
            nomes.add(nome.strip().lower())
        if str(entrada.get("entry_timestamp", ""))[:10] >= corte:
            recentes += 1

    return {
        "dominio_raiz": raiz,
        "n_certificados_validos": len(entradas),
        "n_emitidos_7d": recentes,
        "n_nomes_distintos": len(nomes),
    }


# Sondas que rodam em toda coleta: falam direto com o alvo ou com um resolvedor
# de DNS, e o custo é de quatro requisições.
SONDAS_DE_HORA = [
    sondar_porta80,
    sondar_cabecalhos,
    sondar_tls,
    sondar_security_txt,
    sondar_dns,
]

# Sondas de uma vez por dia. O crt.sh é um serviço comunitário gratuito e
# notoriamente sobrecarregado; consultá-lo de hora em hora para seis domínios
# seriam 144 consultas diárias em cima de uma infraestrutura que ninguém paga.
# Certificado novo também não aparece de hora em hora — a granularidade diária
# não perde nada que importe.
SONDAS_DO_DIA = [
    sondar_ct,
]


def _pulada(nome: str, motivo: str) -> dict[str, Any]:
    """Sonda que não rodou nesta coleta.

    Terceiro estado, distinto de `ok` e de `inconclusivo`: não houve tentativa.
    Chamar isso de inconclusivo seria dizer que tentamos e não soubemos, o que
    é falso — e a doutrina da casa é justamente não colapsar estados que
    significam coisas diferentes.
    """
    return {"sonda": nome, "status": "pulada", "motivo": motivo}


# --------------------------------------------------------------------------
# nota de postura
# --------------------------------------------------------------------------


# Valores de Referrer-Policy que de fato contêm o vazamento de URL para
# terceiro. `unsafe-url` e `no-referrer-when-downgrade` são o oposto disso, e
# um valor que o navegador não reconhece faz o cabeçalho inteiro ser ignorado.
_REFERRER_RESTRITIVO = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
_REFERRER_CONHECIDO = _REFERRER_RESTRITIVO | {
    "origin",
    "origin-when-cross-origin",
    "no-referrer-when-downgrade",
    "unsafe-url",
}


def nota_de_postura(observacao: dict[str, Any]) -> dict[str, Any]:
    """Nota 0–10 dos cabeçalhos, com o porquê de cada ponto.

    A nota só é calculada quando a sonda de cabeçalhos foi conclusiva. Se ela
    falhou, a nota é ``None`` — um alvo que não respondeu não tem nota zero,
    tem nota desconhecida.
    """
    cab = next((s for s in observacao["sondas"] if s["sonda"] == "cabecalhos"), None)
    if not cab or cab["status"] != "ok":
        motivo = (cab or {}).get("motivo", "sonda de cabeçalhos inconclusiva")
        if "borda de proteção" in motivo:
            motivo = (
                "o alvo respondeu pela borda de proteção, não pela aplicação; "
                "atribuir nota aqui seria dar nota ao WAF"
            )
        return {"nota": None, "motivo": motivo}

    presentes = cab.get("cabecalhos", {})
    hsts = cab.get("hsts")
    csp = cab.get("csp")
    csp_meta = cab.get("csp_meta")
    porta80 = next((s for s in observacao["sondas"] if s["sonda"] == "porta80"), None)

    pontos: list[tuple[str, float]] = []

    hsts_vale = bool(hsts and hsts.get("valido") and not hsts.get("desligado"))

    if hsts_vale and hsts["max_age_dias"] >= 180:
        pontos.append(("HSTS com max-age >= 180 dias", 1.5))
    elif hsts_vale:
        pontos.append(("HSTS presente mas com max-age curto", 0.7))

    if hsts_vale and hsts["include_subdomains"]:
        pontos.append(("HSTS cobre subdomínios", 0.5))

    if csp:
        base = 1.5
        if csp["tem_default_src"]:
            base += 0.5
        if csp["tem_frame_ancestors"]:
            base += 0.5
        if csp["usa_nonce"] or csp["usa_strict_dynamic"]:
            base += 0.5
        if csp["usa_unsafe_inline"]:
            base -= 0.7
        if csp["usa_unsafe_eval"]:
            base -= 0.5
        pontos.append(("CSP no cabeçalho", round(max(0.0, base), 2)))
    elif csp_meta:
        # CSP em `<meta>` vale menos, e vale menos por um motivo técnico, não
        # por preciosismo: o navegador descarta frame-ancestors, report-uri e
        # sandbox nessa forma. Protege contra XSS, não contra enquadramento.
        base = 1.0
        if csp_meta["tem_default_src"]:
            base += 0.4
        if csp_meta["usa_unsafe_inline"]:
            base -= 0.5
        pontos.append(("CSP em <meta> (crédito parcial)", round(max(0.0, base), 2)))

    if presentes.get("x-content-type-options", "").lower().startswith("nosniff"):
        pontos.append(("X-Content-Type-Options: nosniff", 1.0))

    # Enquadramento: só conta X-Frame-Options ou frame-ancestors NO CABEÇALHO.
    # frame-ancestors declarado em <meta> é ignorado pelo navegador e por isso
    # não pontua aqui — pontuar seria repetir o engano que o site cometeu.
    #
    # E o VALOR importa. `X-Frame-Options: ALLOWALL` existe para *permitir*
    # enquadramento, e `ALLOW-FROM` não é suportado por navegador moderno
    # nenhum: os dois deixam o site enquadrável. Creditar por presença do nome
    # do cabeçalho é medir a intenção de quem configurou, não o efeito.
    xfo = presentes.get("x-frame-options", "").strip().upper()
    xfo_vale = xfo in {"DENY", "SAMEORIGIN"}
    if xfo_vale or (csp and csp["tem_frame_ancestors"]):
        pontos.append(("Enquadramento restrito", 1.0))

    referrer = presentes.get("referrer-policy", "").strip().lower()
    # Vale o último token válido, que é como o navegador resolve a lista.
    tokens_referrer = [t.strip() for t in referrer.split(",") if t.strip()]
    ultimo = tokens_referrer[-1] if tokens_referrer else ""
    if ultimo in _REFERRER_RESTRITIVO:
        pontos.append(("Referrer-Policy restritiva", 1.0))
    elif ultimo in _REFERRER_CONHECIDO:
        pontos.append(("Referrer-Policy presente, mas permissiva", 0.3))
    if "permissions-policy" in presentes:
        pontos.append(("Permissions-Policy", 0.5))
    if "cross-origin-opener-policy" in presentes:
        pontos.append(("COOP", 0.5))

    if porta80 and porta80["status"] == "ok" and porta80.get("sobe_para_https"):
        pontos.append((":80 sobe para HTTPS", 1.0))

    penalidades: list[tuple[str, float]] = []

    ignoradas = (csp_meta or {}).get("ignoradas_por_estar_em_meta") or []
    if ignoradas:
        penalidades.append(
            (
                "CSP em <meta> declara "
                + ", ".join(ignoradas)
                + " — o navegador ignora essas diretivas nessa forma",
                -0.5,
            )
        )

    if hsts and hsts.get("desligado"):
        penalidades.append(("HSTS com max-age=0 — a política está sendo apagada", -0.5))
    if hsts and not hsts.get("valido"):
        penalidades.append(("HSTS sem max-age — o navegador descarta o cabeçalho", -0.3))
    if xfo and not xfo_vale:
        penalidades.append((f"X-Frame-Options com valor que o navegador ignora ({xfo})", -0.3))

    if "x-powered-by" in presentes:
        penalidades.append(("X-Powered-By revela pilha", -0.3))
    if "x-aspnet-version" in presentes:
        penalidades.append(("X-AspNet-Version revela versão", -0.3))

    for cookie in cab.get("cookies", []):
        if not cookie["secure"]:
            penalidades.append((f"cookie {cookie['nome']} sem Secure", -0.4))
            break
    for cookie in cab.get("cookies", []):
        if not cookie["httponly"]:
            penalidades.append((f"cookie {cookie['nome']} sem HttpOnly", -0.3))
            break

    bruto = sum(p for _, p in pontos) + sum(p for _, p in penalidades)
    return {
        "nota": round(max(0.0, min(10.0, bruto)), 2),
        "ganhos": pontos,
        "perdas": penalidades,
    }


# --------------------------------------------------------------------------
# alvos
# --------------------------------------------------------------------------


def ler_alvos(caminho: Path) -> list[dict[str, str]]:
    """Lê ``alvos.yml``.

    Parser mínimo e proposital: só entende a forma que este projeto usa
    (``- host: x`` seguido de campos indentados). Evita depender de PyYAML só
    para ler seis linhas.
    """
    alvos: list[dict[str, str]] = []
    atual: dict[str, str] | None = None
    for linha in caminho.read_text(encoding="utf-8").splitlines():
        sem_comentario = linha.split("#", 1)[0].rstrip()
        if not sem_comentario.strip():
            continue
        if sem_comentario.lstrip().startswith("- "):
            if atual:
                alvos.append(atual)
            atual = {}
            sem_comentario = sem_comentario.lstrip()[2:]
        if atual is None or ":" not in sem_comentario:
            continue
        chave, valor = sem_comentario.split(":", 1)
        atual[chave.strip()] = valor.strip().strip('"').strip("'")
    if atual:
        alvos.append(atual)
    return [a for a in alvos if a.get("host")]


# --------------------------------------------------------------------------
# execução
# --------------------------------------------------------------------------


def observar(alvo: dict[str, str], completa: bool = False) -> dict[str, Any]:
    host = alvo["host"]
    sondas = [s(host) for s in SONDAS_DE_HORA]

    if completa:
        sondas += [s(host) for s in SONDAS_DO_DIA]
    else:
        sondas += [
            _pulada(
                s.sonda_nome,
                "sonda diária: roda só na coleta completa, para não martelar "
                "um serviço comunitário gratuito de hora em hora",
            )
            for s in SONDAS_DO_DIA
        ]

    observacao: dict[str, Any] = {
        "alvo": host,
        "classe": alvo.get("classe", "referencia"),
        "sondas": sondas,
    }
    observacao["postura"] = nota_de_postura(observacao)
    observacao["impressao"] = _impressao(observacao)
    return observacao


# Campos que mudam sozinhos entre duas coletas sem que nada tenha mudado no
# alvo. Entram na série, mas não contam para decidir se vale guardar um
# instantâneo novo.
_VOLATEIS = {"dias_para_expirar", "motivo", "n_certificados_validos", "n_emitidos_7d"}


def _impressao(observacao: dict[str, Any]) -> str:
    """Impressão digital estável da observação.

    Serve para responder "isto é igual à última vez?" sem se deixar enganar
    por nonce de CSP que rotaciona a cada resposta nem por um contador de dias
    até o certificado expirar, que cai sozinho todo dia.
    """

    def limpar(valor: Any) -> Any:
        if isinstance(valor, dict):
            return {c: limpar(v) for c, v in sorted(valor.items()) if c not in _VOLATEIS}
        if isinstance(valor, list):
            return [limpar(v) for v in valor]
        if isinstance(valor, str):
            return re.sub(r"'nonce-[A-Za-z0-9+/=_-]+'", "'nonce-…'", valor)
        return valor

    estavel = limpar([s for s in observacao["sondas"] if s["status"] != "pulada"])
    return hashlib.sha256(
        json.dumps(estavel, ensure_ascii=False, sort_keys=True).encode()
    ).hexdigest()[:16]


def _ultima_impressao(destino: Path) -> dict[str, str]:
    """As impressões digitais da última coleta registrada na série."""
    serie = destino / "serie.jsonl"
    if not serie.exists():
        return {}
    ultimo_momento, impressoes = None, {}
    for linha in serie.read_text(encoding="utf-8").splitlines():
        if not linha.strip():
            continue
        try:
            reg = json.loads(linha)
        except json.JSONDecodeError:
            continue
        if reg.get("coletado_em") != ultimo_momento:
            ultimo_momento, impressoes = reg.get("coletado_em"), {}
        if reg.get("impressao"):
            impressoes[reg["alvo"]] = reg["impressao"]
    return impressoes


def principal(argv: list[str] | None = None) -> int:
    analisador = argparse.ArgumentParser(description="Coletor do Observatório da Superfície")
    analisador.add_argument("--alvos", default=str(RAIZ / "alvos.yml"))
    analisador.add_argument("--saida", default=str(RAIZ / "dados"))
    analisador.add_argument("--host", action="append", help="observa só este host (repetível)")
    analisador.add_argument(
        "--completa",
        action="store_true",
        help="roda também as sondas diárias (crt.sh) e força gravar o instantâneo",
    )
    argumentos = analisador.parse_args(argv)

    alvos = ler_alvos(Path(argumentos.alvos))
    if argumentos.host:
        pedidos = set(argumentos.host)
        alvos = [a for a in alvos if a["host"] in pedidos]
    if not alvos:
        print("nenhum alvo a observar", file=sys.stderr)
        return 2

    momento = datetime.now(UTC)
    coleta = {
        "coletado_em": momento.isoformat(timespec="seconds"),
        "versao_coletor": "1.0",
        "observacoes": [],
    }

    destino = Path(argumentos.saida)
    destino.mkdir(parents=True, exist_ok=True)
    anteriores = _ultima_impressao(destino)

    for alvo in alvos:
        print(f"  observando {alvo['host']} ...", file=sys.stderr, flush=True)
        coleta["observacoes"].append(observar(alvo, completa=argumentos.completa))

    # A série é o arquivo permanente: uma linha compacta por alvo por coleta,
    # sempre. É ela que sustenta a afirmação "medimos de hora em hora".
    serie = destino / "serie.jsonl"
    with serie.open("a", encoding="utf-8") as arquivo:
        for observacao in coleta["observacoes"]:
            arquivo.write(
                json.dumps(
                    {
                        "coletado_em": coleta["coletado_em"],
                        "alvo": observacao["alvo"],
                        "classe": observacao["classe"],
                        "nota": observacao["postura"]["nota"],
                        "impressao": observacao["impressao"],
                        "sondas": {s["sonda"]: s["status"] for s in observacao["sondas"]},
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    # O instantâneo com os cabeçalhos inteiros só é gravado quando há o que
    # guardar: alguma coisa mudou, ou é a coleta completa do dia. Guardar 23 KB
    # de cabeçalhos idênticos a cada hora custaria 193 MB por ano de histórico
    # que o Git nunca esquece, para registrar que nada aconteceu.
    mudou = [
        o["alvo"] for o in coleta["observacoes"] if anteriores.get(o["alvo"]) != o["impressao"]
    ]
    grava = bool(mudou) or argumentos.completa

    instantaneo = None
    if grava:
        dia = destino / momento.strftime("%Y") / momento.strftime("%m")
        dia.mkdir(parents=True, exist_ok=True)
        instantaneo = dia / f"{momento.strftime('%Y-%m-%dT%H%MZ')}.json"
        coleta["completa"] = argumentos.completa
        coleta["mudaram"] = mudou
        instantaneo.write_text(
            json.dumps(coleta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    conclusivas = sum(1 for o in coleta["observacoes"] for s in o["sondas"] if s["status"] == "ok")
    total = sum(1 for o in coleta["observacoes"] for s in o["sondas"] if s["status"] != "pulada")
    motivo = "coleta completa" if argumentos.completa else f"mudou: {', '.join(mudou)}"
    print(
        f"série: {len(coleta['observacoes'])} observações, "
        f"{conclusivas}/{total} sondas conclusivas | "
        + (f"instantâneo em {instantaneo} ({motivo})" if grava else "sem mudança, sem instantâneo"),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(principal())
