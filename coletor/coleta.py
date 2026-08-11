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

AGENTE = (
    "ObservatorioDaSuperficie/1.0 "
    "(+https://github.com/Paulo-Marcos-Lucio/observatorio-da-superficie; "
    "coleta passiva de cabeçalhos públicos; 2 requisições/dia)"
)

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
    pedido = urllib.request.Request(
        url, method=metodo, headers={"User-Agent": AGENTE, **(cabecalhos_extra or {})}
    )
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

        return executar

    return envelope


# --------------------------------------------------------------------------
# sondas
# --------------------------------------------------------------------------


# Códigos com que uma borda de proteção costuma responder a um cliente que ela
# não reconhece. Ver `_bloqueio_de_borda`.
CODIGOS_DE_BORDA = {401, 403, 405, 406, 409, 429, 451, 503}

_ASSINATURAS_DE_BORDA = (
    "cf-ray",
    "cf-mitigated",
    "x-akamai-transformed",
    "x-sucuri-id",
    "x-iinfo",
    "server-timing",
)

_TEXTOS_DE_BORDA = (
    "attention required",
    "just a moment",
    "access denied",
    "request blocked",
    "verifying you are human",
    "checking your browser",
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
    """
    if codigo not in CODIGOS_DE_BORDA:
        return None

    indicios = [f"HTTP {codigo} na raiz"]

    servidor = " ".join(cabecalhos.get("server", [])).lower()
    for nome in ("cloudflare", "akamai", "sucuri", "imperva", "incapsula", "awselb"):
        if nome in servidor:
            indicios.append(f"Server: {servidor}")
            break

    for assinatura in _ASSINATURAS_DE_BORDA:
        if assinatura in cabecalhos:
            indicios.append(f"cabeçalho `{assinatura}` presente")

    texto = corpo[:8192].decode("utf-8", "replace").lower()
    for marca in _TEXTOS_DE_BORDA:
        if marca in texto:
            indicios.append(f"corpo contém {marca!r}")
            break

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

    presentes: dict[str, str] = {}
    for nome in CABECALHOS:
        if nome in cabecalhos:
            presentes[nome] = " | ".join(cabecalhos[nome])[:600]

    csp_meta = _ler_csp_meta(corpo)

    return {
        "codigo": codigo,
        "cabecalhos": presentes,
        "cookies": _ler_cookies(cabecalhos.get("set-cookie", [])),
        "hsts": _ler_hsts(presentes.get("strict-transport-security")),
        "csp": _ler_csp(presentes.get("content-security-policy")),
        "csp_meta": csp_meta,
    }


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
    if not valor:
        return None
    idade = re.search(r"max-age\s*=\s*(\d+)", valor, re.I)
    segundos = int(idade.group(1)) if idade else 0
    return {
        "max_age_segundos": segundos,
        "max_age_dias": round(segundos / 86400, 1),
        "include_subdomains": "includesubdomains" in valor.lower(),
        "preload": "preload" in valor.lower(),
    }


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


@sonda("dns")
def sondar_dns(alvo: str) -> dict[str, Any]:
    """DNS por DoH (Cloudflare). Registro público, consulta passiva."""
    raiz = ".".join(alvo.split(".")[-2:]) if alvo.count(".") >= 1 else alvo

    def consultar(nome: str, tipo: str) -> list[str]:
        url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode(
            {"name": nome, "type": tipo}
        )
        _, _, corpo = _abrir(url, cabecalhos_extra={"accept": "application/dns-json"})
        resposta = json.loads(corpo)
        return [r["data"] for r in resposta.get("Answer", []) if "data" in r]

    txt = consultar(raiz, "TXT")
    dmarc = consultar(f"_dmarc.{raiz}", "TXT")

    return {
        "dominio_raiz": raiz,
        "a": consultar(alvo, "A")[:8],
        "aaaa": consultar(alvo, "AAAA")[:8],
        "mx": consultar(raiz, "MX")[:8],
        "caa": consultar(raiz, "CAA")[:8],
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


SONDAS = [
    sondar_porta80,
    sondar_cabecalhos,
    sondar_tls,
    sondar_security_txt,
    sondar_dns,
    sondar_ct,
]


# --------------------------------------------------------------------------
# nota de postura
# --------------------------------------------------------------------------


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

    if hsts and hsts["max_age_dias"] >= 180:
        pontos.append(("HSTS com max-age >= 180 dias", 1.5))
    elif hsts:
        pontos.append(("HSTS presente mas com max-age curto", 0.7))

    if hsts and hsts["include_subdomains"]:
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
    if "x-frame-options" in presentes or (csp and csp["tem_frame_ancestors"]):
        pontos.append(("Enquadramento restrito", 1.0))
    if "referrer-policy" in presentes:
        pontos.append(("Referrer-Policy", 1.0))
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


def observar(alvo: dict[str, str]) -> dict[str, Any]:
    host = alvo["host"]
    observacao: dict[str, Any] = {
        "alvo": host,
        "classe": alvo.get("classe", "referencia"),
        "sondas": [s(host) for s in SONDAS],
    }
    observacao["postura"] = nota_de_postura(observacao)
    return observacao


def principal(argv: list[str] | None = None) -> int:
    analisador = argparse.ArgumentParser(description="Coletor do Observatório da Superfície")
    analisador.add_argument("--alvos", default=str(RAIZ / "alvos.yml"))
    analisador.add_argument("--saida", default=str(RAIZ / "dados"))
    analisador.add_argument("--host", action="append", help="observa só este host (repetível)")
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

    for alvo in alvos:
        print(f"  observando {alvo['host']} ...", file=sys.stderr, flush=True)
        coleta["observacoes"].append(observar(alvo))

    destino = Path(argumentos.saida)
    dia = destino / momento.strftime("%Y") / momento.strftime("%m")
    dia.mkdir(parents=True, exist_ok=True)

    instantaneo = dia / f"{momento.strftime('%Y-%m-%dT%H%MZ')}.json"
    instantaneo.write_text(
        json.dumps(coleta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

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
                        "sondas": {s["sonda"]: s["status"] for s in observacao["sondas"]},
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    conclusivas = sum(1 for o in coleta["observacoes"] for s in o["sondas"] if s["status"] == "ok")
    total = sum(len(o["sondas"]) for o in coleta["observacoes"])
    print(
        f"coleta gravada em {instantaneo} — {conclusivas}/{total} sondas conclusivas",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(principal())
