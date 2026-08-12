"""Invariantes do coletor.

Cada teste aqui tranca uma *classe* de erro, não um exemplo. A ordem de leitura
é a ordem de importância: primeiro o que impediria o observatório de mentir,
depois o que impediria ele de vazar, depois a aritmética.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "coletor"))

import coleta  # noqa: E402
import painel  # noqa: E402

# --------------------------------------------------------------------------
# 1. Nenhuma sonda devolve silêncio
# --------------------------------------------------------------------------


@given(
    erro=st.sampled_from(
        [
            TimeoutError("estourou"),
            ConnectionRefusedError("recusou"),
            ValueError("json quebrado"),
            OSError("rede sumiu"),
            RuntimeError("crt.sh respondeu HTTP 502"),
        ]
    )
)
def test_qualquer_excecao_vira_inconclusivo_com_motivo(erro):
    """Sonda que explode precisa devolver `inconclusivo`, nunca propagar.

    Se uma exceção escapasse, a coleta inteira do dia morreria por causa de um
    alvo — e o buraco na série seria interpretado depois como "não medimos
    nada", quando na verdade medimos cinco alvos e perdemos um.
    """

    @coleta.sonda("teste")
    def explode(_alvo):
        raise erro

    resultado = explode("exemplo.test")

    assert resultado["status"] == "inconclusivo"
    assert resultado["sonda"] == "teste"
    assert resultado["motivo"], "inconclusivo sem motivo é silêncio disfarçado"
    assert type(erro).__name__ in resultado["motivo"]


def test_sonda_bem_sucedida_marca_ok():
    @coleta.sonda("teste")
    def funciona(_alvo):
        return {"valor": 1}

    assert coleta.sonda("teste")(lambda _a: {"valor": 1})("x")["status"] == "ok"
    assert funciona("x")["valor"] == 1


# --------------------------------------------------------------------------
# 2. Valor de cookie nunca sai da máquina
# --------------------------------------------------------------------------


@given(
    nome=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), max_codepoint=122),
        min_size=1,
        max_size=20,
    ),
    valor=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), max_codepoint=122),
        min_size=8,
        max_size=64,
    ),
    flags=st.lists(st.sampled_from(["Secure", "HttpOnly", "Path=/", "SameSite=Lax"]), unique=True),
)
@settings(max_examples=200)
def test_valor_de_cookie_nunca_aparece_na_saida(nome, valor, flags):
    """Para *qualquer* cookie, o valor não pode sobreviver à leitura.

    Este repositório é público e o histórico do Git é permanente. Um único
    valor de cookie de sessão gravado por descuido vira vazamento eterno.
    A invariante é property-based de propósito: proteger contra o caso que eu
    lembrei de escrever não protege contra o caso que eu não lembrei.
    """
    bruto = f"{nome}={valor}" + "".join(f"; {f}" for f in flags)

    lidos = coleta._ler_cookies([bruto])

    assert len(lidos) == 1
    assert lidos[0]["nome"] == nome

    # O nome é gravado de propósito, então sai da checagem — senão o teste
    # falharia sozinho quando o Hypothesis sorteasse nome == valor.
    resto = {c: v for c, v in lidos[0].items() if c != "nome"}

    # A checagem é sobre os *valores* do registro, não sobre o `repr` inteiro:
    # o `repr` carrega os nomes dos campos, e o Hypothesis chega em `valor =
    # "httponly"` sem esforço nenhum — oito letras minúsculas. Comparar contra
    # o `repr` faria o teste acusar vazamento onde não há.
    for campo, conteudo in resto.items():
        assert valor not in str(conteudo), f"o valor do cookie vazou em `{campo}`"

    assert set(resto) == {"secure", "httponly", "samesite"}, (
        "surgiu campo novo no registro de cookie — ele precisa ser auditado "
        "antes de entrar, porque este repositório é público"
    )


def test_flags_de_cookie_sao_lidas():
    lidos = coleta._ler_cookies(["sid=abc123; Secure; HttpOnly; SameSite=Strict"])
    assert lidos[0] == {
        "nome": "sid",
        "secure": True,
        "httponly": True,
        "samesite": "Strict",
    }


# --------------------------------------------------------------------------
# 3. Bloqueio de borda nunca vira nota
# --------------------------------------------------------------------------


@given(codigo=st.sampled_from(sorted(coleta.CODIGOS_DE_BORDA)))
def test_codigo_de_recusa_e_reconhecido_como_borda(codigo):
    bloqueio = coleta._bloqueio_de_borda(codigo, {"server": ["cloudflare"]}, b"")
    assert bloqueio is not None
    assert bloqueio["bloqueado"] is True
    assert any("cloudflare" in i for i in bloqueio["indicios"])


@given(codigo=st.sampled_from([200, 201, 204, 301, 302, 304, 404, 410]))
def test_resposta_legitima_nao_e_confundida_com_borda(codigo):
    """404 é resposta da aplicação, não recusa da borda. Não pode virar bloqueio."""
    assert coleta._bloqueio_de_borda(codigo, {"server": ["cloudflare"]}, b"") is None


def test_alvo_barrado_na_borda_fica_sem_nota():
    """A regressão que este teste tranca aconteceu de verdade.

    A primeira execução deu nota 2,0 para `www.cloudflare.com` e para
    `owasp.org`. Nenhum dos dois tem postura ruim: os dois responderam 403 a um
    cliente não reconhecido, e o coletor mediu os cabeçalhos da página de
    bloqueio achando que eram do site.

    Nota baixa por WAF é pior que nota nenhuma, porque parece um resultado.
    """
    observacao = {
        "alvo": "exemplo.test",
        "classe": "referencia",
        "sondas": [
            {
                "sonda": "cabecalhos",
                "status": "inconclusivo",
                "motivo": "resposta veio de uma borda de proteção, não da aplicação: HTTP 403",
            }
        ],
    }

    postura = coleta.nota_de_postura(observacao)

    assert postura["nota"] is None
    assert "WAF" in postura["motivo"]


# --------------------------------------------------------------------------
# 4. CSP em <meta> não recebe crédito que o navegador não dá
# --------------------------------------------------------------------------


def test_frame_ancestors_em_meta_nao_pontua_enquadramento():
    """`frame-ancestors` declarado em `<meta>` é descartado pelo navegador.

    Pontuar essa declaração seria repetir, no instrumento de medida, o mesmo
    engano que o site cometeu na configuração.
    """
    corpo = (
        b"<html><head><meta http-equiv='Content-Security-Policy' "
        b"content=\"default-src 'self'; frame-ancestors 'none'\"></head></html>"
    )
    csp_meta = coleta._ler_csp_meta(corpo)

    assert csp_meta is not None
    assert csp_meta["tem_frame_ancestors"] is True
    assert csp_meta["ignoradas_por_estar_em_meta"] == ["frame-ancestors"]

    observacao = {
        "alvo": "exemplo.test",
        "classe": "proprio",
        "sondas": [
            {
                "sonda": "cabecalhos",
                "status": "ok",
                "cabecalhos": {},
                "cookies": [],
                "hsts": None,
                "csp": None,
                "csp_meta": csp_meta,
            }
        ],
    }

    postura = coleta.nota_de_postura(observacao)
    rotulos = [r for r, _ in postura["ganhos"]]

    assert "Enquadramento restrito" not in rotulos
    assert any("meta" in r for r, _ in postura["perdas"])


def test_csp_no_cabecalho_vale_mais_que_csp_em_meta():
    politica = "default-src 'self'; frame-ancestors 'none'"

    def observacao_com(**cab):
        base = {
            "sonda": "cabecalhos",
            "status": "ok",
            "cabecalhos": {},
            "cookies": [],
            "hsts": None,
            "csp": None,
            "csp_meta": None,
        }
        base.update(cab)
        return {"alvo": "x", "classe": "proprio", "sondas": [base]}

    no_cabecalho = coleta.nota_de_postura(
        observacao_com(
            cabecalhos={"content-security-policy": politica},
            csp=coleta._ler_csp(politica),
        )
    )
    em_meta = coleta.nota_de_postura(
        observacao_com(
            csp_meta=coleta._ler_csp_meta(
                f"<meta http-equiv='Content-Security-Policy' content=\"{politica}\">".encode()
            )
        )
    )

    assert no_cabecalho["nota"] > em_meta["nota"]


# --------------------------------------------------------------------------
# 5. Inconclusivo não é ausência
# --------------------------------------------------------------------------


def test_nota_e_none_e_nao_zero_quando_nao_ha_medida():
    """Alvo que não respondeu tem nota desconhecida, não nota zero.

    Zero é uma afirmação: "medi e não achei nada". `None` é a verdade quando
    não se mediu. Colapsar os dois é o defeito de classe que este projeto
    existe para não cometer.
    """
    observacao = {
        "alvo": "x",
        "classe": "proprio",
        "sondas": [{"sonda": "cabecalhos", "status": "inconclusivo", "motivo": "timeout"}],
    }
    postura = coleta.nota_de_postura(observacao)

    assert postura["nota"] is None
    assert postura["nota"] != 0


def test_nota_zero_existe_para_quem_realmente_nao_tem_nada():
    """E o contrário também precisa valer: quem respondeu sem nenhum cabeçalho
    de segurança recebe zero de verdade, não `None`."""
    observacao = {
        "alvo": "x",
        "classe": "proprio",
        "sondas": [
            {
                "sonda": "cabecalhos",
                "status": "ok",
                "cabecalhos": {},
                "cookies": [],
                "hsts": None,
                "csp": None,
                "csp_meta": None,
            }
        ],
    }
    assert coleta.nota_de_postura(observacao)["nota"] == 0.0


# --------------------------------------------------------------------------
# 6. Aritmética da nota
# --------------------------------------------------------------------------


@given(
    hsts_dias=st.integers(min_value=0, max_value=800),
    tem_csp=st.booleans(),
    tem_nosniff=st.booleans(),
    tem_xfo=st.booleans(),
    tem_referrer=st.booleans(),
)
@settings(max_examples=300)
def test_nota_fica_sempre_entre_zero_e_dez(hsts_dias, tem_csp, tem_nosniff, tem_xfo, tem_referrer):
    cabecalhos = {}
    if hsts_dias:
        cabecalhos["strict-transport-security"] = f"max-age={hsts_dias * 86400}"
    if tem_csp:
        cabecalhos["content-security-policy"] = "default-src 'self'; frame-ancestors 'none'"
    if tem_nosniff:
        cabecalhos["x-content-type-options"] = "nosniff"
    if tem_xfo:
        cabecalhos["x-frame-options"] = "DENY"
    if tem_referrer:
        cabecalhos["referrer-policy"] = "no-referrer"

    observacao = {
        "alvo": "x",
        "classe": "proprio",
        "sondas": [
            {
                "sonda": "cabecalhos",
                "status": "ok",
                "cabecalhos": cabecalhos,
                "cookies": [],
                "hsts": coleta._ler_hsts(cabecalhos.get("strict-transport-security")),
                "csp": coleta._ler_csp(cabecalhos.get("content-security-policy")),
                "csp_meta": None,
            }
        ],
    }

    nota = coleta.nota_de_postura(observacao)["nota"]
    assert 0.0 <= nota <= 10.0


def test_unsafe_inline_derruba_a_nota_da_csp():
    frouxa = coleta._ler_csp("default-src 'self'; script-src 'unsafe-inline'")
    firme = coleta._ler_csp("default-src 'self'; script-src 'nonce-abc123'")

    assert frouxa["usa_unsafe_inline"] is True
    assert firme["usa_nonce"] is True


# --------------------------------------------------------------------------
# 7. Leitura de alvos
# --------------------------------------------------------------------------


def test_alvos_do_repositorio_tem_justificativa(tmp_path):
    """Nenhum alvo entra sem justificativa — a regra do REGRAS-DE-ENGAJAMENTO
    precisa ser executável, não só escrita."""
    alvos = coleta.ler_alvos(Path(__file__).resolve().parent.parent / "alvos.yml")

    assert alvos, "a lista de alvos não pode estar vazia"
    for alvo in alvos:
        assert alvo.get("justificativa"), f"{alvo['host']} sem justificativa"
        assert alvo.get("classe") in {"proprio", "referencia"}, alvo


def test_parser_de_alvos_ignora_comentario(tmp_path):
    arquivo = tmp_path / "alvos.yml"
    arquivo.write_text(
        "# comentário\n"
        "- host: a.test\n"
        "  classe: proprio\n"
        '  justificativa: "minha"  # inline\n'
        "\n"
        "- host: b.test\n"
        "  classe: referencia\n"
        "  justificativa: 'bounty'\n",
        encoding="utf-8",
    )
    alvos = coleta.ler_alvos(arquivo)

    assert [a["host"] for a in alvos] == ["a.test", "b.test"]
    assert alvos[0]["justificativa"] == "minha"


# --------------------------------------------------------------------------
# 8. O diário não pode gritar todo dia
# --------------------------------------------------------------------------


@given(
    a=st.text(alphabet="ABCDEFabcdef0123456789+/=", min_size=16, max_size=44),
    b=st.text(alphabet="ABCDEFabcdef0123456789+/=", min_size=16, max_size=44),
)
def test_rotacao_de_nonce_nao_e_mudanca_de_politica(a, b):
    """Nonce de CSP muda a cada resposta — é assim que ele funciona.

    Sem neutralizar isso, o diário registraria "a CSP mudou" duas vezes por dia
    para sempre, em todo alvo que usa nonce. Um diário que grita todo dia é um
    diário que ninguém lê, e um instrumento que dispara sempre não informa nada.
    Mesma disciplina de falso-positivo que a suíte aplica em detector.
    """
    molde = "script-src 'strict-dynamic' 'nonce-{}'; object-src 'none'"

    assert painel._normalizar(molde.format(a)) == painel._normalizar(molde.format(b))


def test_mudanca_real_de_politica_continua_sendo_vista():
    """O dual da invariante acima: silenciar ruído não pode silenciar sinal."""
    antes = "script-src 'strict-dynamic' 'nonce-AAAA'; object-src 'none'"
    agora = "script-src 'unsafe-inline' 'nonce-BBBB'; object-src 'none'"

    assert painel._normalizar(antes) != painel._normalizar(agora)


@given(
    comuns=st.lists(
        st.text(alphabet="0123456789.", min_size=7, max_size=15), min_size=1, max_size=3
    ),
    extras_antes=st.lists(st.text(alphabet="0123456789.", min_size=7, max_size=15), max_size=3),
    extras_agora=st.lists(st.text(alphabet="0123456789.", min_size=7, max_size=15), max_size=3),
)
def test_rodizio_de_balanceador_nao_e_migracao(comuns, extras_antes, extras_agora):
    """Enquanto sobrar um endereço em comum, o host não se mudou.

    Domínio grande devolve um subconjunto rotativo dos seus IPs a cada consulta.
    Comparar as listas cruas acusaria migração em toda coleta.
    """
    antes = comuns + extras_antes
    agora = comuns + extras_agora

    assert painel._mudanca_de_endereco(antes, agora) is False


def test_troca_completa_de_endereco_e_reportada():
    """E quando nenhum endereço de antes responde, aí é migração de verdade."""
    assert painel._mudanca_de_endereco(["1.1.1.1", "1.1.1.2"], ["9.9.9.9"]) is True
    assert painel._mudanca_de_endereco([], ["9.9.9.9"]) is True
    assert painel._mudanca_de_endereco(["1.1.1.1"], []) is True
    assert painel._mudanca_de_endereco([], []) is False


def test_troca_de_ip_so_vira_diario_em_alvo_proprio():
    """Anycast respira; o DNS do Paulo não deveria.

    A mesma troca de endereço é ruído num alvo de referência e alerta num alvo
    próprio. O dado fica gravado nos dois casos — o que muda é o que é narrado.
    """

    def observacao(classe, ips):
        return {
            "alvo": "x",
            "classe": classe,
            "sondas": [
                {
                    "sonda": "dns",
                    "status": "ok",
                    "a": ips,
                    "aaaa": [],
                    "mx": [],
                    "caa": [],
                    "spf": None,
                    "dmarc": None,
                }
            ],
        }

    antes_ips, agora_ips = ["1.1.1.1"], ["9.9.9.9"]

    referencia = painel.comparar(
        observacao("referencia", antes_ips), observacao("referencia", agora_ips)
    )
    proprio = painel.comparar(observacao("proprio", antes_ips), observacao("proprio", agora_ips))

    assert referencia == []
    assert any("registro A trocou" in m for m in proprio)


def test_perda_de_visibilidade_nao_vira_mudanca_do_alvo():
    """Sonda que parou de concluir diz respeito a nós, não ao alvo.

    Registrar "o alvo parou de enviar HSTS" quando na verdade a coleta deu
    timeout seria inventar um fato sobre um sistema de terceiro.
    """

    def com_status(status, **extra):
        sonda = {"sonda": "cabecalhos", "status": status, **extra}
        if status == "inconclusivo":
            sonda["motivo"] = "TimeoutError: estourou"
        return {"alvo": "x", "classe": "referencia", "sondas": [sonda]}

    antes = com_status(
        "ok",
        cabecalhos={"strict-transport-security": "max-age=31536000"},
        cookies=[],
        hsts=None,
        csp=None,
        csp_meta=None,
    )
    agora = com_status("inconclusivo")

    mudancas = painel.comparar(antes, agora)

    assert any("visibilidade" in m for m in mudancas)
    assert not any("parou de enviar" in m for m in mudancas)


# --------------------------------------------------------------------------
# 9. Regressões achadas pela passagem adversarial de 2026-08-11
# --------------------------------------------------------------------------


@given(
    codigo=st.sampled_from([200, 201, 403, 503]),
    assinatura=st.sampled_from(["cf-mitigated", "x-iinfo"]),
)
def test_bloqueio_com_assinatura_forte_e_pego_em_qualquer_codigo(codigo, assinatura):
    """Nem todo bloqueio vem com código de recusa.

    A Imperva devolve "Request unsuccessful. Incapsula incident ID" com HTTP
    **200**. A primeira versão saía com `return None` antes de olhar qualquer
    cabeçalho quando o código não era 4xx/5xx — e a página do WAF virava nota.
    """
    bloqueio = coleta._bloqueio_de_borda(codigo, {assinatura: ["x"]}, b"")
    assert bloqueio is not None, f"{codigo} + {assinatura} passou batido"


def test_texto_de_pagina_de_bloqueio_e_pego_em_200():
    corpo = b"<html><title>Just a moment...</title>Checking your browser</html>"
    assert coleta._bloqueio_de_borda(200, {"server": ["cloudflare"]}, corpo) is not None

    corpo_imperva = b"Request unsuccessful. Incapsula incident ID: 1234-567"
    assert coleta._bloqueio_de_borda(200, {}, corpo_imperva) is not None


@given(codigo=st.sampled_from([200, 301, 404]))
def test_cdn_saudavel_nao_vira_bloqueio(codigo):
    """O dual: `cf-ray` e `server: cloudflare` aparecem em resposta saudável.

    Tratá-los como bloqueio transformaria metade da web em inconclusivo.
    """
    assert (
        coleta._bloqueio_de_borda(codigo, {"server": ["cloudflare"], "cf-ray": ["8a"]}, b"") is None
    )


def test_hsts_max_age_zero_nao_pontua():
    """`max-age=0` manda o navegador APAGAR a política. É HSTS desligado."""
    lido = coleta._ler_hsts("max-age=0; includeSubDomains")
    assert lido["desligado"] is True

    observacao = {
        "alvo": "x",
        "classe": "proprio",
        "sondas": [
            {
                "sonda": "cabecalhos",
                "status": "ok",
                "cabecalhos": {"strict-transport-security": "max-age=0; includeSubDomains"},
                "cookies": [],
                "hsts": lido,
                "csp": None,
                "csp_meta": None,
            }
        ],
    }
    postura = coleta.nota_de_postura(observacao)

    assert not any("HSTS" in r for r, _ in postura["ganhos"])
    assert any("max-age=0" in r for r, _ in postura["perdas"])
    assert postura["nota"] == 0.0


def test_hsts_sem_max_age_e_invalido_e_nao_curto():
    lido = coleta._ler_hsts("includeSubDomains; preload")
    assert lido["valido"] is False
    assert lido["max_age_segundos"] is None


@given(valor=st.sampled_from(["ALLOWALL", "ALLOW-FROM https://x.test", "", "invalido"]))
def test_x_frame_options_com_valor_ignorado_nao_pontua(valor):
    """`ALLOWALL` existe para PERMITIR enquadramento; `ALLOW-FROM` nenhum
    navegador moderno suporta. Creditar por presença mede a intenção de quem
    configurou, não o efeito no navegador."""
    cabecalhos = {"x-frame-options": valor} if valor else {}
    observacao = {
        "alvo": "x",
        "classe": "proprio",
        "sondas": [
            {
                "sonda": "cabecalhos",
                "status": "ok",
                "cabecalhos": cabecalhos,
                "cookies": [],
                "hsts": None,
                "csp": None,
                "csp_meta": None,
            }
        ],
    }
    postura = coleta.nota_de_postura(observacao)
    assert not any("Enquadramento" in r for r, _ in postura["ganhos"])


@given(valor=st.sampled_from(["DENY", "SAMEORIGIN", "deny", " sameorigin "]))
def test_x_frame_options_valido_pontua(valor):
    observacao = {
        "alvo": "x",
        "classe": "proprio",
        "sondas": [
            {
                "sonda": "cabecalhos",
                "status": "ok",
                "cabecalhos": {"x-frame-options": valor},
                "cookies": [],
                "hsts": None,
                "csp": None,
                "csp_meta": None,
            }
        ],
    }
    postura = coleta.nota_de_postura(observacao)
    assert any("Enquadramento" in r for r, _ in postura["ganhos"])


def test_referrer_policy_permissiva_nao_vale_o_mesmo_que_restritiva():
    def nota(valor):
        return coleta.nota_de_postura(
            {
                "alvo": "x",
                "classe": "proprio",
                "sondas": [
                    {
                        "sonda": "cabecalhos",
                        "status": "ok",
                        "cabecalhos": {"referrer-policy": valor},
                        "cookies": [],
                        "hsts": None,
                        "csp": None,
                        "csp_meta": None,
                    }
                ],
            }
        )["nota"]

    assert nota("no-referrer") > nota("unsafe-url")
    assert nota("strict-origin-when-cross-origin") > nota("no-referrer-when-downgrade")


def test_csp_repetida_nao_e_concatenada_com_separador_inventado():
    """O navegador aplica todas as políticas; ele não as cola com ' | '.

    Concatenar gruda a última diretiva de uma na primeira da outra e produz uma
    política que não existe em lugar nenhum.
    """
    lida = coleta._ler_csp_multipla(
        ["default-src 'self'", "frame-ancestors 'none'; script-src 'unsafe-inline'"]
    )
    assert lida["n_politicas"] == 2
    assert lida["tem_default_src"] is True
    assert lida["tem_frame_ancestors"] is True
    assert lida["usa_unsafe_inline"] is True


def test_linha_da_tabela_tem_sempre_o_mesmo_numero_de_colunas():
    """O ramo de fallback punha o motivo na 9ª célula — a de `security.txt` —
    e o README publicado dizia "security.txt: barrado na borda" quando o que
    fora barrado era a raiz."""

    def observacao(status):
        sondas = [{"sonda": "cabecalhos", "status": status}]
        if status == "ok":
            sondas[0].update(
                {"cabecalhos": {}, "cookies": [], "hsts": None, "csp": None, "csp_meta": None}
            )
        else:
            sondas[0]["motivo"] = "resposta veio de uma borda de proteção: HTTP 403"
        obs = {"alvo": "x", "classe": "referencia", "sondas": sondas}
        obs["postura"] = coleta.nota_de_postura(obs)
        return obs

    com = painel.linha_da_tabela(observacao("ok"))
    sem = painel.linha_da_tabela(observacao("inconclusivo"))

    assert com.count("|") == sem.count("|")
    # o motivo explica a nota, então mora na coluna da nota (3ª célula)
    assert sem.split("|")[3].strip() == "barrado na borda"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
