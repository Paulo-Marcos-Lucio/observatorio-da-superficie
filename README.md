# Observatório da Superfície

Leitura diária e passiva da superfície pública de um punhado de alvos —
cabeçalhos de segurança, TLS, DNS e Transparência de Certificados —
guardada como série temporal para que a **mudança** fique visível.

Um relatório de segurança tirado num dia só diz como o alvo estava naquele dia.
O que interessa é a deriva: o cabeçalho que sumiu numa migração, o certificado
que passou a ser emitido por outro fornecedor, o subdomínio de homologação que
apareceu num log de Transparência. Isso só aparece medindo todo dia e comparando.

**Última coleta:** 2026-08-24T10:06:40+00:00 · **270 coletas** na série (de hora em hora) · **268 instantâneos** guardados

O quadro abaixo é do instantâneo de `2026-08-24T10:06:40+00:00`, com 30/30 sondas conclusivas. Instantâneo com os
cabeçalhos inteiros só é guardado quando alguma coisa muda — a série
registra todas as horas, mas 23 KB de cabeçalhos idênticos por hora
seriam 193 MB por ano de histórico para dizer que nada aconteceu.

## Postura observada

| Alvo | Classe | Nota | HSTS | CSP | Enquadr. | nosniff | Referrer | security.txt | Cert. |
|---|---|---|---|---|---|---|---|---|---|
| `paulo-marcos-lucio.github.io` | proprio | **3.9** | ✅ | ⚠ meta | — | — | — | ✅ | 68d |
| `owasp.org` | referencia | **7.8** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 42d |
| `www.cloudflare.com` | referencia | **7.6** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 80d |
| `github.com` | referencia | **7.5** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 37d |
| `www.mozilla.org` | referencia | **7.3** | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠ fora da RFC | 87d |
| `web.dev` | referencia | **6.3** | ✅ | ✅ | ✅ | ✅ | — | — | 65d |

`·` significa **inconclusivo**: a sonda não conseguiu medir. Não é o mesmo que
ausente, e este projeto nunca escreve um pelo outro.

`⚠ meta` significa CSP entregue por `<meta http-equiv>` em vez de cabeçalho.
Vale contra XSS, mas o navegador **descarta** `frame-ancestors`, `report-uri` e
`sandbox` nessa forma — quem confia nela para barrar enquadramento não está
barrando nada.

## O que o observatório encontra na própria casa

### `paulo-marcos-lucio.github.io` — nota 3.9

- `+1.5` HSTS com max-age >= 180 dias
- `+1.4` CSP em <meta> (crédito parcial)
- `+1.0` :80 sobe para HTTPS

## Diário de mudanças

Dias em que a superfície observada mudou:

- [2026-08-24](diario/2026-08-24.md)
- [2026-08-23](diario/2026-08-23.md)
- [2026-08-22](diario/2026-08-22.md)
- [2026-08-21](diario/2026-08-21.md)
- [2026-08-20](diario/2026-08-20.md)
- [2026-08-19](diario/2026-08-19.md)
- [2026-08-18](diario/2026-08-18.md)
- [2026-08-17](diario/2026-08-17.md)
- [2026-08-16](diario/2026-08-16.md)
- [2026-08-15](diario/2026-08-15.md)

## Como isto funciona

- `alvos.yml` — a lista, com a justificativa de admissão de cada alvo.
- `coletor/coleta.py` — as sondas. Só biblioteca padrão do Python, para que
  continue rodando daqui a um ano sem manutenção de dependência.
- `dados/serie.jsonl` — série append-only, uma linha por alvo por coleta.
- `dados/AAAA/MM/*.json` — o instantâneo bruto de cada coleta.
- `diario/` — o texto do que mudou, quando mudou.
- [`REGRAS-DE-ENGAJAMENTO.md`](REGRAS-DE-ENGAJAMENTO.md) — o que é coletado, o que
  nunca é coletado, e como pedir a remoção de um alvo.

Nenhum valor de cookie é gravado, em nenhuma hipótese. Nenhuma sonda envia
requisição que altere estado. Nenhum alvo é observado sem política pública que
autorize a observação.

---

<sub>Painel gerado por `coletor/painel.py`. A coleta é automática; a lista de alvos,
as regras e a leitura dos achados são decisão humana.</sub>
