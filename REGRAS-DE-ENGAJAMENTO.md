# Regras de engajamento do Observatório

Este repositório observa a superfície pública de alvos declarados em
[`alvos.yml`](alvos.yml). Observação é uma atividade que mexe com sistemas de
terceiros, então ela precisa de limite escrito — não de bom senso presumido.
O que segue é o limite.

## O que é coletado

Por alvo, uma vez por hora:

| Sonda | O que faz | Natureza |
|---|---|---|
| `porta80` | um `GET http://alvo/`, sem seguir o redirecionamento | 1 requisição |
| `cabecalhos` | um `GET https://alvo/` e a leitura dos cabeçalhos de resposta | 1 requisição |
| `tls` | um handshake TLS para ler o certificado apresentado | 1 conexão |
| `security_txt` | um `GET https://alvo/.well-known/security.txt` | 1 requisição |
| `dns` | consulta DNS por DoH ao resolvedor da Cloudflare | não toca no alvo |
| `transparencia_certificados` | consulta ao crt.sh | não toca no alvo |

O `transparencia_certificados` é a exceção: ele não roda de hora em hora. O
crt.sh é serviço comunitário gratuito e certificado novo não aparece a cada
hora, então essa sonda sai uma vez por dia, na coleta das 03h UTC.

Total: **quatro requisições HTTP por alvo por coleta, uma coleta por hora — teto
de 96 requisições diárias por alvo.** Na prática sai menos, porque o agendador
do GitHub Actions atrasa e às vezes pula: nas primeiras 91 horas de operação
saíram 74 coletas, 80% da agenda, o que dá uma média de 78 requisições por dia
por alvo. Um serviço de monitoramento comum bate a cada cinco minutos, o que dá
288 por dia — e um navegador carregando a página inicial uma única vez dispara
mais requisições do que uma coleta inteira.

A resolução de uma hora existe porque é ela que distingue "o cabeçalho sumiu" de
"o cabeçalho sumiu e voltou". Uma amostra a cada doze horas passa por cima de
uma janela de manutenção inteira — e o deploy revertido às pressas é o evento
mais informativo que este observatório pode registrar.

## O que nunca é coletado

- **Valor de cookie.** Só o nome e as flags (`Secure`, `HttpOnly`, `SameSite`).
  Valor de cookie de sessão é credencial, este repositório é público, e o
  histórico do Git é para sempre. Não existe motivo bom o bastante.
- **Conteúdo de página** além dos primeiros 64 KB usados para achar a CSP em
  `<meta>` — e esse trecho não é gravado, só analisado.
- **Dado pessoal**, de qualquer natureza.
- **Nada autenticado.** O observatório não tem credencial de nenhum alvo e
  nunca tenta obter uma.

## O que nunca é feito

- Nenhuma requisição que **altere estado**: só `GET`. Sem `POST`, sem `PUT`,
  sem `DELETE`.
- Nenhuma **enumeração**: o observatório não varre diretório, não testa
  caminho adivinhado, não tenta subdomínio. Ele lê a raiz e o
  `security.txt`, que é um caminho padronizado (RFC 9116) cuja razão de
  existir é ser lido.
- Nenhum **teste de vulnerabilidade**: não há injeção, não há força bruta, não
  há fuzzing. Isto é um observatório, não um scanner.
- Nenhuma tentativa de **contornar bloqueio**: sem rotação de agente, sem troca
  de IP, sem burlar limite de taxa. O agente se identifica pelo nome, aponta
  para este repositório e declara a frequência.

## Quem entra na lista

Um alvo só é admitido em uma destas duas classes:

**`proprio`** — propriedade do operador do observatório.

**`referencia`** — organização que publica programa de bug bounty ou política
de divulgação de vulnerabilidade. Cada entrada em `alvos.yml` carrega o campo
`justificativa` com o endereço dessa política. Alvo sem justificativa
verificável não entra, por mais interessante que fosse.

Alvos de referência existem para dar um eixo de comparação: uma nota isolada
não diz nada, mas uma nota ao lado da de organizações que levam o assunto a
sério diz bastante.

## Como pedir a saída da lista

Abra uma issue neste repositório, ou escreva para **contatopml26@gmail.com**.
Não é preciso justificar e não haverá discussão: o alvo sai da lista e os dados
históricos dele são removidos do repositório na mesma semana.

## Sobre a nota

A nota de 0 a 10 mede **postura de cabeçalho observável de fora**. Ela não é
uma avaliação de segurança da organização, e é importante que isso fique dito
sem meias palavras:

- Um alvo com nota 10 pode ter uma falha grave de lógica de negócio.
- Um alvo com nota baixa pode estar atrás de um WAF que resolve na borda o que
  o cabeçalho resolveria na resposta.
- Hospedagem estática (GitHub Pages, por exemplo) **não permite** configurar
  cabeçalho de resposta. Um site hospedado assim recebe nota baixa por uma
  limitação da hospedagem, não por descuido de quem o mantém — o próprio site
  do operador deste observatório está nessa situação, e a nota dele reflete isso.

A nota serve para tornar visível a **deriva ao longo do tempo** de um mesmo
alvo. Comparar alvos diferentes pela nota é usar o instrumento fora do que ele
mede.

## Inconclusivo não é ausência

Quando uma sonda falha — timeout, DNS que não resolve, crt.sh fora do ar — o
registro fica com `status: "inconclusivo"` e o motivo. Nunca é gravado
"ausente".

Não medir e medir-e-não-achar são fatos diferentes. Confundir os dois é o erro
que transforma relatório de segurança em ficção, e é o erro que este projeto
existe, entre outras coisas, para não cometer.
