---
layout: post
title: "AD Lateral Movement - PsExec, WinRM, Pass-the-Hash e Pivoting"
description: "Walkthrough de laboratório TryHackMe: enumeração, administração remota Windows, reutilização de credenciais e túneis SSH, com conceitos e detecção."
date: 2026-10-21
categories: [walkthrough, pentest, windows, tryhackme]
tags: [active-directory, lateral-movement, psexec, impacket, netexec, smb, winrm, pass-the-hash, ntlm, ssh, pivoting, proxychains, windows-laps, detection]
---

# AD Lateral Movement — PsExec, WinRM, Pass-the-Hash e Pivoting

Neste exercício autorizado do **TryHackMe**, estudei como credenciais encontradas em um host podem abrir caminho para outros computadores do Active Directory. O objetivo é entender **qual máquina estou acessando, quais permissões tenho e por que o próximo salto funciona**.

**Antes deste guia:** [Active Directory — enumeração e autenticação](/notes/ad-authenticated-enumeration/).

## 1. Mapa do laboratório

| Host | IP | Função |
|---|---|---|
| WebServer | `192.168.13.71` | Linux comprometido; SSH e Gitea; intermediário de rede |
| WRK / WRK1 | `192.168.13.61` | Estação Windows; jdoe possui administração local |
| SERVER1 | `192.168.13.51` | Servidor Windows; jdoe pode usar WinRM, mas não tem administração local |
| ROOTDC | `192.168.13.100` | Domain Controller do domínio `thm.loc` |

Fluxo estudado:

~~~text
AttackBox --SSH--> WebServer
                   |--> WRK: acesso administrativo por PsExec -> SYSTEM
                   |--> SERVER1: WinRM limitado -> acesso administrativo com credencial reutilizada
                   +--> DC: caminho de rede via túnel SSH/ProxyChains
~~~

**Cuidado com o /etc/hosts:** minhas primeiras anotações diziam `192.168.12.100` e `192.168.12.71`, mas o diagrama e os testes desta instância usam **192.168.13.x**. É preciso conferir as entradas e evitar linhas conflitantes.

~~~bash
getent hosts thm.loc git.thm.loc
cat /etc/hosts
~~~

## 2. Enumerar os hosts e serviços

~~~bash
fping -agq 192.168.13.0/24 2>/dev/null > hosts.txt
cat hosts.txt
nmap -p 88,135,139,389,445 -sV -sC -iL hosts.txt
~~~

| Parâmetro | Explicação |
|---|---|
| `-a -g -q` no fping | Mostra ativos, percorre a faixa e reduz mensagens |
| `2>/dev/null` | Descarta erros |
| `> hosts.txt` | Salva a saída, sobrescrevendo arquivo anterior |
| `-p` | Define portas |
| `-sV` | Identifica serviços |
| `-sC` | Usa scripts Nmap padrão |
| `-iL` | Lê os alvos do arquivo |

**Resultado que observei:** a porta SMB **445 estava aberta** na WRK e no SERVER1. No DC, as portas testadas apareciam como `filtered` a partir da AttackBox. Isso não prova que os serviços estejam fechados: pode haver filtragem de rede. Dois outros IPs responderam, `.1` e `.250`; o `.250` mostrava Samba/WORKGROUP, sem identificação como membro do AD da room.

## 3. SSH e identidade

A entrada inicial foi uma sessão SSH no WebServer, usando a credencial de laboratório fornecida pela room.

~~~bash
ssh jdoe@192.168.13.71
whoami
id
~~~

O resultado foi `jdoe`, UID 1001, no Linux. **Permissões Linux não se transferem automaticamente para Windows.** Uma conta pode ter direitos diferentes em cada host.

## 4. PsExec: por que uma conta administrativa abre shell SYSTEM?

O PsExec do **Impacket** usa **SMB (445)** para autenticar, um compartilhamento administrativo (como `ADMIN$`) para enviar o binário temporário e o **Service Control Manager** para instalar/iniciar um serviço remoto.

No exercício, o NetExec validou as permissões de `jdoe` na WRK:

~~~bash
nxc smb 192.168.13.61 -u jdoe -p '<SENHA_DA_ROOM>' -d thm.loc
~~~

- `-u`: usuário; `-p`: senha; `-d`: domínio.
- `[+]`: autenticação aceita; `(Pwn3d!)`: o NetExec detectou acesso administrativo compatível com suas verificações.

A execução posterior do PsExec mostrou `Found writable share ADMIN$`, upload de executável, criação e início de serviço. Na shell Windows:

~~~cmd
whoami
whoami /priv
~~~

Resultado que confirmei: **`nt authority\system`**. A razão não é que `jdoe` tenha se tornado SYSTEM: ele possuía autorização para **criar um serviço**, e o serviço rodou como **LocalSystem**.

**Flag registrada:** `THM{ps3x3c_syst3m_sh3ll}`.

## 5. Encontrar e interpretar credenciais

Na WRK, foi examinado o arquivo `C:\Users\Administrator\Documents\loot.txt`, com a estrutura:

~~~text
Administrator:500:LM_HASH:NT_HASH:::
~~~

| Campo | Significado |
|---|---|
| `Administrator` | Conta de administrador **local** |
| `500` | RID da conta Administrator integrada |
| `LM_HASH` | Campo reservado ao formato de hash LM |
| `NT_HASH` | Representação NTLM usada na autenticação NTLM |

**Lição:** anotar sempre o **escopo da conta**. `Administrator` local de uma máquina não é a mesma identidade que `THM\Administrator` do domínio. Não publique hashes ou senhas reais de produção em relatórios abertos.

## 6. WinRM: shell remota não é sinônimo de administrador

A conta `jdoe` fazia parte de **Remote Management Users** no SERVER1. O acesso estudado foi por **Evil-WinRM**, no protocolo de gerenciamento remoto do Windows, normalmente nas portas TCP 5985 ou 5986.

A existência de uma sessão WinRM confirma **permissão de login remoto**, não permissão para instalar serviços ou acessar diretórios de administrador.

**Flag registrada:** `THM{w1nrm_r3m0t3_sh3ll}`.

## 7. Pass-the-Hash e reutilização de credenciais

**Pass-the-Hash (PtH)** autentica por NTLM usando o NT hash, sem recuperar a senha original em texto claro. Não é a mesma coisa que quebrar um hash offline.

Na room, o hash de um administrador **local** encontrado na WRK foi aproveitado contra o SERVER1, onde a conta tinha uma credencial equivalente. Assim, foi possível executar comandos com privilégios mais altos naquele servidor.

### Parâmetros vistos na prática

| Sintaxe | Significado |
|---|---|
| `nxc smb` | Verificação de acesso SMB |
| `-H` | Fornece NT hash em vez de senha |
| `--local-auth` | Autentica contra contas locais do host |
| `psexec.py -hashes LM:NT` | Aceita os campos LM e NT na autenticação |
| `DOMINIO/usuario@host` | Identifica a conta de domínio e o alvo |

No SERVER1, foi possível ler `C:\Users\Administrator\Desktop\flag4.txt`. **Flag registrada:** `THM{p4ss_th3_h4sh_ftw}`.

Também foi encontrado `da_creds.txt`, cujo conteúdo apontava uma credencial da conta `THM\Administrator` (domínio), **diferente** do administrador local utilizado antes. O laboratório evidencia por que não se deve reutilizar senhas administrativas entre máquinas ou expor credenciais de domínio em servidores comuns.

## 8. Pivoting: quando há credencial, mas não há caminho de rede

A conexão SMB direta da AttackBox ao DC expirava, assim como a tentativa HTTP direta ao Gitea interno. O **WebServer** aceitava SSH e podia funcionar como intermediário (*pivot*).

**Local port forwarding** (`ssh -L`): associa **uma porta local** a um serviço remoto específico. No exemplo da room, a porta local 13389 representava o serviço RDP 3389 do DC, através do WebServer.

**Dynamic port forwarding** (`ssh -D`): cria um proxy SOCKS local (ex.: porta 1080). Com o **ProxyChains**, ferramentas TCP podem usar o túnel para alcançar serviços internos. Ao contrário de `-L`, não é necessário definir previamente cada destino.

| Opção | Papel |
|---|---|
| `ssh -L` | Encaminhamento local de porta |
| `ssh -D` | Proxy SOCKS dinâmico |
| `ssh -N` | Mantém o túnel sem executar comando remoto |
| `ssh -f` | Passa o SSH ao segundo plano |
| `proxychains` | Encaminha conexões TCP compatíveis via proxy |
| `proxy_dns` | Tenta fazer resolução DNS através do proxy |

**Nmap via SOCKS:** use **`-sT`** (TCP Connect) com **`-Pn`** (sem depender de descoberta por ping). `-sS` precisa enviar pacotes SYN brutos, que não passam pelo SOCKS do ProxyChains tradicional. Também não conte com ping ICMP nem UDP por esse método.

**Estado do exercício:** minha última anotação incluiu a tentativa de conexão ao DC através de ProxyChains, mas **não** a saída confirmando a autenticação nem uma leitura real de `flag5.txt`. Portanto, não publico a flag ilustrativa do enunciado como resultado obtido.

### Outras ferramentas citadas pela room

- **Chisel**: túneis TCP sobre HTTP, úteis quando SSH não está disponível.
- **Ligolo-ng**: túnel com interface TUN, que permite usar ferramentas sem envolvê-las individualmente com ProxyChains.

São alternativas de estudo, não ferramentas que eu tenha confirmado ter executado nesta room.

## 9. Mitigação e detecção

| Controle | O que evita/reduz |
|---|---|
| **Windows LAPS** | Senhas locais exclusivas e rotativas; dificulta reutilização do NT hash entre hosts |
| Princípio do menor privilégio | Evita administrar outras máquinas com contas comuns |
| Restrições a NTLM | Reduz oportunidades de PtH; deve-se auditar compatibilidade |
| Firewall/segmentação | Restringe SMB, WinRM e RDP entre máquinas sem necessidade |
| PAW | Isola operações e credenciais de administração de domínio |
| Credential Guard | Protege segredos do LSASS em cenários suportados |
| SMB signing | Protege integridade SMB e combate relay; **não bloqueia, sozinho, PtH válido** |

**Eventos Windows de interesse:**

| ID | Log | Significado |
|---|---|---|
| `4624` Type 3 | Security | Logon de rede |
| `4624` Type 10 | Security | Logon remoto interativo (RDP) |
| `4648` | Security | Credenciais explícitas |
| **`7045`** | **System** | Novo serviço instalado; importante ao investigar PsExec |
| `4688` | Security | Criação de processo, conforme auditoria habilitada |
| `4698` | Security | Criação de tarefa agendada |
| Sysmon `1` | Sysmon/Operational | Criação de processo |
| Sysmon `10` | Sysmon/Operational | Acesso a outro processo, inclusive LSASS |

Comando de consulta no PowerShell:

~~~powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select-Object TimeCreated, Id, Message
~~~

`TimeCreated` aparece primeiro. Um serviço novo pode ser legítimo; correlacione conta, origem, nome do serviço e processo.

## 10. Checklist geral

| Etapa | Conferir |
|---|---|
| Recon | IPs alcançáveis, portas abertas e portas filtradas |
| Identidade | Quem sou e em **qual host** estou executando? |
| Privilégios | Login remoto, administrador local ou Domain Admin? |
| Acesso | SMB, WinRM, SSH ou RDP; requisitos de cada protocolo |
| Credenciais | Qual conta, qual máquina e escopo **local x domínio** |
| Movimento | Há autenticação válida **e** caminho de rede? |
| Pivoting | Qual host intermediário enxerga o destino? |
| Comprovação | `hostname`, `whoami`, saída efetiva e flag |
| Defesa | Serviços, logons remotos, tarefas, contas privilegiadas |

**Aprendizado:** obter SYSTEM em uma workstation não equivale a comprometer o domínio. Cada salto depende de **permissão no alvo e conectividade**. E um timeout por filtragem não prova que a credencial esteja incorreta.

---

## 11. Outros posts e referências

**Meus posts relacionados:**

- [Active Directory — enumeração, password spraying e AS-REP Roasting](/notes/ad-authenticated-enumeration/)
- [Windows Jump — Guest ao SYSTEM](/notes/windows-jump/)
- [Windows Privilege Escalation — tokens e Pass-the-Hash](/notes/windows-privilege-escalation/)

**Referências:**

- [TryHackMe](https://tryhackme.com/)
- [TryHackMe — Detecting AD Lateral Movement (room de detecção complementar)](https://tryhackme.com/room/detectingadlateralmovement)
- [Impacket — PsExec](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
- [NetExec](https://www.netexec.wiki/)
- [MITRE ATT&CK — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK — Pass-the-Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Microsoft Learn — Windows LAPS](https://learn.microsoft.com/pt-br/windows-server/identity/laps/laps-overview)
