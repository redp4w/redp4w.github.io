---
layout: post
title: "Nmap, Telnet e Hydra — guia prático de redes e pentest"
description: "Guia didático de Nmap, Telnet e THC Hydra: descoberta de portas, SYN e NULL Scan, timing, leitura de banners, testes de autenticação e FTP em dois canais com EPSV, LIST e RETR."
date: 2026-11-14
categories: [tutorial]
tags: [linux, tryhackme, nmap, telnet, hydra, ftp, tcp, port-scanning, enumeration, banner-grabbing, ids, brute-force, wordlist]
---

# Nmap, Telnet e Hydra — guia prático de redes e pentest

Em uma room do **TryHackMe**, o desafio era usar somente três ferramentas: **Nmap, Telnet e Hydra**. Já conhecia o Nmap e o Hydra, mas uma parte foi novidade: usar o **Telnet para conversar diretamente com um servidor FTP**, abrindo dois terminais para executar comandos e receber arquivos.

Este não é um walkthrough com todas as perguntas da room. Organizei os comandos, os conceitos de rede e os erros que encontrei em um guia que posso consultar em outros laboratórios.

> **Escopo:** os exemplos de teste de credenciais e varredura são destinados a laboratórios e sistemas com autorização explícita. Nmap e Hydra geram tráfego que pode ser detectado, bloqueado ou causar bloqueio de contas.

## Índice

1. [Fluxo de trabalho](#fluxo)
2. [Nmap: descobrir hosts, portas e serviços](#nmap)
3. [SYN, NULL, FIN, Xmas e timing](#scans)
4. [Telnet: testar conexões e conversar com serviços](#telnet)
5. [FTP com Telnet: controle e dados](#ftp)
6. [Hydra: testar credenciais com wordlists](#hydra)
7. [Problemas comuns e o que aprendi](#erros)
8. [Cheat sheet](#cheatsheet)
9. [Referências e posts relacionados](#referencias)

<a id="fluxo"></a>

## 1. Fluxo de trabalho

As três ferramentas cumprem papéis diferentes:

| Ferramenta | Principal função | O que responde? |
|---|---|---|
| **Nmap** | Reconhecimento de rede | Quais hosts, portas e serviços estão acessíveis? |
| **Telnet** | Cliente TCP interativo | O que o serviço responde quando envio texto/protocolo? |
| **Hydra** | Teste de credenciais | Algum usuário/senha da lista consegue autenticar? |

~~~text
                  Host autorizado
                        |
                        v
                Nmap: portas abertas
                        |
                +-------+-------+
                |               |
                v               v
          Telnet: banner    Hydra: credenciais
          e protocolo       autorizadas
                |               |
                +-------+-------+
                        |
                        v
             Interpretar as respostas
~~~

Nos comandos, `<target>` representa o IP ou hostname da máquina autorizada. Substitua pelo endereço do seu laboratório, sem os símbolos `<` e `>`.

<a id="nmap"></a>

## 2. Nmap: descobrir hosts, portas e serviços

O [Nmap](https://nmap.org/) (*Network Mapper*) envia sondagens de rede e interpreta as respostas para identificar hosts ativos, portas TCP/UDP, serviços e, em alguns casos, versões e sistema operacional.

### 2.1 Varredura padrão x todas as portas

**Comando básico:**

~~~bash
nmap <target>
~~~

Por padrão, o Nmap examina as **1.000 portas TCP mais comuns**, e não todas as 65.535 portas TCP possíveis.

**Comando que usei na room:**

~~~bash
nmap -sS -T4 -p- --open <target>
~~~

| Parâmetro | Explicação |
|---|---|
| `-sS` | TCP SYN Scan: tenta identificar portas sem completar o handshake TCP |
| `-T4` | Perfil de timing mais rápido, geralmente apropriado para laboratório ou rede estável |
| `-p-` | Examina as portas TCP de 1 a 65535 |
| `--open` | Mostra apenas portas identificadas como abertas ou potencialmente abertas |

O SYN Scan costuma exigir privilégios administrativos para criar pacotes brutos. Não confunda **velocidade** com **discrição**: `-T4` foi útil para concluir a enumeração rapidamente, mas não foi escolhido para evitar IDS.

No laboratório, a varredura completa encontrou **sete portas TCP**:

~~~text
22/tcp     open  ssh
80/tcp     open  http
139/tcp    open  netbios-ssn
445/tcp    open  microsoft-ds
8081/tcp   open  http
10001/tcp  open  unknown
10121/tcp  open  ftp
~~~

As portas `8081` e `10121` eram importantes para o exercício. Uma varredura padrão teria deixado a `10121` de fora.

### 2.2 Identificar serviços e versões

Depois de descobrir as portas, podemos concentrar o reconhecimento nelas:

~~~bash
nmap -sV -sC -p 22,80,139,445,8081,10001,10121 <target>
~~~

- `-sV`: tenta identificar serviço e versão (version detection).
- `-sC`: executa o conjunto padrão de scripts NSE do Nmap.
- `-p`: seleciona as portas informadas, separadas por vírgula.

Foi com `-sV` que identifiquei o servidor FTP da porta não convencional:

~~~text
10121/tcp open ftp vsftpd 3.0.5
~~~

Também encontrei strings de desafio dentro de banners: uma no cabeçalho `Server` do HTTP e outra na identificação enviada pelo SSH. Em um pentest real, banners ajudam a levantar hipóteses sobre a tecnologia, mas **não provam sozinhos a versão instalada ou uma vulnerabilidade**.

### 2.3 Outros comandos úteis

| Objetivo | Comando |
|---|---|
| Descobrir hosts sem varrer portas | `nmap -sn 192.168.1.0/24` |
| Não depender da resposta à descoberta inicial de host | `nmap -Pn <target>` |
| Evitar consultas DNS reversas | `nmap -n <target>` |
| Escanear portas específicas | `nmap -p 22,80,443 <target>` |
| Descobrir versões | `nmap -sV <target>` |
| Usar scripts padrão e versões | `nmap -sC -sV <target>` |
| TCP Connect Scan, sem pacotes SYN brutos | `nmap -sT <target>` |
| Examinar UDP, mais lento e sujeito a ambiguidade | `sudo nmap -sU -p 53,123,161 <target>` |
| Exibir motivos para o estado das portas | `nmap --reason <target>` |
| Salvar saídas normal, XML e grepable | `nmap -oA scan-inicial <target>` |

> **Dica:** `-Pn` não significa que o host está ativo. Ele diz ao Nmap para **pular a fase de descoberta** e tentar escanear o alvo mesmo sem resposta ao ping/sondagens iniciais.

### 2.4 Interpretar o estado de uma porta

| Estado | Significado prático |
|---|---|
| `open` | Algum serviço responde naquela porta |
| `closed` | A porta responde, mas não há serviço aceitando conexões |
| `filtered` | Um filtro ou a falta de respostas impede determinar se está aberta |
| `open\|filtered` | Não é possível diferenciar porta aberta de filtrada |
| `unfiltered` | O Nmap alcança a porta, mas ainda não determina se está aberta |

O estado depende **do tipo de varredura e das respostas recebidas**. `open|filtered` não deve ser tratado como confirmação de porta aberta.

<a id="scans"></a>

## 3. SYN, NULL, FIN, Xmas e timing

Uma das dúvidas da room foi: **um TCP NULL Scan é mais furtivo do que SYN Scan com `-T1`?**

Não existe uma resposta universal. São duas dimensões distintas:

- O tipo de scan altera **quais pacotes TCP são enviados**.
- O timing altera **a cadência e os intervalos de envio**.

### 3.1 Comparando técnicas de TCP Scan

| Técnica | Comando | Comportamento |
|---|---|---|
| **SYN** | `nmap -sS <target>` | Envia SYN e observa SYN/ACK ou RST; normalmente não completa a conexão |
| **Connect** | `nmap -sT <target>` | Usa a conexão TCP do sistema operacional; completa o handshake quando possível |
| **NULL** | `nmap -sN <target>` | Envia segmento TCP com todas as flags desligadas |
| **FIN** | `nmap -sF <target>` | Envia segmento com FIN |
| **Xmas** | `nmap -sX <target>` | Envia FIN, PSH e URG |
| **ACK** | `nmap -sA <target>` | Ajuda a analisar regras de filtragem; não determina diretamente portas abertas |

O **TCP handshake** convencional funciona assim:

~~~text
Cliente                  Servidor
   | ------ SYN --------> |
   | <---- SYN/ACK ------ |
   | ------ ACK --------> |
   |     Conectado        |
~~~

Em um `-sS`, o Nmap não precisa completar essa negociação para classificar uma porta. Já o `-sN` envia um segmento sem flags TCP ativadas.

Em sistemas que seguem o comportamento esperado para essas sondagens, portas fechadas respondem com **RST**; portas abertas podem ficar sem responder. Por isso o resultado costuma ser `open|filtered`: silêncio também pode significar que um firewall descartou o pacote.

**Limitação:** esse mecanismo não funciona igualmente em todos os sistemas operacionais e firewalls; certos equipamentos respondem com RST independentemente de a porta estar aberta.

### 3.2 Timing: de T0 a T5

| Perfil | Nome | Ideia geral |
|---|---|---|
| `-T0` | Paranoid | Extremamente lento |
| `-T1` | Sneaky | Lento; aumenta bastante a duração |
| `-T2` | Polite | Reduz agressividade |
| `-T3` | Normal | Padrão |
| `-T4` | Aggressive | Mais rápido em redes confiáveis |
| `-T5` | Insane | Muito agressivo; pode sacrificar precisão |

No laboratório, experimentei:

~~~bash
nmap -sS -T1 -p- <target>
~~~

Isso **não resolveu o desafio do IDS**. Quando executei:

~~~bash
nmap -sN <target>
~~~

A aplicação entregou a flag. O exercício estava relacionado à **técnica dos pacotes**, e não apenas à velocidade do scan.

> **O que aprendi:** NULL Scan pode atravessar alguns filtros que procuram conexões SYN, mas **não é invisível**. IDS modernos podem reconhecer os padrões NULL/FIN/Xmas e gerar alertas. Reduzir velocidade com `-T1` também não garante ausência de detecção.

<a id="telnet"></a>

## 4. Telnet: testar conexões e conversar com serviços

O [Telnet](https://www.rfc-editor.org/rfc/rfc854) é um protocolo antigo de acesso remoto sem criptografia. O cliente `telnet` também pode ser usado para abrir uma conexão TCP interativa e enviar texto a serviços que aceitam protocolos textuais.

**Testar uma porta:**

~~~bash
telnet <target> 22
~~~

Se a conexão abrir, o SSH poderá apresentar um banner parecido com:

~~~text
Connected to <target>.
SSH-2.0-OpenSSH_8.2p1
~~~

Isso confirma que a conexão TCP foi estabelecida e que houve resposta do serviço. **Não significa que o Telnet consegue autenticar numa sessão SSH**; SSH é outro protocolo.

### 4.1 Fazer uma requisição HTTP manualmente

Na room, encontrei uma aplicação Node.js/Express na porta `8081`. Pelo Telnet, enviei:

~~~bash
telnet <target> 8081
~~~

Em seguida, digitei estas linhas e pressionei **Enter mais uma vez ao final**, para enviar a linha em branco que encerra os cabeçalhos HTTP:

~~~http
GET / HTTP/1.1
Host: <target>
Connection: close

~~~

Resposta observada:

~~~http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
~~~

O HTML retornado apresentava um pequeno desafio sobre detecção de varredura.

Esse é o mesmo princípio das requisições que um navegador faz por nós, só que aqui escrevemos manualmente a mensagem HTTP.

### 4.2 Sair corretamente

Em uma sessão Telnet:

- `Ctrl+]`: abre o prompt local do próprio cliente Telnet.
- `quit`: fecha a sessão a partir desse prompt.

Se o serviço conectado aceitar um comando de encerramento próprio, como `QUIT` no FTP, prefira usá-lo.

> **Atenção:** Telnet não criptografa a comunicação. Em redes reais, credenciais e comandos podem trafegar em texto claro. Para administração remota, prefira SSH; para arquivos, SFTP ou FTPS conforme o ambiente.

<a id="ftp"></a>

## 5. FTP com Telnet: controle e dados

Esta foi a parte mais interessante do exercício. Eu conseguia autenticar no FTP, mas o comando `LIST` falhava:

~~~text
425 Use PORT or PASV first.
~~~

O erro aconteceu porque **FTP trabalha com dois canais de comunicação**, diferentemente da ideia de uma única conexão que normalmente usamos ao testar portas.

### 5.1 Entendendo os dois canais

~~~text
TERMINAL 1                            SERVIDOR FTP
Controle TCP -----------------------> porta 10121
USER / PASS / EPSV / LIST / RETR

TERMINAL 2                            SERVIDOR FTP
Dados TCP --------------------------> porta indicada pelo EPSV
Listagem de arquivos / conteúdo
~~~

| Canal | Responsável por |
|---|---|
| **Controle** | Autenticar, mudar de pasta e enviar comandos como `LIST` e `RETR` |
| **Dados** | Transmitir efetivamente a listagem ou os bytes de um arquivo |

O FTP convencional utiliza a porta `21` para controle, mas o servidor do laboratório escutava na porta **10121**.

### 5.2 Passo a passo: listar arquivos usando apenas Telnet

**Terminal 1 — conectar e autenticar:**

~~~bash
telnet <target> 10121
~~~

Dentro da sessão:

~~~text
USER quinn
331 Please specify the password.
PASS cookie
230 Login successful.
PWD
257 "/" is the current directory
EPSV
229 Entering Extended Passive Mode (|||30607|)
~~~

- `USER`: nome de usuário.
- `PASS`: senha.
- `PWD`: diretório atual.
- `EPSV`: solicita uma porta de dados no servidor (*Extended Passive Mode*).

O número **30607** é a porta temporária escolhida pelo servidor nesse exemplo. **Ela muda entre as operações**.

**Terminal 2 — abrir a conexão de dados:**

~~~bash
telnet <target> 30607
~~~

Deixe esse terminal conectado. **Não envie `USER`, `PASS`, `HELP` nem `LIST` no Terminal 2**. Ele só recebe os dados.

**Volte ao Terminal 1 e execute:**

~~~text
LIST
150 Here comes the directory listing.
226 Directory send OK.
~~~

No **Terminal 2**, apareceu:

~~~text
-rw-rw-r--    1 1002     1002           22 Feb 24  2026 ftp_flag.txt
Connection closed by foreign host.
~~~

As permissões `-rw-rw-r--` indicam um arquivo regular; dono e grupo podem ler/escrever, e outros usuários podem ler. O número `22` no resultado representa o tamanho em bytes. É a listagem do diretório remoto, não um arquivo local do terminal.

### 5.3 Ler o arquivo com RETR

A conexão de dados usada no `LIST` foi encerrada. Para recuperar um arquivo, pedimos **outra porta**.

**Terminal 1:**

~~~text
EPSV
229 Entering Extended Passive Mode (|||30254|)
~~~

**Terminal 2:** abrir nova conexão, agora na porta `30254`:

~~~bash
telnet <target> 30254
~~~

**Terminal 1:**

~~~text
RETR ftp_flag.txt
150 Opening BINARY mode data connection for ftp_flag.txt (22 bytes).
226 Transfer complete.
~~~

**Terminal 2:** recebe o conteúdo do arquivo:

~~~text
THM{QUINN_IS_BACK007}
Connection closed by foreign host.
~~~

O comando `RETR` solicita a transferência do arquivo; quem transporta os 22 bytes é a **conexão de dados**.

> **Importante:** esse procedimento com Telnet é útil para aprender o protocolo e visualizar arquivos de texto. Telnet não é uma ferramenta adequada para baixar arquivos binários arbitrários, porque seu comportamento como terminal pode interferir na representação dos bytes. Em uso normal, um cliente FTP lida automaticamente com os dois canais.

### 5.4 EPSV x PASV

O servidor também respondia ao comando `PASV`:

~~~text
227 Entering Passive Mode (10,67,180,197,119,243).
~~~

Aqui a resposta contém **IP + dois números que representam a porta**. O cálculo é:

~~~text
porta = p1 × 256 + p2
porta = 119 × 256 + 243
porta = 30707
~~~

Já `EPSV` responde apenas com a porta, por exemplo `(|||30254|)`, e usa o mesmo endereço da conexão de controle.

| Comando | Exemplo de resposta | Como interpretar |
|---|---|---|
| `PASV` | `227 (...,119,243)` | IP informado e porta `119 × 256 + 243` |
| `EPSV` | `229 (|||30254|)` | Mesma máquina; conectar na porta `30254` |

No **modo passivo**, o servidor abre uma porta de dados e o cliente inicia a conexão para ela. No **modo ativo**, o cliente informa ao servidor onde deve receber a conexão de dados. Passivo costuma simplificar o cenário com NAT e firewalls do lado do cliente.

### 5.5 Códigos de resposta FTP comuns

| Código | Significado |
|---|---|
| `220` | Serviço pronto |
| `331` | Usuário aceito; falta senha |
| `230` | Login bem-sucedido |
| `227` | Porta de dados informada por PASV |
| `229` | Porta de dados informada por EPSV |
| `150` | Transferência ou listagem iniciando |
| `226` | Transferência concluída |
| `425` | Não foi possível estabelecer a conexão de dados |
| `421` | Serviço encerrou a conexão, por exemplo por timeout |
| `530` | Não autenticado / login falhou |

**Resumo mental:** `EPSV` prepara o canal de dados, o segundo Telnet se conecta a ele, e `LIST` ou `RETR` no primeiro terminal **dispara a transferência**.

<a id="hydra"></a>

## 6. Hydra: testar credenciais com wordlists

O [THC Hydra](https://github.com/vanhauser-thc/thc-hydra) automatiza tentativas de autenticação em protocolos suportados, como FTP e SSH, usando combinações de usuários e senhas fornecidas pelo operador.

Ele não é um scanner de portas, nem faz *cracking* offline de hashes como John ou Hashcat. O Hydra envia **tentativas de login ao serviço**, por isso pode gerar logs, alertas e bloqueio de contas.

### 6.1 Um usuário e uma wordlist

**Comando usado na room:**

~~~bash
hydra -l quinn -P rockyou.txt -s 10121 -t 4 -f <target> ftp
~~~

| Opção | Explicação |
|---|---|
| `-l quinn` | Um usuário fixo |
| `-P rockyou.txt` | Arquivo com candidatas a senha |
| `-s 10121` | Porta não padrão do serviço |
| `-t 4` | Quatro tarefas de autenticação simultâneas |
| `-f` | Para depois do primeiro usuário/senha válido encontrado no host |
| `<target> ftp` | Endereço do serviço e módulo/protocolo FTP |

O resultado encontrado no laboratório foi:

~~~text
[10121][ftp] host: <target> login: quinn password: cookie
~~~

Também testei `eddie`, que autenticou com a senha `softball`. A atividade funcionou porque ambos tinham senhas fracas presentes na wordlist utilizada.

### 6.2 Dois ou mais usuários no mesmo comando

Uma opção melhor do que repetir o comando manualmente para cada usuário é criar uma pequena lista:

~~~bash
printf 'eddie\nquinn\n' > users.txt
~~~

Depois:

~~~bash
hydra -L users.txt -P rockyou.txt -s 10121 -t 4 <target> ftp
~~~

- `-l` (minúsculo): usuário literal.
- `-L` (maiúsculo): **arquivo com usuários**.
- `-p` (minúsculo): uma senha literal.
- `-P` (maiúsculo): **arquivo com senhas**.

Para buscar **as duas credenciais**, não use `-f`, pois ele pode interromper o teste após a primeira combinação válida.

**Correção importante sobre `-f` e `-F`:**

| Opção | Comportamento |
|---|---|
| `-f` | Para após encontrar um par válido no host (ou por host, ao usar `-M`) |
| `-F` | Para após encontrar um par válido entre todos os hosts, quando usamos `-M` |
| Sem ambas | Continua tentando as combinações previstas |

`-F` **não** quer dizer “encontrar uma senha para cada usuário”. Essa é uma distinção fácil de confundir.

### 6.3 Outras opções úteis

| Opção | Para que serve |
|---|---|
| `-C pares.txt` | Lê pares no formato `usuario:senha` |
| `-e ns` | Testa senha vazia (`n`) e senha igual ao login (`s`) |
| `-o resultado.txt` | Salva credenciais encontradas |
| `-v` | Exibe informações adicionais |
| `-V` | Mostra cada tentativa de login/senha |
| `-W 2` | Intervalo entre conexões realizadas por cada tarefa (segundos) |
| `-M hosts.txt` | Usa uma lista de hosts |
| `-U ftp` | Exibe opções específicas do módulo FTP |
| `-h` | Mostra a ajuda do Hydra |

**Exemplo de teste de autenticação SSH em laboratório:**

~~~bash
hydra -l aluno -P senhas-lab.txt -t 2 <target> ssh
~~~

Nesse caso, substituí o módulo `ftp` por `ssh` e limitei a concorrência a duas tarefas. A sintaxe do Hydra muda conforme o módulo; para formulários HTTP, consulte a ajuda do módulo correspondente, pois a requisição e a condição de falha precisam ser especificadas corretamente.

### 6.4 Wordlists enormes e estimativas de duração

Minha `rockyou.txt` tinha mais de **14 milhões de entradas**. O Hydra mostrou uma estimativa de milhares de horas, mas encontrou a senha nos primeiros minutos.

Isso acontece porque a previsão considera a quantidade total de combinações e a taxa observada naquele instante. Ela **não sabe em qual posição a senha correta aparecerá**.

Para testes autorizados, listas pequenas e contextualizadas costumam ser mais eficientes, geram menos tráfego e reduzem o risco de bloqueio. Escrevi mais sobre isso no [guia de criação de wordlists](/notes/criando-wordlists/).

<a id="erros"></a>

## 7. Problemas comuns e o que aprendi

| Situação | Causa provável | Como interpretar ou corrigir |
|---|---|---|
| Nmap padrão não encontrou a porta FTP | Porta fora do conjunto de 1.000 portas mais comuns | Examinar `-p-` ou uma faixa definida |
| `-sN` retornou `open\|filtered` | Falta de resposta conclusiva | Não presumir porta aberta |
| `-sS -T1` não passou no desafio IDS | A regra não dependia somente da velocidade | Entender a técnica do scan e o padrão detectado |
| Telnet conectou, mas não respondeu a comandos HTTP | Falta de mensagem HTTP correta ou linha em branco | Enviar método, caminho, versão, cabeçalhos e linha vazia |
| FTP respondeu `425` ao `LIST` | Canal de dados ainda não preparado | Fazer `EPSV`, conectar o segundo terminal e só então `LIST` |
| Enviei `USER` no Telnet de dados e nada aconteceu | Porta de dados não é canal de comandos | Enviar `USER` e `PASS` somente no canal de controle |
| `RETR` falhou após `LIST` | A conexão de dados anterior foi consumida/encerrada | Repetir `EPSV` e abrir nova conexão |
| Hydra parou após encontrar um usuário | `-f` estava ativado | Remover `-f` se precisar testar outros usuários |
| Hydra parece demorar demais | Lista muito grande, latência ou limitação do servidor | Usar listas adequadas ao escopo e ajustar taxa com cuidado |

### Conclusões práticas

1. **Descoberta não é enumeração completa:** uma porta pode estar fora das 1.000 mais comuns.
2. **Timing e técnica de varredura são coisas diferentes:** um scan lento não é automaticamente invisível.
3. **FTP é mais fácil de entender quando observamos seus dois canais:** o Telnet tornou esse detalhe explícito.
4. **Força bruta online depende do serviço:** cada tentativa é uma autenticação real, com riscos de detecção e bloqueio.
5. **Banners são pistas:** precisam ser interpretados e, quando necessário, confirmados por outras evidências.

<a id="cheatsheet"></a>

## 8. Cheat sheet

### Nmap

~~~bash
# Portas padrão
nmap <target>

# Todas as portas TCP abertas
sudo nmap -sS -T4 -p- --open <target>

# Versões e scripts padrão apenas nas portas de interesse
nmap -sV -sC -p 22,80,8081,10121 <target>

# Teste de TCP NULL Scan em laboratório
sudo nmap -sN <target>

# Descoberta de hosts
nmap -sn 192.168.1.0/24

# Salvar resultados
nmap -oA scan-inicial <target>
~~~

### Telnet

~~~bash
# Testar uma porta TCP
telnet <target> 22

# Fazer uma requisição HTTP manual
telnet <target> 8081

# FTP: controle em uma porta não padrão
telnet <target> 10121

# FTP: dados na porta devolvida por EPSV
telnet <target> <porta-dados>
~~~

### Hydra

~~~bash
# Uma conta, várias senhas
hydra -l usuario -P senhas.txt -s 10121 -t 4 -f <target> ftp

# Várias contas, várias senhas
hydra -L users.txt -P senhas.txt -s 10121 -t 4 <target> ftp

# Uma conta de laboratório no SSH
hydra -l aluno -P senhas-lab.txt -t 2 <target> ssh

# Ajuda e opções do módulo
hydra -h
hydra -U ftp
~~~

<a id="referencias"></a>

## 9. Referências e posts relacionados

**Documentação:**

- [Nmap — documentação oficial](https://nmap.org/book/man.html)
- [Nmap — TCP NULL, FIN e Xmas Scan](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html)
- [THC Hydra — repositório oficial](https://github.com/vanhauser-thc/thc-hydra)
- [Hydra — manual de opções](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra.1)
- [RFC 2428 — EPSV e extensões do FTP](https://datatracker.ietf.org/doc/html/rfc2428.html)

**Outros estudos do blog:**

- [O básico de custom wordlists](/notes/criando-wordlists/) — construindo listas mais úteis para os testes.
- [Jump: reconhecimento, FTP e privilege escalation](/notes/jump-recon-ftp-privesc/) — aplicação do reconhecimento em outra room.
- [Silent Monitor: SQLi, Command Injection e KeePass](/notes/silent-monitor-sqli-command-injection-keepass-root/) — enumeração inicial com Nmap e exploração web.
- [Operation Coldstart: FTP anônimo, SSRF e Tar Wildcard Injection](/notes/operation-coldstart-ssrf-tar-wildcard-cron-root/) — outro exemplo de FTP, agora expondo um backup.

O principal aprendizado foi sair da execução automática dos comandos e enxergar **o protocolo que existe por trás deles**. Quando um cliente FTP lista arquivos sem que eu perceba, ele está cuidando dos canais de controle e dados. Com dois terminais Telnet, pude acompanhar esse processo manualmente.
