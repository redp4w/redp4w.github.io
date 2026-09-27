# redp4w // security notes

Portfólio técnico de [Jezer Ferreira](https://github.com/redp4w), publicado em <https://redp4w.github.io>.

O GitHub [redp4w/redp4w](https://github.com/redp4w/redp4w) é a apresentação; este repositório concentra writeups, walkthroughs e estudos. A rota `/latest.json` fornece as três publicações recentes para sincronização automatizada do perfil.

## Publicar uma nota

Crie `_posts/AAAA-MM-DD-titulo.md` com front matter:

```yaml
---
layout: post
title: "Título da análise"
description: "Resumo de uma linha."
date: AAAA-MM-DD
categories: [Estudos, Linux] # ou [TryHackMe, Linux], [HackTheBox, Windows]
tags: [Linux, SOC]
---
```

Use uma introdução, ambiente, passos com evidências, resultado, detecção/mitigação e referências. Não publique flags de salas ativas, credenciais ou dados de terceiros.

## Navegação e manutenção

- `/writeups/`: arquivo completo.
- `/walkthroughs/`: posts nas categorias TryHackMe, HackTheBox ou Walkthroughs.
- `/estudos/`: posts nas categorias Estudos, Research ou Studies.
- `/latest.json`: índice público usado pela rotina do README de perfil.

GitHub Pages publica a branch `main` usando Jekyll. A configuração usa o nome correto `jekyll-theme-hacker` e layouts/CSS próprios. As publicações já existentes em `_posts/` devem ser preservadas.
