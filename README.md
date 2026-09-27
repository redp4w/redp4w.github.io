# redp4w // security notes

Publicações em https://redp4w.github.io — repositório da página e dos artigos.
O [perfil do GitHub](https://github.com/redp4w) funciona como capa; o site concentra o conteúdo.

## Publicar um artigo

Coloque **todos** os artigos em `_posts/`, independentemente do assunto. Não crie pastas
separadas por tipo. Use um arquivo com nome `AAAA-MM-DD-titulo-curto.md` e este cabeçalho:

```yaml
---
layout: post
title: "TryHackMe — Nome da sala | Técnica estudada"
description: "Resumo curto para o card da página inicial e do arquivo."
date: 2026-09-27
categories: [TryHackMe, Linux]  # metadados; não criam pastas
# O filtro do site é gerado automaticamente a partir das tags de todos os artigos.
tags: [Walkthrough, Linux, Privilege-Escalation]
---

# Título visível do artigo

Seu conteúdo em Markdown.
```

**Para um estudo:** mude `title`, `categories` e `tags`; mantenha-o em `_posts/`.
A página `arquivo.md` listará todos os posts automaticamente. Os botões de filtro usam as tags.
O link do post permanece em `/notes/titulo-curto/`.

## Onde editar

- `_config.yml`: título, endereço e configuração Jekyll. Usa CSS/layouts locais, sem tema externo.
- `_layouts/home.html`: texto da capa e áreas de interesse.
- `_layouts/archive.html`: arquivo único, pesquisa e filtros automáticos.
- `_layouts/post.html`: moldura de cada publicação.
- `_includes/post-card.html`: aparência dos cards nas duas páginas.
- `assets/css/style.css`: cores e estilos, organizados por seções comentadas.
- `assets/js/archive.js`: busca e filtro (não precisa alterar para adicionar posts).
- `latest.json`: exporta as três publicações mais recentes para o README do perfil.

Mantenha `_posts/2026-09-27-fragnesia.md`, bem como `assets/favicon.svg`.
**Exclua** o antigo `writeups/index.md`; a página agora é `arquivo.md`.
Se tiver criado `walkthroughs/` ou `estudos/` na tentativa anterior, exclua essas duas pastas de índice.
