---
layout: default
title: "Glossário técnico"
description: "Dicionário de redes, Active Directory, pentest, Windows, Linux e SOC usado automaticamente nos walkthroughs do redp4w."
permalink: /glossario/
---

<section class="glossary-page" aria-labelledby="glossary-title">
  <div class="glossary-header">
    <span class="section-number">REFERENCE / KNOWLEDGE BASE</span>
    <h1 id="glossary-title">Glossário técnico</h1>
    <p>Definições rápidas dos termos que aparecem nos meus estudos. O mesmo dicionário alimenta os popups dos walkthroughs: adiciono um conceito aqui e ele passa a funcionar também nos posts antigos.</p>
    <p class="glossary-hint">Nos artigos, passe o mouse, use <kbd>Tab</kbd> ou toque na palavra sublinhada para ver sua definição.</p>
  </div>

  <div class="glossary-filter">
    <label for="glossary-search">Buscar termo, sigla ou definição</label>
    <input id="glossary-search" type="search" placeholder="Ex.: RootDSE, Kerberos, SMB Signing, SIEM..." autocomplete="off">
    <p id="glossary-count" role="status" aria-live="polite">{{ site.data.glossary.size }} termo(s)</p>
  </div>

  {% assign ordered = site.data.glossary | sort: 'termo' %}
  <ol class="glossary-list" id="glossary-list">
    {% for entry in ordered %}
    <li class="glossary-entry" data-glossary-search="{{ entry.termo | downcase | escape }} {{ entry.aliases | join: ' ' | downcase | escape }} {{ entry.descricao | downcase | escape }}">
      <div class="glossary-entry-heading">
        <h2>{{ entry.termo | escape }}</h2>
        <span>{{ entry.categoria | escape }}</span>
      </div>
      <p>{{ entry.descricao | escape }}</p>
      {% if entry.aliases and entry.aliases.size > 0 %}
      <small>Também: {{ entry.aliases | join: ', ' | escape }}</small>
      {% endif %}
      {% if entry.link %}<a href="{{ entry.link | escape }}" target="_blank" rel="noopener noreferrer">Referência ↗</a>{% endif %}
    </li>
    {% endfor %}
  </ol>

  <section class="glossary-sources" aria-labelledby="glossary-sources-title">
    <h2 id="glossary-sources-title">Fontes para aprofundar</h2>
    <p>Termos selecionados e definições resumidas em linguagem própria, com foco nos meus estudos de segurança. Para ampliar os assuntos:</p>
    <ul>
      <li><a href="https://www.opservices.com.br/dicionario-da-ti/">OpServices — Dicionário de TI ↗</a></li>
      <li><a href="https://www.gov.br/agricultura/pt-br/acesso-a-informacao/tecnologia-da-informacao/dicionario">MAPA — Dicionário de referência de TI ↗</a></li>
      <li><a href="https://www.tjac.jus.br/wp-content/uploads/2024/07/Glossario-de-Termos-Tecnicos-da-TI.pdf">TJAC — Glossário de termos técnicos da TI (PDF) ↗</a></li>
    </ul>
  </section>
</section>
