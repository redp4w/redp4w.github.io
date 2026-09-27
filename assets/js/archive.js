/* Arquivo único de artigos: busca local e filtro por tags.
 * Para adicionar conteúdo, publique um Markdown em _posts/ com title/tags.
 * Nenhuma atualização neste JavaScript é necessária ao publicar.
 */
(() => {
  'use strict';
  const search = document.getElementById('post-search');
  const grid = document.getElementById('archive-grid');
  const count = document.getElementById('result-count');
  const empty = document.getElementById('no-results');
  const filters = [...document.querySelectorAll('[data-filter]')];
  if (!search || !grid || !count || !empty) return;

  const cards = [...grid.querySelectorAll('.post-card')];
  const normalize = (value) => String(value || '').normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('pt-BR').trim();
  const params = new URLSearchParams(window.location.search);
  let activeTag = normalize(params.get('tag'));
  if (!filters.some((button) => normalize(button.dataset.filter) === activeTag)) activeTag = '';

  function update() {
    const query = normalize(search.value);
    let visible = 0;
    for (const card of cards) {
      const tags = (card.dataset.tags || '').split('|').map(normalize);
      const matches = (!activeTag || tags.includes(activeTag)) &&
        (!query || normalize(card.textContent).includes(query));
      card.hidden = !matches;
      if (matches) visible++;
    }
    count.textContent = `${visible} de ${cards.length} registros`;
    empty.hidden = visible !== 0 || cards.length === 0;
    for (const button of filters) {
      const selected = normalize(button.dataset.filter) === activeTag;
      button.classList.toggle('active', selected);
      button.setAttribute('aria-pressed', String(selected));
    }
  }

  search.addEventListener('input', update);
  for (const button of filters) {
    button.addEventListener('click', () => {
      activeTag = normalize(button.dataset.filter);
      const url = new URL(window.location.href);
      if (activeTag) url.searchParams.set('tag', activeTag);
      else url.searchParams.delete('tag');
      window.history.replaceState(null, '', url);
      update();
    });
  }
  update();
})();
