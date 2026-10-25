/* Busca local por notas: facetas, sinônimos e filtros compartilháveis via URL. */
(() => {
  'use strict';
  const search = document.getElementById('post-search');
  const grid = document.getElementById('archive-grid');
  const count = document.getElementById('result-count');
  const empty = document.getElementById('no-results');
  const system = document.getElementById('filter-system');
  const tool = document.getElementById('filter-tool');
  const type = document.getElementById('filter-type');
  const clear = document.getElementById('clear-filters');
  const activeTagBox = document.getElementById('active-tag');
  const activeTagName = document.getElementById('active-tag-name');
  const clearTag = document.getElementById('clear-tag');
  if (!search || !grid || !count || !empty || !system || !tool || !type) return;

  const normalize = (value) => String(value || '').normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('pt-BR')
    .replace(/[-_]+/g, ' ').replace(/\s+/g, ' ').trim();
  const aliases = {
    'reconnaissance': 'recon', 'reconhecimento': 'recon', 'reccon': 'recon',
    'ad': 'active directory', 'privesc': 'privilege escalation',
    'escalacao': 'privilege escalation', 'senhas': 'passwords', 'senha': 'passwords'
  };
  const canonicalTag = (value) => {
    const key = normalize(value);
    return (aliases[key] || key).replace(/\s+/g, '-');
  };
  const availableSystems = ['linux', 'windows', 'macos', 'freebsd', 'android'];
  const knownTools = new Set([
    'bloodhound','cewl','crunch','cupp','evil-winrm','ffuf','gtfobins',
    'hashcat','hydra','icacls','impacket','john','kerbrute','less',
    'metasploit','meterpreter','mimikatz','msfvenom','netcat','netexec',
    'nmap','openssl','powershell','powerview','privesccheck',
    'proxychains','pspy','psexec','roguewinrm','rpcclient','secretsdump',
    'socat','ssh','wes-ng','winpeas','xfreerdp'
  ]);
  const cards = [...grid.querySelectorAll('.post-card')].map(node => {
    const tags = (node.dataset.tags || '').split('|').filter(Boolean);
    return {node, tags, systemTags: tags.filter(tag => availableSystems.includes(tag)),
      tools: tags.filter(tag => knownTools.has(tag)),
      type: node.dataset.type || '', text: normalize(node.dataset.search + ' ' + node.textContent)};
  });
  function addOptions(select, values, names) {
    values.sort((a, b) => a.localeCompare(b, 'pt-BR'));
    for (const value of values) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = names[value] || value;
      select.appendChild(option);
    }
  }
  addOptions(system, [...new Set(cards.flatMap(card => card.systemTags))],
    {linux: 'Linux', windows: 'Windows', macos: 'macOS', freebsd: 'FreeBSD', android: 'Android'});
  addOptions(tool, [...new Set(cards.flatMap(card => card.tools))], {});
  addOptions(type, [...new Set(cards.map(card => card.type).filter(Boolean))],
    {walkthrough: 'Walkthrough', guia: 'Guia', tutorial: 'Tutorial'});

  const params = new URL(window.location.href).searchParams;
  search.value = params.get('q') || '';
  system.value = params.get('os') || '';
  tool.value = params.get('tool') || '';
  type.value = params.get('tipo') || '';
  let activeTag = canonicalTag(params.get('tag'));
  if (activeTag && !cards.some(card => card.tags.includes(activeTag))) activeTag = '';
  function matchesQuery(card, raw) {
    if (!raw) return true;
    const query = aliases[raw] || raw;
    return query.split(' ').every(word => card.text.includes(aliases[word] || word));
  }
  function update() {
    const query = normalize(search.value);
    let visible = 0;
    for (const card of cards) {
      const matches = (!activeTag || card.tags.includes(activeTag)) &&
        (!system.value || (system.value === 'none'
          ? card.systemTags.length === 0 : card.systemTags.includes(system.value))) &&
        (!tool.value || (tool.value === 'none'
          ? card.tools.length === 0 : card.tools.includes(tool.value))) &&
        (!type.value || card.type === type.value) && matchesQuery(card, query);
      card.node.hidden = !matches;
      if (matches) visible++;
    }
    count.textContent = visible + ' de ' + cards.length + ' registros';
    empty.hidden = visible !== 0 || !cards.length;
    activeTagBox.hidden = !activeTag;
    if (activeTag) activeTagName.textContent = '#' + activeTag;
    const current = new URL(window.location.href);
    const next = current.searchParams;
    const values = {q: search.value.trim(), os: system.value, tool: tool.value,
      tipo: type.value, tag: activeTag};
    for (const [key, value] of Object.entries(values)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    window.history.replaceState(null, '', current.pathname + current.search + current.hash);
  }
  for (const select of [system, tool, type]) select.addEventListener('change', update);
  search.addEventListener('input', update);
  clear.addEventListener('click', () => {
    search.value = ''; system.value = ''; tool.value = ''; type.value = ''; activeTag = '';
    update(); search.focus();
  });
  clearTag.addEventListener('click', () => { activeTag = ''; update(); });
  update();
})();
