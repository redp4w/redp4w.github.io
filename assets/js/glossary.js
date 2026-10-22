/* Glossário global do blog: primeira ocorrência, sem alterar Markdown ou blocos de código. */
(function () {
  "use strict";
  const root = document.querySelector(".article-content");
  const script = document.currentScript;
  const endpoint = script && script.dataset.glossaryUrl;

  const search = document.querySelector("#glossary-search");
  if (search) {
    const items = Array.from(document.querySelectorAll("#glossary-list [data-glossary-search]"));
    const count = document.querySelector("#glossary-count");
    const update = () => {
      const query = search.value.trim().toLocaleLowerCase("pt-BR");
      let visible = 0;
      items.forEach(item => {
        item.hidden = !!query && !item.dataset.glossarySearch.includes(query);
        if (!item.hidden) visible++;
      });
      if (count) count.textContent = visible + " termo(s) encontrado(s)";
    };
    search.addEventListener("input", update);
    update();
  }

  if (!root || !endpoint || !window.fetch) return;
  fetch(endpoint, {credentials:"same-origin"})
    .then(r => { if (!r.ok) throw Error("HTTP " + r.status); return r.json(); })
    .then(data => { if (Array.isArray(data)) annotate(data); })
    .catch(e => console.warn("Glossário indisponível:", e));

  function slug(term) {
    return term.toLocaleLowerCase("pt-BR").normalize("NFD").replace(/[\u0300-\u036f]/g,"")
      .replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"");
  }

  function annotate(data) {
    const entries = new Map();
    const aliases = new Map();
    data.forEach((entry, id) => {
      if (!entry || !entry.termo || !entry.descricao) return;
      entries.set(id, entry);
      [entry.termo].concat(Array.isArray(entry.aliases) ? entry.aliases : []).forEach(alias => {
        const key = String(alias).toLocaleLowerCase("pt-BR");
        if (!aliases.has(key)) aliases.set(key, {id, text:String(alias)});
      });
    });
    if (!aliases.size) return;

    const specials = "\\^$.*+?()[]{}|";
    const escape = value => Array.from(value).map(c => specials.includes(c) ? "\\" + c : c).join("");
    const variants = Array.from(aliases.values()).sort((a,b) => b.text.length - a.text.length);
    const pattern = new RegExp("(^|[^\\p{L}\\p{N}_])(" +
      variants.map(v => escape(v.text)).join("|") +
      ")(?=$|[^\\p{L}\\p{N}_])", "giu");
    const excluded = "a,code,pre,kbd,samp,script,style,button,h1,h2,h3,h4,h5,h6,svg,textarea,.glossary-term,[contenteditable]";
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        return n.nodeValue.trim() && n.parentElement && !n.parentElement.closest(excluded)
          ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    const used = new Set();
    const tip = createTip();

    nodes.forEach(node => {
      const value = node.nodeValue;
      const hits = [];
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(value))) {
        const phrase = match[2];
        const found = aliases.get(phrase.toLocaleLowerCase("pt-BR"));
        if (!found || used.has(found.id)) continue;
        // Siglas de 2-3 letras só em maiúsculas, evitando coincidências em prosa.
        if (phrase.length <= 3 && found.text === found.text.toUpperCase() && phrase !== found.text) continue;
        hits.push({start:match.index + match[1].length, end:match.index + match[1].length + phrase.length, id:found.id});
        used.add(found.id);
      }
      if (!hits.length) return;
      let offset = 0;
      const fragment = document.createDocumentFragment();
      hits.forEach(hit => {
        fragment.appendChild(document.createTextNode(value.slice(offset,hit.start)));
        const el = document.createElement("button");
        el.type = "button";
        el.className = "glossary-term";
        el.textContent = value.slice(hit.start,hit.end);
        el.setAttribute("aria-label", el.textContent + ": ver definição");
        el.setAttribute("aria-expanded","false");
        el.setAttribute("aria-controls","glossary-popover");
        tip.wire(el, entries.get(hit.id));
        fragment.appendChild(el);
        offset = hit.end;
      });
      fragment.appendChild(document.createTextNode(value.slice(offset)));
      node.parentNode.replaceChild(fragment,node);
    });
  }

  function createTip() {
    const panel = document.createElement("div");
    panel.id = "glossary-popover";
    panel.className = "glossary-popover";
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Definição técnica");
    panel.hidden = true;
    const close = document.createElement("button");
    close.className = "glossary-close";
    close.type = "button";
    close.setAttribute("aria-label", "Fechar definição");
    close.textContent = "×";
    const cat = document.createElement("small");
    const title = document.createElement("strong");
    const desc = document.createElement("p");
    const actions = document.createElement("div");
    actions.className = "glossary-actions";
    const more = document.createElement("a");
    more.textContent = "Ver no glossário ↗";
    const external = document.createElement("a");
    external.textContent = "Referência ↗";
    external.target = "_blank";
    external.rel = "noopener noreferrer";
    actions.append(more,external);
    panel.append(close,cat,title,desc,actions);
    document.body.appendChild(panel);
    let active = null, timer = null;
    const stopTimer = () => { clearTimeout(timer); timer = null; };
    const hide = () => {
      stopTimer();
      if (active) active.setAttribute("aria-expanded","false");
      active = null;
      panel.hidden = true;
    };
    const reposition = () => {
      if (!active || panel.hidden) return;
      const r = active.getBoundingClientRect();
      const w = panel.offsetWidth, h = panel.offsetHeight;
      const x = Math.max(10,Math.min(r.left,innerWidth-w-10));
      const y = innerHeight-r.bottom >= h+12 || r.top < h+12 ? r.bottom+8 : r.top-h-8;
      panel.style.left = x+"px";
      panel.style.top = Math.max(8,y)+"px";
    };
    const show = (el,entry) => {
      stopTimer();
      if (active && active!==el) active.setAttribute("aria-expanded","false");
      active=el;
      el.setAttribute("aria-expanded","true");
      cat.textContent = entry.categoria || "Glossário";
      title.textContent = entry.termo;
      desc.textContent = entry.descricao;
      more.href = "/glossario/#"+slug(entry.termo);
      if (typeof entry.link==="string" && /^https?:\/\//i.test(entry.link)) {
        external.href=entry.link; external.hidden=false;
      } else {external.removeAttribute("href");external.hidden=true;}
      panel.hidden=false;
      reposition();
    };
    const scheduleHide = () => {
      stopTimer();
      timer=setTimeout(() => {
        if (!panel.matches(":hover") && !(active && (active.matches(":hover") || active===document.activeElement)) &&
            !panel.contains(document.activeElement)) hide();
      },180);
    };
    panel.addEventListener("pointerenter",stopTimer);
    panel.addEventListener("pointerleave",scheduleHide);
    panel.addEventListener("focusout",scheduleHide);
    close.addEventListener("click",()=>{const prev=active;hide();if(prev)prev.focus();});
    document.addEventListener("keydown",e=>{if(e.key==="Escape" && active){const prev=active;hide();prev.focus();}});
    document.addEventListener("pointerdown",e=>{if(active && !panel.contains(e.target) && e.target!==active)hide();});
    window.addEventListener("scroll",reposition,true);
    window.addEventListener("resize",reposition);
    return {wire(el,entry) {
      el.addEventListener("pointerenter",e=>{if(e.pointerType!=="touch")show(el,entry);});
      el.addEventListener("pointerleave",scheduleHide);
      el.addEventListener("focus",()=>show(el,entry));
      el.addEventListener("blur",scheduleHide);
      el.addEventListener("click",()=>show(el,entry));
    }};
  }
})();