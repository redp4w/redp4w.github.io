/*
 * Índice lateral automático para artigos Jekyll.
 * - Usa os títulos reais (H1/H2/H3), sem alterar posts.
 * - Preserva IDs gerados pelo Jekyll e remove índice manual somente após sucesso.
 * - Menu sticky no desktop, recolhível no celular; navegação por teclado.
 */
(() => {
  "use strict";

  const layout = document.querySelector(".post-layout");
  const article = layout && layout.querySelector(".article-content");
  const aside = layout && layout.querySelector(".post-toc");
  const details = aside && aside.querySelector(".post-toc-details");
  const list = aside && aside.querySelector(".post-toc-list");
  const count = aside && aside.querySelector(".post-toc-count");
  if (!layout || !article || !aside || !details || !list) return;

  const normalize = text => text.normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("pt-BR")
    .trim();

  // Remove índices escritos no corpo APENAS se identificarmos a lista de links.
  function manualIndexes() {
    const indexes = [];
    article.querySelectorAll("h2, h3").forEach(h => {
      const title = normalize(h.textContent.replace(/\s+/g, " "));
      if (!["indice", "sumario", "indice clicavel", "neste artigo"].includes(title)) return;
      const next = h.nextElementSibling;
      if (next && ["OL", "UL", "NAV"].includes(next.tagName) && next.querySelector('a[href^="#"]')) {
        indexes.push({heading:h, list:next, divider: next.nextElementSibling &&
          next.nextElementSibling.tagName === "HR" ? next.nextElementSibling : null});
      }
    });
    return indexes;
  }

  const oldIndexes = manualIndexes();
  const oldIndexHeadings = new Set(oldIndexes.map(i => i.heading));
  const allHeadings = Array.from(article.querySelectorAll("h1, h2, h3"));
  // O primeiro H1 é o título da publicação, não uma seção do índice.
  const titleHeading = article.querySelector("h1");
  const headings = allHeadings.filter(h => h !== titleHeading && !oldIndexHeadings.has(h) &&
    !h.closest("blockquote, table, nav, [hidden]"));

  if (headings.length < 2) return; // Artigos curtos mantêm o layout original.

  const minLevel = Math.min(...headings.map(h => Number(h.tagName[1])));
  const seenIds = new Set(Array.from(document.querySelectorAll("[id]")).map(el => el.id));

  function headingId(heading) {
    if (heading.id) return heading.id;
    const name = normalize(heading.textContent).replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "secao";
    let candidate = name;
    for (let n = 2; seenIds.has(candidate); n++) candidate = name + "-" + n;
    seenIds.add(candidate);
    heading.id = candidate;
    return candidate;
  }

  const links = headings.map((heading, index) => {
    const li = document.createElement("li");
    li.className = "post-toc-item post-toc-depth-" +
      Math.min(2, Math.max(0, Number(heading.tagName[1]) - minLevel));

    const anchor = document.createElement("a");
    anchor.href = "#" + encodeURIComponent(headingId(heading));
    anchor.textContent = heading.textContent.replace(/\s+/g, " ").trim();
    anchor.title = anchor.textContent;
    anchor.addEventListener("click", () => {
      activate(index);
      if (mobile.matches) details.open = false;
    });

    li.appendChild(anchor);
    list.appendChild(li);
    return anchor;
  });

  aside.querySelectorAll(".post-toc-count").forEach(el => {
    el.textContent = headings.length + " tópicos";
  });

  const mobile = window.matchMedia("(max-width: 980px)");
  function syncView() {
    details.open = !mobile.matches;
  }
  syncView();
  if (typeof mobile.addEventListener === "function") {
    mobile.addEventListener("change", syncView);
  } else if (typeof mobile.addListener === "function") {
    mobile.addListener(syncView);
  }

  // Os índices escritos manualmente só são escondidos com a navegação pronta.
  oldIndexes.forEach(i => {
    i.heading.hidden = true;
    i.list.hidden = true;
    if (i.divider) i.divider.hidden = true;
  });
  layout.classList.add("has-toc");
  aside.hidden = false;

  let previous = -1;
  function activate(index) {
    if (index === previous) return;
    if (links[previous]) links[previous].removeAttribute("aria-current");
    previous = index;
    if (links[index]) {
      links[index].setAttribute("aria-current", "location");
      // Só deslocar o menu quando o item ativo sai da área visível.
      if (!mobile.matches) {
        const item = links[index];
        const viewport = aside.getBoundingClientRect();
        const rect = item.getBoundingClientRect();
        if (rect.top < viewport.top + 45 || rect.bottom > viewport.bottom - 15) {
          // Rola apenas a lateral; evita mover a página durante a leitura.
          if (rect.top < viewport.top + 45) {
            aside.scrollTop -= (viewport.top + 45 - rect.top);
          } else {
            aside.scrollTop += (rect.bottom - viewport.bottom + 15);
          }
        }
      }
    }
  }

  let queued = false;
  function updatePosition() {
    queued = false;
    const threshold = 150;
    let index = 0;
    headings.forEach((heading, i) => {
      if (heading.getBoundingClientRect().top <= threshold) index = i;
    });
    // Quando chegamos ao final do artigo, selecionar a última seção.
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 5) {
      index = headings.length - 1;
    }
    activate(index);
  }
  function scheduleUpdate() {
    if (queued) return;
    queued = true;
    window.requestAnimationFrame(updatePosition);
  }

  window.addEventListener("scroll", scheduleUpdate, {passive:true});
  window.addEventListener("resize", scheduleUpdate);
  window.addEventListener("hashchange", scheduleUpdate);
  scheduleUpdate();
})();