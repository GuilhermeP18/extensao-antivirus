/* content.js */
let debounceTimer;

async function scanAndShieldBatch() {
  if (!chrome.runtime?.id) return;

  const anchors = Array.from(document.querySelectorAll('a:not([data-safelink-checked])'));
  
  if (anchors.length === 0) return;

  const urlsToSend = [];
  const validAnchors = [];

  anchors.forEach(a => {
    const href = a.href;
    if (href && href.startsWith('http')) {
      a.setAttribute('data-safelink-checked', 'true');
      urlsToSend.push(href);
      validAnchors.push(a);
    }
  });

  if (urlsToSend.length === 0) return;

  // Envia apenas URLs únicas para reduzir payload
  const uniqueUrls = [...new Set(urlsToSend)];

  chrome.runtime.sendMessage({ type: "CHECK_BATCH", urls: uniqueUrls }, (results) => {
    if (chrome.runtime.lastError) return; // Evita erros se a extensão for recarregada

    if (results && Array.isArray(results)) {
      results.forEach(res => {
        if (!res.safe) {
          // Encontra todos os anchors que batem com a URL perigosa
          const unsafeElements = validAnchors.filter(a => a.href === res.url);
          unsafeElements.forEach(el => applyShieldInteraction(el, res));
        }
      });
    }
  });
}

function applyShieldInteraction(element, threatData) {
  // Estilização visual de alerta
  element.style.backgroundColor = "#ffebeb";
  element.style.color = "#c00";
  element.style.border = "1px solid #c00";
  element.style.textDecoration = "line-through";
  element.title = `⚠️ PERIGO: ${threatData.threatType}. Clique para opções.`;
  element.setAttribute('data-safelink-unsafe', 'true');

  // Remove event listeners antigos clonando o elemento (opcional, mas garante limpeza)
  // Aqui optamos por apenas adicionar o listener com capture e stopImmediatePropagation
  
  element.addEventListener('click', (e) => {
    // Para tudo imediatamente
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    const proceed = confirm(
      `⛔ SAFELINK ALERTA ⛔\n\nLink Malicioso Detectado!\nTipo: ${threatData.threatType}\nURL: ${threatData.url}\n\nDeseja acessar mesmo assim?`
    );

    if (proceed) {
      // Verifica se o link original abriria em nova aba
      const target = element.getAttribute('target');
      if (target === '_blank') {
        window.open(element.href, '_blank');
      } else {
        window.location.href = element.href;
      }
    }
  }, true); // UseCapture para interceptar antes de outros scripts da página
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "CMD_REFRESH_SCAN") {
    console.log("[SafeLink] Refresh solicitado. Reanalisando...");
    document.querySelectorAll('a[data-safelink-checked]').forEach(a => {
      a.removeAttribute('data-safelink-checked');
      // Limpa estilos de erro caso seja reclassificado como seguro (opcional, mas bom para UX)
      if (a.hasAttribute('data-safelink-unsafe')) {
          a.style.backgroundColor = "";
          a.style.color = "";
          a.style.border = "";
          a.style.textDecoration = "";
          a.removeAttribute('data-safelink-unsafe');
          // Nota: O event listener não é removido facilmente sem clonar o nó, 
          // mas o reload da página ou o MutationObserver cuidam de novos elementos.
          // Para uma limpeza perfeita, seria ideal clonar o nó: a.replaceWith(a.cloneNode(true));
      }
    });
    scanAndShieldBatch();
  }
});

const observer = new MutationObserver(() => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(scanAndShieldBatch, 1000);
});

setTimeout(scanAndShieldBatch, 500);
// Observer configurado para childList e subtree para pegar conteúdo dinâmico (AJAX, SPAs)
observer.observe(document.body, { childList: true, subtree: true });