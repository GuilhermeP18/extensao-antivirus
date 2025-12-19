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
  const uniqueUrls = [...new Set(urlsToSend)];

  chrome.runtime.sendMessage({ type: "CHECK_BATCH", urls: uniqueUrls }, (results) => {
    if (chrome.runtime.lastError) return;

    if (results && Array.isArray(results)) {
      results.forEach(res => {
        if (!res.safe) {
          const unsafeElements = validAnchors.filter(a => a.href === res.url);
          unsafeElements.forEach(el => applyShieldInteraction(el, res));
        }
      });
    }
  });
}

function applyShieldInteraction(element, threatData) {
  element.style.backgroundColor = "#ffebeb";
  element.style.color = "#c00";
  element.style.border = "1px solid #c00";
  element.style.textDecoration = "line-through";
  element.title = `⚠️ PERIGO: ${threatData.threatType}. Clique para opções.`;
  element.setAttribute('data-safelink-unsafe', 'true');

  element.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    const proceed = confirm(
      `⛔ SAFELINK ALERTA ⛔\n\nLink Malicioso Detectado!\nTipo: ${threatData.threatType}\nURL: ${threatData.url}\n\nDeseja acessar mesmo assim?`
    );

    if (proceed) {
      const target = element.getAttribute('target');
      if (target === '_blank') {
        window.open(element.href, '_blank');
      } else {
        window.location.href = element.href;
      }
    }
  }, true);
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "CMD_REFRESH_SCAN") {
    console.log("[SafeLink] Refresh solicitado.");
    document.querySelectorAll('a[data-safelink-checked]').forEach(a => {
      a.removeAttribute('data-safelink-checked');
      if (a.hasAttribute('data-safelink-unsafe')) {
          a.style.backgroundColor = "";
          a.style.color = "";
          a.style.border = "";
          a.style.textDecoration = "";
          a.removeAttribute('data-safelink-unsafe');
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
observer.observe(document.body, { childList: true, subtree: true });