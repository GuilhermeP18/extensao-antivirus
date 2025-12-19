let allLinks = [];
let currentTabId = null;

const inputEl = document.getElementById('manual-url');
const btnCheck = document.getElementById('check-btn');
const btnExport = document.getElementById('export-btn');
const btnRefresh = document.getElementById('refresh-btn');

// Inicialização: Pega a aba atual
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs.length > 0) {
    currentTabId = tabs[0].id;
    loadData();
  }
});

function loadData() {
  chrome.storage.local.get(['lastScannedLinks'], (res) => { 
    if (res.lastScannedLinks) { 
      allLinks = res.lastScannedLinks; 
      renderUI(); 
    }
  });
}

function renderUI() {
  const container = document.getElementById('results');
  if (!container) return;
  container.innerHTML = '';
  
  // FILTRAGEM: Mostra apenas links da aba atual OU verificações manuais feitas nela
  // A propriedade 'tabId' foi adicionada no background.js
  const tabLinks = allLinks.filter(item => item.tabId === currentTabId);
  
  // Remove duplicatas visuais (embora o background já trate isso, garante UI limpa)
  const uniqueLinks = Array.from(new Map(tabLinks.map(item => [item.url, item])).values());
  
  let safeCount = 0, dangerCount = 0;

  if (uniqueLinks.length === 0) {
    container.innerHTML = '<div style="text-align:center; color:#999; padding:20px;">Nenhum link encontrado nesta aba.<br><small>Tente clicar no Refresh 🔄</small></div>';
  }

  uniqueLinks.forEach(item => {
    if (item.safe) safeCount++; else dangerCount++;

    const card = document.createElement('div');
    card.className = `card ${item.safe ? 'safe' : 'malicious'}`;
    
    const urlSpan = document.createElement('span');
    urlSpan.className = 'url-display';
    urlSpan.textContent = item.url; 

    const statusSpan = document.createElement('span');
    statusSpan.className = 'status-label';
    statusSpan.style.color = item.safe ? 'var(--success)' : 'var(--danger)';
    statusSpan.textContent = item.safe ? '✓ SEGURO' : `⚠ ${item.threatType || 'Ameaça Detectada'}`;

    card.appendChild(urlSpan);
    card.appendChild(statusSpan);

    // MUDANÇA: Exibe a fonte SEMPRE, não importa se é seguro ou não
    if (item.source) {
        const sourceDiv = document.createElement('div');
        sourceDiv.style.fontSize = '10px';
        sourceDiv.style.marginTop = '6px';
        sourceDiv.style.paddingTop = '4px';
        sourceDiv.style.borderTop = '1px solid #eee';
        
        // Cor diferente dependendo da fonte para facilitar leitura
        if (item.source.includes("VirusTotal")) {
             sourceDiv.style.color = '#4f46e5'; // Roxo/Azul do VT
             sourceDiv.style.fontWeight = '600';
        } else {
             sourceDiv.style.color = '#9ca3af'; // Cinza para Google
        }

        sourceDiv.textContent = `Validado por: ${item.source}`;
        card.appendChild(sourceDiv);
    }
    
    container.appendChild(card);
  });

  document.getElementById('s-count').innerText = safeCount;
  document.getElementById('d-count').innerText = dangerCount;
}

// Botão Refresh: Manda comando para o Content Script da aba atual
btnRefresh.addEventListener('click', () => {
  if (currentTabId) {
    const icon = btnRefresh;
    icon.style.transform = "rotate(360deg)";
    icon.style.transition = "transform 0.5s";
    
    // Limpa UI temporariamente
    document.getElementById('results').innerHTML = '<div style="text-align:center; padding:20px; color:#666;">Reanalisando página...</div>';
    
    // Envia mensagem para a aba atual
    chrome.tabs.sendMessage(currentTabId, { type: "CMD_REFRESH_SCAN" });
    
    setTimeout(() => { icon.style.transform = "none"; }, 500);
  }
});

// Checagem Manual
btnCheck.addEventListener('click', () => {
  const url = inputEl.value.trim();
  if (!url) return;
  const formattedUrl = url.startsWith('http') ? url : `http://${url}`;
  
  btnCheck.disabled = true;
  btnCheck.innerText = '...';
  
  // Passa o currentTabId para associar essa checagem manual a esta aba
  chrome.runtime.sendMessage({ type: "CHECK_URL", url: formattedUrl, tabId: currentTabId }, (response) => {
    btnCheck.disabled = false;
    btnCheck.innerText = 'Checar';
    inputEl.value = '';
    // A resposta virá via onMessage/loadData automaticamente
  });
});

// Exportar
btnExport.addEventListener('click', () => {
  const tabLinks = allLinks.filter(item => item.tabId === currentTabId);
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(tabLinks, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute("href", dataStr);
  dlAnchor.setAttribute("download", "safelink_logs.json");
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
});

// Listener de atualizações do Background
chrome.runtime.onMessage.addListener((m) => { 
  if(m.type === "LINK_UPDATE"){ 
    allLinks = m.links; 
    renderUI(); 
  }
});