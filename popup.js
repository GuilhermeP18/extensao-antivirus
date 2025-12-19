/* popup.js (Com Toggle VT) */
let allLinks = [];
let currentTabId = null;

const inputEl = document.getElementById('manual-url');
const btnCheck = document.getElementById('check-btn');
const btnExport = document.getElementById('export-btn');
const btnRefresh = document.getElementById('refresh-btn');
const btnClear = document.getElementById('clear-btn');
const vtToggle = document.getElementById('vt-toggle'); // Novo

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs.length > 0) {
    currentTabId = tabs[0].id;
    loadData();
    updateQuotaUI();
  }
});

function loadData() {
  // Carrega links e o estado do botão VT
  chrome.storage.local.get(['lastScannedLinks', 'vtEnabled'], (res) => { 
    if (res.lastScannedLinks) { 
      allLinks = res.lastScannedLinks; 
      renderUI(); 
    }
    // Define o estado do toggle (Padrão: true/ligado se undefined)
    vtToggle.checked = res.vtEnabled !== false;
  });
}

// Listener para salvar a preferência do usuário
vtToggle.addEventListener('change', (e) => {
  const isEnabled = e.target.checked;
  chrome.storage.local.set({ vtEnabled: isEnabled });
  // Opcional: Recarregar visualmente ou notificar background, mas o background lê direto do storage
});


function updateQuotaUI() {
  const box = document.getElementById('quota-box');
  const txt = document.getElementById('quota-text');
  const fill = document.getElementById('quota-fill');
  
  box.style.display = 'block';

  chrome.runtime.sendMessage({ type: "CHECK_VT_QUOTA" }, (res) => {
    if (chrome.runtime.lastError || !res) {
       txt.innerText = "Erro ao carregar";
       return;
    }

    if (res.error) {
       txt.innerHTML = `<span style="color:#ef4444;font-size:10px;">${res.details}</span>`;
       fill.style.width = "0%";
       fill.className = 'progress-fill danger';
       return;
    }

    txt.innerText = `${res.used} / ${res.limit} (${res.percent}%)`;
    fill.style.width = `${res.percent}%`;
    fill.className = 'progress-fill';
    if (res.percent > 50) fill.classList.add('warning');
    if (res.percent > 80) fill.classList.add('danger');
  });
}

function renderUI() {
  const container = document.getElementById('results');
  if (!container) return;
  container.innerHTML = '';
  
  const tabLinks = allLinks.filter(item => item.tabId === currentTabId || item.tabId === 'MANUAL');
  const uniqueLinks = Array.from(new Map(tabLinks.map(item => [item.url, item])).values());
  
  let safeCount = 0, dangerCount = 0;

  if (uniqueLinks.length === 0) {
    container.innerHTML = '<div style="text-align:center; color:#999; padding:20px;">Nenhum link encontrado ou lista limpa.<br><small>Use o Refresh 🔄 para escanear.</small></div>';
  }

  uniqueLinks.forEach(item => {
    if (item.safe) safeCount++; else dangerCount++;

    const card = document.createElement('div');
    card.className = `card ${item.safe ? 'safe' : 'malicious'}`;
    
    const urlSpan = document.createElement('span');
    urlSpan.className = 'url-display';
    
    if (item.tabId === 'MANUAL' || item.isManual) {
        urlSpan.innerHTML = `<span style="background:#eee; color:#666; padding:1px 4px; border-radius:3px; font-size:9px; margin-right:4px;">MANUAL</span> ${item.url}`;
    } else {
        urlSpan.textContent = item.url; 
    }

    const statusSpan = document.createElement('span');
    statusSpan.className = 'status-label';
    statusSpan.style.color = item.safe ? 'var(--success)' : 'var(--danger)';
    statusSpan.textContent = item.safe ? '✓ SEGURO' : `⚠ ${item.threatType || 'Ameaça Detectada'}`;

    card.appendChild(urlSpan);
    card.appendChild(statusSpan);

    if (item.source) {
        const sourceDiv = document.createElement('div');
        sourceDiv.style.fontSize = '10px';
        sourceDiv.style.marginTop = '6px';
        sourceDiv.style.paddingTop = '4px';
        sourceDiv.style.borderTop = '1px solid #eee';
        
        if (item.source.includes("VirusTotal")) {
             sourceDiv.style.color = '#4f46e5'; 
             sourceDiv.style.fontWeight = '600';
        } else {
             sourceDiv.style.color = '#9ca3af'; 
        }

        sourceDiv.textContent = `Validado por: ${item.source}`;
        card.appendChild(sourceDiv);
    }
    
    container.appendChild(card);
  });

  document.getElementById('s-count').innerText = safeCount;
  document.getElementById('d-count').innerText = dangerCount;
}

btnRefresh.addEventListener('click', () => {
  if (currentTabId) {
    const icon = btnRefresh;
    icon.style.transform = "rotate(360deg)";
    icon.style.transition = "transform 0.5s";
    
    document.getElementById('results').innerHTML = '<div style="text-align:center; padding:20px; color:#666;">Reanalisando página...</div>';
    chrome.tabs.sendMessage(currentTabId, { type: "CMD_REFRESH_SCAN" });
    
    setTimeout(updateQuotaUI, 2000);
    setTimeout(() => { icon.style.transform = "none"; }, 500);
  }
});

btnClear.addEventListener('click', () => {
    allLinks = [];
    renderUI();
    chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" });
});

btnCheck.addEventListener('click', () => {
  const url = inputEl.value.trim();
  if (!url) return;
  const formattedUrl = url.startsWith('http') ? url : `http://${url}`;
  
  btnCheck.disabled = true;
  btnCheck.innerText = '...';
  
  chrome.runtime.sendMessage({ type: "CHECK_URL", url: formattedUrl, tabId: currentTabId }, (response) => {
    btnCheck.disabled = false;
    btnCheck.innerText = 'Checar';
    inputEl.value = '';
    updateQuotaUI();
  });
});

btnExport.addEventListener('click', () => {
  const tabLinks = allLinks.filter(item => item.tabId === currentTabId || item.tabId === 'MANUAL');
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(tabLinks, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute("href", dataStr);
  dlAnchor.setAttribute("download", "safelink_logs.json");
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
});

chrome.runtime.onMessage.addListener((m) => { 
  if(m.type === "LINK_UPDATE"){ 
    allLinks = m.links; 
    renderUI(); 
  }
});