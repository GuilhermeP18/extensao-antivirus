/* background.js (Atualizado - Controle Toggle VT) */
const GOOGLE_KEY = "AIzaSyDGIpHmo5er3l7Wg5CkeMqSt5cN3dr7Qik"; 
const VT_KEY = "fa95db1a3ddc7391c98d5891b957be8d267674dd5a4dfebcc4b1b5da4108ddb8"; 
const VT_USERNAME = "Sashin32"; 

const GOOGLE_API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`;
const SUSPICIOUS_EXTS = ['.exe', '.zip', '.pdf', '.dmg', '.rar', '.msi', '.bat', '.sh'];

async function getFromCache(key) {
  try {
    const result = await chrome.storage.session.get(key);
    return result[key] || null;
  } catch (e) { return null; }
}

async function saveToCache(key, value) {
  try {
    const obj = {};
    obj[key] = value;
    await chrome.storage.session.set(obj);
  } catch (e) { console.error("Erro cache", e); }
}

function updateTabBadge(tabId, allSessionLinks) {
  if (!tabId || tabId === 'MANUAL') return;
  const tabLinks = allSessionLinks.filter(l => l.tabId === tabId);
  const dangerCount = tabLinks.filter(l => !l.safe).length;

  if (dangerCount > 0) {
    chrome.action.setBadgeText({ text: dangerCount.toString(), tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: tabId });
  } else {
    chrome.action.setBadgeText({ text: "", tabId: tabId });
  }
}

async function checkVtQuota() {
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/users/${VT_USERNAME}`, {
      method: 'GET',
      headers: {
        'x-apikey': VT_KEY,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        return { error: "Erro de Auth", details: "API Key Inválida" };
      }
      return { error: `Erro ${response.status}`, details: "Falha na API" };
    }

    const json = await response.json();
    const quotas = json?.data?.attributes?.quotas?.api_requests_daily;
    const used = quotas?.used || 0;
    const limit = quotas?.allowed || 500; 

    return { 
      used: used, 
      limit: limit, 
      percent: Math.min(Math.round((used / limit) * 100), 100) 
    };

  } catch (e) {
    console.error("Erro Quota VT:", e);
    return { error: "Erro Conexão", details: "Falha na Rede" };
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.session.set({ sessionScannedLinks: [] });
  chrome.action.setBadgeText({ text: "" });
  // Opcional: Definir padrão do Toggle como true se não existir
  chrome.storage.local.get('vtEnabled', (res) => {
    if (res.vtEnabled === undefined) chrome.storage.local.set({ vtEnabled: true });
  });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = request.tabId || (sender.tab ? sender.tab.id : null);

  if (request.type === "CLEAR_HISTORY") {
    chrome.storage.session.set({ sessionScannedLinks: [] });
    chrome.storage.local.set({ lastScannedLinks: [] });
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => chrome.action.setBadgeText({ text: "", tabId: tab.id }));
    });
    try { chrome.runtime.sendMessage({ type: "LINK_UPDATE", links: [] }); } catch(e){}
    return true;
  }

  if (request.type === "CHECK_VT_QUOTA") {
    checkVtQuota().then(quotaData => sendResponse(quotaData));
    return true;
  }

  if (request.type === "CHECK_URL") {
    processBatchSecurityCheck([request.url], tabId, true).then((results) => {
      saveResultForPopup(results);
      sendResponse(results[0]);
    });
    return true;
  }
  
  if (request.type === "CHECK_BATCH") {
    processBatchSecurityCheck(request.urls, tabId, false).then((results) => {
      saveResultForPopup(results);
      sendResponse(results);
    });
    return true; 
  }
});

async function saveResultForPopup(results) {
  let sessionLinks = (await getFromCache('sessionScannedLinks')) || [];
  results.forEach(res => {
    sessionLinks = sessionLinks.filter(l => !(l.url === res.url && l.tabId === res.tabId));
    sessionLinks.unshift(res);
  });
  sessionLinks = sessionLinks.slice(0, 200);
  
  await saveToCache('sessionScannedLinks', sessionLinks);
  chrome.storage.local.set({ lastScannedLinks: sessionLinks });
  
  if (results.length > 0) {
    const targetTabId = results[0].tabId;
    if (targetTabId && targetTabId !== 'MANUAL') {
        updateTabBadge(targetTabId, sessionLinks);
    }
  }

  try { chrome.runtime.sendMessage({ type: "LINK_UPDATE", links: sessionLinks }); } catch(e){}
}

async function resolveFinalUrl(url) {
  const cachedRedirect = await getFromCache(`redirect_${url}`);
  if (cachedRedirect) return cachedRedirect;

  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 2000); 
    let response = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller.signal })
      .catch(() => null);
    clearTimeout(id);
    const finalUrl = response ? response.url : url;
    await saveToCache(`redirect_${url}`, finalUrl);
    return finalUrl;
  } catch (error) { return url; }
}

async function processBatchSecurityCheck(urls, tabId, isManual = false) {
  const uniqueUrls = [...new Set(urls)];
  const results = [];
  const urlMapping = new Map();
  const urlsToProcess = [];

  // 1. Ler configuração do VT no Storage
  // Padrão é TRUE se não estiver definido
  const settings = await chrome.storage.local.get('vtEnabled');
  const vtEnabled = settings.vtEnabled !== false; 

  for (const url of uniqueUrls) {
    const cachedResult = await getFromCache(`res_${url}`);
    if (cachedResult) {
      results.push({ 
        ...cachedResult, 
        tabId: isManual ? 'MANUAL' : tabId,
        isManual: isManual 
      });
    } else {
      urlsToProcess.push(url);
    }
  }

  if (urlsToProcess.length === 0) return results;

  const resolvePromises = urlsToProcess.map(async (originalUrl) => {
    const finalUrl = await resolveFinalUrl(originalUrl);
    urlMapping.set(originalUrl, finalUrl);
  });
  await Promise.all(resolvePromises);

  const finalUrlsToCheck = urlsToProcess.map(u => urlMapping.get(u) || u);
  const googleMap = await checkGoogleBatch(finalUrlsToCheck);

  for (const originalUrl of urlsToProcess) {
    const finalUrl = urlMapping.get(originalUrl) || originalUrl;
    
    const isRedirected = originalUrl !== finalUrl;
    const isSuspiciousFile = SUSPICIOUS_EXTS.some(ext => finalUrl.toLowerCase().endsWith(ext));

    let result = {
      url: originalUrl,
      finalUrl: isRedirected ? finalUrl : null,
      safe: true,
      threatType: null,
      source: "Google Safe Browsing",
      isSuspiciousFile: isSuspiciousFile,
      tabId: isManual ? 'MANUAL' : tabId,
      isManual: isManual 
    };

    // Google Safe Browsing (Sempre ativo)
    if (googleMap[finalUrl] && !googleMap[finalUrl].safe) {
      result.safe = false;
      result.source = "Google Safe Browsing";
      result.threatType = googleMap[finalUrl].threatType;
    } 
    // VirusTotal:
    // Só executa se:
    // 1. (É Manual) OU (VT está Ativado Globalmente)
    // 2. AND (É arquivo suspeito OU É Manual OU Houve Redirecionamento)
    // 3. AND (Tem chave API)
    else if ((isManual || vtEnabled) && (result.isSuspiciousFile || isManual || isRedirected) && VT_KEY.length > 10) {
      console.log(`🔍 Analisando no VirusTotal (Redir ou Suspeito): ${finalUrl}`);
      
      const vtRes = await checkVirusTotal(finalUrl);
      
      if (!vtRes.safe) {
        result.safe = false;
        result.source = "VirusTotal";
        result.threatType = `Vírus Detectado (${vtRes.positives})`;
      } else if (vtRes.reason === 'unknown') {
        result.source = "VirusTotal (Novo/Não Listado)";
      } else {
        result.source = "VirusTotal (Limpo)";
      }
    }

    await saveToCache(`res_${originalUrl}`, result);
    results.push(result);
  }

  return results;
}

async function checkGoogleBatch(urls) {
  const uniqueFinalUrls = [...new Set(urls)];
  if (uniqueFinalUrls.length === 0) return {};

  const threatEntries = uniqueFinalUrls.map(u => ({ url: u }));
  const body = {
    client: { clientId: "safelink-pro", clientVersion: "2.2" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: threatEntries
    }
  };

  try {
    const response = await fetch(GOOGLE_API_URL, { method: "POST", body: JSON.stringify(body) });
    const data = await response.json();
    const resultMap = {};
    uniqueFinalUrls.forEach(u => resultMap[u] = { safe: true, source: "Google Safe Browsing" });

    if (data.matches) {
      data.matches.forEach(match => {
        resultMap[match.threat.url] = { safe: false, threatType: match.threatType };
      });
    }
    return resultMap;
  } catch (e) { return {}; }
}

async function checkVirusTotal(urlToCheck) {
  try {
    const urlId = btoa(unescape(encodeURIComponent(urlToCheck)))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': VT_KEY }
    });

    if (response.status === 404) return { safe: true, reason: 'unknown' }; 
    if (response.status !== 200) return { safe: true, reason: 'error' };

    const data = await response.json();
    const stats = data.data?.attributes?.last_analysis_stats;

    if (stats && stats.malicious > 0) {
      return { safe: false, positives: stats.malicious };
    }
    return { safe: true, reason: 'clean' };

  } catch (e) { return { safe: true, reason: 'error' }; }
}