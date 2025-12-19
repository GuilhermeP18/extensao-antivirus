/* background.js (Atualizado) */
const GOOGLE_KEY = "AIzaSyDGIpHmo5er3l7Wg5CkeMqSt5cN3dr7Qik"; 
const VT_KEY = "fa95db1a3ddc7391c98d5891b957be8d267674dd5a4dfebcc4b1b5da4108ddb8"; 

const GOOGLE_API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`;
const SUSPICIOUS_EXTS = ['.exe', '.zip', '.pdf', '.dmg', '.rar', '.msi', '.bat', '.sh'];

// -- GERENCIAMENTO DE CACHE --
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

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.session.set({ sessionScannedLinks: [] });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = request.tabId || (sender.tab ? sender.tab.id : null);

  // Se for checagem manual (CHECK_URL), forçamos uma flag 'isManual'
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

// Adicionado parâmetro 'isManual'
async function processBatchSecurityCheck(urls, tabId, isManual = false) {
  const uniqueUrls = [...new Set(urls)];
  const results = [];
  const urlMapping = new Map();
  const urlsToProcess = [];

  for (const url of uniqueUrls) {
    const cachedResult = await getFromCache(`res_${url}`);
    if (cachedResult) {
      results.push({ ...cachedResult, tabId });
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
    // Verifica se é arquivo suspeito
    const isSuspiciousFile = SUSPICIOUS_EXTS.some(ext => finalUrl.toLowerCase().endsWith(ext));

    let result = {
      url: originalUrl,
      finalUrl: isRedirected ? finalUrl : null,
      safe: true,
      threatType: null,
      source: "Google Safe Browsing", // Padrão inicial
      isSuspiciousFile: isSuspiciousFile,
      tabId: tabId
    };

    // 1. Google Safe Browsing
    if (googleMap[finalUrl] && !googleMap[finalUrl].safe) {
      result.safe = false;
      result.source = "Google Safe Browsing";
      result.threatType = googleMap[finalUrl].threatType;
    } 
    // 2. VirusTotal (Apenas se for arquivo suspeito OU Checagem Manual)
    // Se for manual, checamos VT mesmo que não termine em .exe, para dar mais segurança
    else if ((result.isSuspiciousFile || isManual) && VT_KEY.length > 10) {
      console.log(`🔍 Analisando no VirusTotal: ${finalUrl}`);
      
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
    client: { clientId: "safelink-pro", clientVersion: "2.1" },
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
    // Define a fonte padrão como Google Safe Browsing aqui também
    uniqueFinalUrls.forEach(u => resultMap[u] = { safe: true, source: "Google Safe Browsing" });

    if (data.matches) {
      data.matches.forEach(match => {
        resultMap[match.threat.url] = { safe: false, threatType: match.threatType };
      });
    }
    return resultMap;
  } catch (e) {
    console.error("Erro Google Batch:", e);
    return {};
  }
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