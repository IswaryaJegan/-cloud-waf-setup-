// WAF Rule Engine
let totalRequests = 0;
let blockedTotal = 0;
let logs = [];

// DOM elements
const totalRequestsSpan = document.getElementById('totalRequests');
const blockedCountSpan = document.getElementById('blockedCount');
const securityScoreSpan = document.getElementById('securityScore');
const logListDiv = document.getElementById('logList');
const requestUrlInput = document.getElementById('requestUrl');
const sendBtn = document.getElementById('sendRequestBtn');
const presetBtns = document.querySelectorAll('.preset');
const filterAllBtn = document.getElementById('filterAll');
const filterBlockedBtn = document.getElementById('filterBlocked');
const filterAllowedBtn = document.getElementById('filterAllowed');
const clearLogsBtn = document.getElementById('clearLogs');

// Rule toggles
const ruleSQL = document.getElementById('ruleSQL');
const ruleXSS = document.getElementById('ruleXSS');
const rulePathTraversal = document.getElementById('rulePathTraversal');
const ruleBadBot = document.getElementById('ruleBadBot');

let currentFilter = 'all';

function updateStatsUI() {
  totalRequestsSpan.innerText = totalRequests;
  blockedCountSpan.innerText = blockedTotal;
  let score = Math.max(0, 100 - Math.floor(blockedTotal / (totalRequests || 1) * 100));
  if (totalRequests === 0) score = 100;
  securityScoreSpan.innerText = score;
}

function addLog(message, type = 'info') {
  const timestamp = new Date().toLocaleTimeString();
  const logEntry = { timestamp, message, type };
  logs.unshift(logEntry); // newest first
  if (logs.length > 50) logs.pop();
  renderLogs();
}

function renderLogs() {
  let filtered = logs;
  if (currentFilter === 'blocked') filtered = logs.filter(l => l.type === 'blocked');
  if (currentFilter === 'allowed') filtered = logs.filter(l => l.type === 'allowed');
  
  logListDiv.innerHTML = filtered.length === 0 ? 
    '<div class="log-entry info">No logs match filter</div>' : 
    filtered.map(log => `<div class="log-entry ${log.type}">[${log.timestamp}] ${log.message}</div>`).join('');
}

function clearLogs() {
  logs = [];
  renderLogs();
  addLog('Logs cleared', 'info');
}

// WAF inspection logic
function inspectRequest(url) {
  const urlLower = url.toLowerCase();
  let blocked = false;
  let reasons = [];

  // SQL Injection pattern
  if (ruleSQL.checked && /(\%27)|(\')|(\-\-)|(\%23)|(#)|(select.*from)|(union.*select)|(insert.*into)|(drop.*table)/i.test(urlLower)) {
    blocked = true;
    reasons.push('SQL Injection');
  }
  // XSS pattern
  if (ruleXSS.checked && /<script|javascript:|onerror=|onload=|alert\(|prompt\(|confirm\(/i.test(urlLower)) {
    blocked = true;
    reasons.push('XSS (Cross-site Scripting)');
  }
  // Path traversal
  if (rulePathTraversal.checked && /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c/i.test(urlLower)) {
    blocked = true;
    reasons.push('Path Traversal');
  }
  // Bad bot patterns (simple)
  if (ruleBadBot.checked && /(curl|wget|python-requests|scrapy|bot|crawler|spider)/i.test(urlLower)) {
    blocked = true;
    reasons.push('Malicious Bot User-Agent (simulated)');
  }

  return { blocked, reasons };
}

function sendRequest(url) {
  totalRequests++;
  const inspection = inspectRequest(url);
  const blocked = inspection.blocked;
  if (blocked) blockedTotal++;
  
  updateStatsUI();
  
  const logMessage = `Request: ${url.substring(0, 70)} → ${blocked ? '🚫 BLOCKED' : '✅ ALLOWED'}${blocked ? ' [' + inspection.reasons.join(', ') + ']' : ''}`;
  addLog(logMessage, blocked ? 'blocked' : 'allowed');
  
  // Also show visual feedback (alert not needed, but small toast effect)
  const simPanel = document.querySelector('.simulator-panel');
  simPanel.style.transition = '0.1s';
  simPanel.style.backgroundColor = blocked ? '#4a0e0e30' : '#0f172ad9';
  setTimeout(() => simPanel.style.backgroundColor = '', 200);
}

// Event listeners
sendBtn.addEventListener('click', () => {
  let url = requestUrlInput.value.trim();
  if (!url) url = '/';
  sendRequest(url);
});

presetBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    const url = btn.getAttribute('data-url');
    requestUrlInput.value = url;
    sendRequest(url);
  });
});

filterAllBtn.addEventListener('click', () => {
  currentFilter = 'all';
  filterAllBtn.classList.add('active');
  filterBlockedBtn.classList.remove('active');
  filterAllowedBtn.classList.remove('active');
  renderLogs();
});
filterBlockedBtn.addEventListener('click', () => {
  currentFilter = 'blocked';
  filterBlockedBtn.classList.add('active');
  filterAllBtn.classList.remove('active');
  filterAllowedBtn.classList.remove('active');
  renderLogs();
});
filterAllowedBtn.addEventListener('click', () => {
  currentFilter = 'allowed';
  filterAllowedBtn.classList.add('active');
  filterAllBtn.classList.remove('active');
  filterBlockedBtn.classList.remove('active');
  renderLogs();
});
clearLogsBtn.addEventListener('click', clearLogs);

// Initial log
addLog('WAF engine started. Rules active: SQL Injection, XSS, Path Traversal, Bad Bots', 'info');
updateStatsUI();