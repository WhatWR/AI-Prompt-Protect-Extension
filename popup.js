'use strict';

const PATTERNS = [
  // SECRETS
  { id:'openai',     label:'OpenAI API Key',        cat:'secret', re:/sk-[a-zA-Z0-9\-_]{20,80}/g },
  { id:'anthropic',  label:'Anthropic API Key',     cat:'secret', re:/sk-ant-[a-zA-Z0-9\-_]{30,}/g },
  { id:'google',     label:'Google API Key',        cat:'secret', re:/AIza[0-9A-Za-z\-_]{35}/g },
  { id:'aws',        label:'AWS Access Key',        cat:'secret', re:/\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/g },
  { id:'github',     label:'GitHub Token',          cat:'secret', re:/ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}/g },
  { id:'stripe',     label:'Stripe Key',            cat:'secret', re:/\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{20,}\b/g },
  { id:'slack',      label:'Slack Token',           cat:'secret', re:/xox[baprs]-[0-9A-Za-z\-]{10,}/g },
  { id:'jwt',        label:'JWT Token',             cat:'secret', re:/eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.?[A-Za-z0-9\-_.+/=]*/g },
  { id:'bearer',     label:'Bearer Token',          cat:'secret', re:/Bearer\s+[A-Za-z0-9\-_\.]{20,}/g },
  { id:'pem',        label:'Private Key (PEM)',     cat:'secret', re:/-----BEGIN[^-]+PRIVATE KEY-----/g },
  { id:'dbconn',     label:'DB Connection String',  cat:'secret', re:/(mongodb(\+srv)?|postgresql|mysql|redis|amqp):\/\/[^\s"'`\n]+/gi },
  { id:'password',   label:'Password inline',       cat:'secret', re:/(?:password|passwd|pwd|secret|api_secret)\s*[:=]\s*['"]?[^\s'"`,;\n]{4,}['"]?/gi },
  { id:'envvar',     label:'ENV Variable',          cat:'secret', re:/^[A-Z][A-Z0-9_]{2,}=.+$/gm },
  { id:'hex32',      label:'Secret Key (hex)',      cat:'secret', re:/\b[0-9a-f]{32,64}\b/g },
  // PII THAI
  { id:'thaiid',     label:'เลขบัตรประชาชน',       cat:'pii',    re:/\b\d{1}-\d{4}-\d{5}-\d{2}-\d{1}\b/g },
  { id:'thaiphone',  label:'เบอร์โทรศัพท์',         cat:'pii',    re:/\b0[689]\d[-\s]?\d{3}[-\s]?\d{4}\b/g },
  { id:'thainame',   label:'ชื่อ-นามสกุล',          cat:'pii',    re:/(?:นาย|นาง(?:สาว)?|คุณ|ดร\.|ผศ\.|รศ\.)\s*[ก-ฮ]{2,}\s+[ก-ฮ]{2,}/g },
  { id:'promptpay',  label:'PromptPay',             cat:'pii',    re:/(?:พร้อมเพย์|promptpay)\s*:?\s*[\d\-]{10,13}/gi },
  { id:'thaibank',   label:'เลขบัญชีธนาคาร',       cat:'pii',    re:/\b\d{3}[-\s]?\d{1}[-\s]?\d{5}[-\s]?\d{1}\b/g },
  // PII GENERAL
  { id:'email',      label:'อีเมล',                cat:'pii',    re:/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g },
  { id:'card',       label:'บัตรเครดิต',            cat:'pii',    re:/\b(?:\d{4}[-\s]?){3}\d{4}\b/g },
  { id:'passport',   label:'Passport',             cat:'pii',    re:/\b[A-Z]{1,2}\d{6,9}\b/g },
  { id:'ip_private', label:'IP Address (private)',  cat:'pii',    re:/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g },
  // BIZ
  { id:'amount',     label:'ตัวเลขการเงิน',         cat:'biz',    re:/\b\d{1,3}(,\d{3})+(\.\d{1,2})?\s*(บาท|฿|THB|USD|EUR|GBP)\b/gi },
  { id:'iurl',       label:'Internal URL',          cat:'biz',    re:/https?:\/\/(localhost|127\.0\.0\.1|192\.168\.|10\.|staging\.|dev\.)[^\s\n]*/gi },
  { id:'taxid',      label:'เลขนิติบุคคล',          cat:'biz',    re:/\b0\d{12}\b/g },
];

let findings = [];
let stats    = { total: 0, masked: 0, safe: 0 };

// ── DOM refs (assigned after DOMContentLoaded)
let inputText, findingsSection, safeBanner, findingsCount,
    findingsList, outputSection, outputText, copyBtn, statTotal,
    statMasked, statSafe;

document.addEventListener('DOMContentLoaded', () => {
  inputText       = document.getElementById('inputText');
  findingsSection = document.getElementById('findingsSection');
  safeBanner      = document.getElementById('safeBanner');
  findingsCount   = document.getElementById('findingsCount');
  findingsList    = document.getElementById('findingsList');
  outputSection   = document.getElementById('outputSection');
  outputText      = document.getElementById('outputText');
  copyBtn         = document.getElementById('copyBtn');
  statTotal       = document.getElementById('statTotal');
  statMasked      = document.getElementById('statMasked');
  statSafe        = document.getElementById('statSafe');

  // Wire buttons — NO inline handlers
  document.getElementById('clearBtn').addEventListener('click', clearAll);
  document.getElementById('pasteBtn').addEventListener('click', pasteFromClipboard);
  document.getElementById('scanBtn').addEventListener('click', runScan);
  document.getElementById('maskAllBtn').addEventListener('click', maskAll);
  copyBtn.addEventListener('click', copyOutput);
  inputText.addEventListener('input', onInput);

  // Load stored stats
  chrome.storage.local.get(['stats'], (d) => {
    if (d.stats) { stats = d.stats; updateStats(); }
  });
});

// ── Helpers
function catClass(cat) {
  return cat === 'secret' ? 't-secret' : cat === 'pii' ? 't-pii' : 't-biz';
}
function catLabel(cat) {
  return cat === 'secret' ? '🔑 SECRET' : cat === 'pii' ? '👤 PII' : '💼 BIZ';
}

function updateStats() {
  statTotal.textContent  = stats.total;
  statMasked.textContent = stats.masked;
  statSafe.textContent   = stats.safe;
}

function saveStats() {
  chrome.storage.local.set({ stats });
  updateStats();
}

// ── Actions
async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    inputText.value = text;
    onInput();
  } catch (_) {
    alert('กรุณา paste ด้วย Ctrl+V ในช่องโดยตรง');
  }
}

function onInput() {
  findingsSection.style.display = 'none';
  safeBanner.style.display      = 'none';
  inputText.classList.remove('has-findings');
}

function runScan() {
  const text = inputText.value.trim();
  if (!text) { alert('กรุณา paste text ก่อนสแกน'); return; }

  findings = [];
  const seen = new Set();

  for (const p of PATTERNS) {
    const rx = new RegExp(p.re.source, p.re.flags);
    const matches = text.match(rx) || [];
    for (const m of matches) {
      if (!seen.has(m)) {
        seen.add(m);
        findings.push({ pattern: p, value: m, masked: true });
      }
    }
  }

  stats.total++;

  if (findings.length === 0) {
    safeBanner.style.display      = 'block';
    findingsSection.style.display = 'none';
    inputText.classList.remove('has-findings');
    stats.safe++;
    saveStats();
    return;
  }

  safeBanner.style.display = 'none';
  inputText.classList.add('has-findings');
  renderFindings();
  renderOutput();
  findingsSection.style.display = 'block';
  outputSection.style.display   = 'block';
  stats.masked += findings.length;
  saveStats();
}

function renderFindings() {
  findingsCount.textContent = findings.length + ' รายการ';

  findingsList.innerHTML = findings.map((f, i) => {
    const display = f.value.length > 38 ? f.value.slice(0, 38) + '…' : f.value;
    return `<div class="finding-row checked" data-idx="${i}">
      <span class="ftag ${catClass(f.pattern.cat)}">${catLabel(f.pattern.cat)}</span>
      <span class="fval">${display}</span>
      <span class="flabel">${f.pattern.label}</span>
      <span class="fcheck">✓</span>
    </div>`;
  }).join('');

  // Attach click listeners (no inline handlers)
  findingsList.querySelectorAll('.finding-row').forEach((row) => {
    row.addEventListener('click', () => {
      const idx = parseInt(row.dataset.idx, 10);
      toggleFinding(idx, row);
    });
  });
}

function toggleFinding(i, row) {
  findings[i].masked = !findings[i].masked;
  row.classList.toggle('checked', findings[i].masked);
  row.classList.toggle('masked',  !findings[i].masked);
  renderOutput();
}

function renderOutput() {
  let text = inputText.value;
  let maskedCount = 0;

  for (const f of findings) {
    if (f.masked) {
      const escaped     = f.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const replacement = '[' + '█'.repeat(Math.min(f.value.length, 12)) + ']';
      text = text.replace(new RegExp(escaped, 'g'), replacement);
      maskedCount++;
    }
  }

  outputText.value    = text;
  copyBtn.textContent = maskedCount > 0
    ? `📋 Copy (masked ${maskedCount} รายการ)`
    : '📋 Copy text';
  copyBtn.classList.remove('copied');
}

function maskAll() {
  findingsList.querySelectorAll('.finding-row').forEach((row, i) => {
    findings[i].masked = true;
    row.classList.add('checked');
    row.classList.remove('masked');
  });
  renderOutput();
}

function copyOutput() {
  const text = outputText.value;
  navigator.clipboard.writeText(text).then(() => {
    const orig = copyBtn.textContent;
    copyBtn.textContent = '✅ Copied!';
    copyBtn.classList.add('copied');
    setTimeout(() => {
      copyBtn.textContent = orig;
      copyBtn.classList.remove('copied');
    }, 2000);
  }).catch(() => {
    outputText.select();
    document.execCommand('copy');
  });
}

function clearAll() {
  inputText.value = '';
  inputText.classList.remove('has-findings');
  findingsSection.style.display = 'none';
  outputSection.style.display   = 'none';
  safeBanner.style.display      = 'none';
  findings = [];
}
