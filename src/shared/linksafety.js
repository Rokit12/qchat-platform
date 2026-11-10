// On-device phishing & scam detection. Messages are end-to-end encrypted, so the server can't scan
// them (and shouldn't). Everything here runs locally; nothing about the link is sent anywhere.

export const URL_RE = /\b((?:https?:\/\/|www\.)[^\s<>"']+[^\s<>"'.,;:!?)\]])/gi;

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 'lnkd.in', 'bl.ink', 'short.io', 'v.gd', 's.id', 'qr.ae', 'shorte.st', 'adf.ly', 'bitly.com', 'linktr.ee']);
const RISKY_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'rest', 'icu', 'cam', 'quest', 'loan', 'men', 'kim', 'fit', 'bid', 'party', 'review', 'win', 'download', 'stream', 'monster', 'lol', 'sbs', 'cfd', 'buzz', 'cyou', 'bond', 'skin', 'hair', 'mom', 'beauty', 'live', 'shop']);
const TWO_LEVEL = new Set(['co.uk', 'co.ke', 'or.ke', 'go.ke', 'ac.ke', 'co.za', 'com.au', 'co.jp', 'co.in', 'com.br', 'com.ng', 'co.nz', 'com.mx', 'co.tz', 'co.ug', 'com.gh', 'gov.uk', 'ac.uk', 'org.uk', 'com.tr', 'com.sg']);
// brand → official registrable domains
const BRANDS = {
  paypal: ['paypal.com', 'paypal.me'], apple: ['apple.com', 'icloud.com'], icloud: ['icloud.com', 'apple.com'], google: ['google.com', 'youtube.com', 'goo.gl', 'g.co', 'gmail.com'],
  gmail: ['gmail.com', 'google.com'], microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com'], outlook: ['outlook.com', 'live.com', 'microsoft.com'],
  office365: ['office.com', 'microsoft.com'], amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amzn.to'], netflix: ['netflix.com'], facebook: ['facebook.com', 'fb.com', 'fb.me'],
  instagram: ['instagram.com'], whatsapp: ['whatsapp.com', 'whatsapp.net', 'wa.me'], telegram: ['telegram.org', 't.me'], tiktok: ['tiktok.com'], twitter: ['twitter.com', 'x.com', 't.co'],
  linkedin: ['linkedin.com', 'lnkd.in'], coinbase: ['coinbase.com'], binance: ['binance.com'], metamask: ['metamask.io'], trustwallet: ['trustwallet.com'], blockchain: ['blockchain.com'],
  chase: ['chase.com'], wellsfargo: ['wellsfargo.com'], bankofamerica: ['bankofamerica.com'], citibank: ['citi.com', 'citibank.com'], hsbc: ['hsbc.com', 'hsbc.co.uk'],
  dhl: ['dhl.com'], fedex: ['fedex.com'], usps: ['usps.com'], ups: ['ups.com'], irs: ['irs.gov'], steam: ['steampowered.com', 'steamcommunity.com'], roblox: ['roblox.com'],
  mpesa: ['safaricom.co.ke'], safaricom: ['safaricom.co.ke'], equitybank: ['equitybankgroup.com', 'equitybank.co.ke'], kcb: ['kcbgroup.com'], docusign: ['docusign.com', 'docusign.net'],
  dropbox: ['dropbox.com'], adobe: ['adobe.com'], qchat: [],
};
const BRAND_NAMES = { paypal: 'PayPal', icloud: 'iCloud', mpesa: 'M-Pesa', linkedin: 'LinkedIn', tiktok: 'TikTok', whatsapp: 'WhatsApp', bankofamerica: 'Bank of America', wellsfargo: 'Wells Fargo', metamask: 'MetaMask', trustwallet: 'Trust Wallet', docusign: 'DocuSign', equitybank: 'Equity Bank', kcb: 'KCB', dhl: 'DHL', usps: 'USPS', ups: 'UPS', irs: 'IRS', hsbc: 'HSBC', office365: 'Office 365', fedex: 'FedEx', qchat: 'QChat', citibank: 'Citibank' };
const CRED_WORDS = /(log-?in|sign-?in|verif|account|secure|update|wallet|password|passcode|otp|recover|seed|unlock|suspend|confirm|validate|billing|payment|refund|prize|winner|claim|gift|bonus|airdrop|kyc)/i;
const DANGEROUS_EXT = /\.(exe|scr|bat|cmd|com|pif|msi|msp|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|jar|apk|xapk|aab|ipa|dmg|pkg|app|deb|rpm|run|sh|lnk|reg|hta|cpl|dll|iso|img|vhd|xll|docm|xlsm|pptm)$/i;
const CAUTION_EXT = /\.(html?|svg|xhtml|mht|zip|rar|7z|gz|tar|pdf\.\w+)$/i;

const deleet = (s) => s.toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/\$/g, 's').replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[-_.]/g, '');
export function registrableDomain(host) {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join('.');
  return TWO_LEVEL.has(last2) ? parts.slice(-3).join('.') : last2;
}

/** Analyse a URL. ctx.stranger: sender is not someone you chat with. Returns {level, score, host, reasons[]} */
export function analyzeUrl(raw, ctx = {}) {
  let u;
  const href = /^www\./i.test(raw) ? 'https://' + raw : raw;
  try { u = new URL(href); } catch { return { level: 'danger', score: 9, host: '', href, reasons: ['Malformed link'] }; }
  if (!['http:', 'https:'].includes(u.protocol)) return { level: 'danger', score: 9, host: u.protocol, href, reasons: ['Unsafe link type (' + u.protocol + ')'] };
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  const reasons = []; let score = 0;
  const add = (pts, why) => { score += pts; reasons.push(why); };
  const reg = registrableDomain(host);
  if (u.username || u.password || /@/.test(href.split('/')[2] || '')) add(4, 'Hides its real destination using “@” in the address');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':') || /^\[/.test(host)) add(3, 'Uses a raw IP address instead of a website name');
  if (host.split('.').some((l) => l.startsWith('xn--'))) add(4, 'Uses look-alike international characters (possible fake of a real site)');
  for (const [brand, official] of Object.entries(BRANDS)) {
    if (official.some((d) => reg === d || host === d || host.endsWith('.' + d))) continue;
    const name = BRAND_NAMES[brand] || brand[0].toUpperCase() + brand.slice(1);
    if (!host.replace(/[-_.]/g, '').includes(brand) && deleet(host).includes(brand)) { add(5, `Look-alike spelling of ${name} (typosquatting) — really goes to ${reg}`); break; }
    if (host.includes(brand)) { add(3, `Uses the name ${name} but isn't an official ${name} website (${reg})`); break; }
  }
  if (SHORTENERS.has(host) || SHORTENERS.has(reg)) add(2, 'Link shortener hides where it really goes');
  const tld = host.split('.').pop();
  if (RISKY_TLDS.has(tld)) add(tld === 'zip' || tld === 'mov' ? 3 : 1, `“.${tld}” domains are frequently used in scams`);
  if (u.protocol === 'http:') add(1, 'Not encrypted (http instead of https)');
  if (host.split('.').length > 4) add(1, 'Unusually many sub-domains');
  if (host.length > 40) add(1, 'Very long website name');
  if ((host.match(/-/g) || []).length >= 3) add(1, 'Many hyphens in the website name');
  if (CRED_WORDS.test(host + u.pathname)) add(1, 'Asks you to log in, verify or claim something');
  if (DANGEROUS_EXT.test(u.pathname)) add(4, 'Downloads a program or app installer');
  if (ctx.stranger) add(1, 'Sent by someone you haven’t chatted with before');
  const level = score >= 4 ? 'danger' : score >= 1 ? 'caution' : 'ok';
  return { level, score, host, reg, href: u.href, reasons };
}

export function extractUrls(text) { return [...String(text || '').matchAll(URL_RE)].map((m) => m[1]); }

/** Social-engineering patterns in a received message. */
export function analyzeMessage(text) {
  const t = String(text || '');
  const asksForSecrets = /(send|share|give|tell|forward|enter|type|confirm|read|provide|need)\b.{0,50}\b(recovery key|recovery phrase|pass ?code|password|verification code|login code|security code|otp|one[- ]time (code|password|pin)|seed phrase|private key|pin\b|qc1-)/i.test(t)
    || /\bwhat('?s| is) your (pass ?code|password|recovery key|pin|code)\b/i.test(t);
  const claimsOfficial = /\b(q ?chat|whatsapp) (support|team|security|admin|staff|official|help ?desk)\b/i.test(t) || /\bofficial (q ?chat|support) (account|team)\b/i.test(t);
  const urgency = /\b(urgent|immediately|within 24 ?h(ours)?|account (will be )?(suspended|closed|locked|deleted)|act now|final (notice|warning))\b/i.test(t);
  return { asksForSecrets, claimsOfficial, urgency, risky: asksForSecrets || claimsOfficial };
}
export const containsRecoveryKey = (text) => /QC1-[A-Za-z0-9_-]{40,}/.test(String(text || ''));
export function analyzeFile(name, mime = '') {
  const n = String(name || '').toLowerCase();
  if (DANGEROUS_EXT.test(n) || /application\/(x-msdownload|x-msdos-program|vnd\.android\.package-archive|x-sh)/.test(mime)) return { level: 'danger', reason: 'Program or installer — it can take over your device. Only open it if you were expecting it.' };
  if (/\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.\w{2,4}$/.test(n) && !/\.(pdf|docx?|xlsx?|jpe?g|png|txt)$/.test(n)) return { level: 'danger', reason: 'Double file extension — it pretends to be a document.' };
  if (CAUTION_EXT.test(n)) return { level: 'caution', reason: 'Archives and web pages can hide harmful content.' };
  return { level: 'ok' };
}
