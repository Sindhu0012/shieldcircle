// ShieldCircle rule engine: deterministic scam signal detection (India-focused)

const RULES = {
  credentials: {
    label: 'Asks for OTP / PIN / password',
    weight: 35,
    re: /\b(otp|one[\s-]?time\s*(password|code|pin)|cvv|upi\s*pin|atm\s*pin|passcode|share (your )?(pin|password))\b/i
  },
  payment: {
    label: 'Asks for money / UPI payment',
    weight: 20,
    re: /\b(upi|phonepe|gpay|google\s*pay|paytm|bhim|collect request|scan (the |this )?qr|send (me )?(money|rs\.?|₹)\s*\d*|processing fee|registration fee|refundable|security deposit|pay (₹|rs\.?)?\s*\d|transfer (₹|rs\.?)?\s*\d)/i
  },
  kyc: {
    label: 'Fake KYC / account-blocked threat',
    weight: 30,
    re: /\b(kyc|pan\s*(card)?\s*(update|link|expire|expiry)|aadhaar\s*(update|link)|account\s*(will\s*be\s*)?(blocked|suspended|frozen|deactivated|closed)|card\s*(will\s*be\s*)?blocked|sim\s*(will\s*be\s*)?(blocked|deactivated))\b/i
  },
  authority: {
    label: 'Impersonates police / govt authority (digital arrest)',
    weight: 30,
    re: /\b(cbi|police|customs|narcotics|ncb|enforcement directorate|trai|cyber\s*crime|court|warrant|arrest(ed)?|digital arrest|income tax|rbi)\b/i
  },
  urgency: {
    label: 'Creates urgency / panic',
    weight: 15,
    re: /\b(urgent(ly)?|immediately|right now|within \d+\s*(hours?|hrs?|minutes?|mins?)|last chance|act now|expires? (today|soon)|final (notice|warning)|today only|tonight)\b/i
  },
  prize: {
    label: 'Fake prize / lottery / cashback',
    weight: 25,
    re: /\b(lottery|lucky draw|you (have )?won|congratulations|prize|winner|cashback|reward points|free gift)\b/i
  },
  jobscam: {
    label: 'Fake work-from-home / task job',
    weight: 25,
    re: /\b(work from home|part[\s-]?time job|earn\s*(₹|rs\.?)?\s*\d|per day|daily income|like (and )?subscribe|telegram (group|channel)|youtube (like|task))\b/i
  },
  remote: {
    label: 'Asks to install remote-access app',
    weight: 40,
    re: /\b(anydesk|teamviewer|quicksupport|rustdesk|screen\s*share|remote access)\b/i
  },
  apk: {
    label: 'Asks to install an APK / unknown app',
    weight: 35,
    re: /\.apk\b|\bapk\b|install (this|the) app/i
  },
  delivery: {
    label: 'Fake parcel / courier problem',
    weight: 20,
    re: /\b(parcel|courier|fedex|dhl|blue\s*dart|customs duty|package (is )?(held|stuck|seized)|delivery (failed|attempt))\b/i
  },
  utility: {
    label: 'Fake electricity / utility disconnection',
    weight: 25,
    re: /(electricity|power|gas|water).{0,40}(disconnect|cut off|suspended|terminated)/i
  },
  impersonation: {
    label: 'Family impersonation / "new number" trick',
    weight: 25,
    re: /\b(this is my new (number|phone)|lost my phone|changed my number|my new number|new number)\b/i
  },
  injection: {
    label: 'Tries to manipulate AI scanners (prompt injection)',
    weight: 45,
    re: /\b(ignore (all |any )?(the )?(previous|prior|above) (instructions|rules)|disregard (the )?(above|previous)|system prompt|you are now|mark (this|it) as (safe|legit)|verdict\s*:?\s*(safe|likely safe))\b/i
  }
};

const LABELS = Object.fromEntries(Object.entries(RULES).map(([k, v]) => [k, v.label]));
LABELS.links = 'Suspicious link';

const BRANDS = {
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in'],
  hdfc: ['hdfcbank.com'],
  icici: ['icicibank.com'],
  axis: ['axisbank.com'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  amazon: ['amazon.in', 'amazon.com'],
  flipkart: ['flipkart.com'],
  irctc: ['irctc.co.in'],
  uidai: ['uidai.gov.in'],
  incometax: ['incometax.gov.in'],
  epfo: ['epfindia.gov.in'],
  jio: ['jio.com'],
  airtel: ['airtel.in']
};

const SHORTENERS = /^(bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|t\.ly|t\.co)$/i;
const BAD_TLD = /\.(xyz|top|click|live|icu|site|online|link|buzz|cfd|sbs|vip|monster)$/i;
const LINK_RE = /\b(?:https?:\/\/|www\.)[^\s<>"')]+|\b(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|t\.ly)\/[^\s<>"')]+/gi;

function hostOf(u) {
  return u.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split(/[\/?#:]/)[0].toLowerCase();
}

function checkLink(url) {
  const host = hostOf(url);
  const issues = [];
  let penalty = 0;
  if (SHORTENERS.test(host)) { issues.push('Shortened link hides the real destination'); penalty += 25; }
  if (/^http:\/\//i.test(url)) { issues.push('Not secure (http, not https)'); penalty += 10; }
  if (BAD_TLD.test(host)) { issues.push('Unusual domain ending often used in scams'); penalty += 20; }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { issues.push('Link goes to a raw IP address'); penalty += 25; }
  for (const [brand, officials] of Object.entries(BRANDS)) {
    if (host.includes(brand)) {
      const official = officials.some(d => host === d || host.endsWith('.' + d));
      if (!official) {
        issues.push(`Pretends to be "${brand}" but is not its official website`);
        penalty += 30;
      }
      break;
    }
  }
  return { url, host, issues, penalty };
}

function analyzeRules(text) {
  const categories = [];
  const flags = [];
  let score = 0;

  for (const [key, rule] of Object.entries(RULES)) {
    if (rule.re.test(text)) {
      categories.push(key);
      flags.push({ key, label: rule.label, weight: rule.weight });
      score += rule.weight;
    }
  }

  const found = (text.match(LINK_RE) || []).map(checkLink);
  const links = found.map(l => ({ url: l.url, host: l.host, issues: l.issues }));
  const linkPenalty = Math.min(40, found.reduce((s, l) => s + l.penalty, 0));
  if (linkPenalty > 0) {
    categories.push('links');
    flags.push({ key: 'links', label: LABELS.links, weight: linkPenalty });
    score += linkPenalty;
  }

  if (categories.length >= 3) score += 10; // several red flags together

  score = Math.min(100, score);
  const level = score >= 60 ? 'SCAM' : score >= 30 ? 'SUSPICIOUS' : 'LIKELY SAFE';
  return { score, level, categories, flags, links };
}

module.exports = { analyzeRules, LABELS };