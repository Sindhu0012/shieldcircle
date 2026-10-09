require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { analyzeRules, LABELS } = require('./rules');

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const GROQ_API_KEY = process.env.GROQ_API_KEY;
const HINDSIGHT_API_KEY = process.env.HINDSIGHT_API_KEY;
const HINDSIGHT_ENDPOINT = (process.env.HINDSIGHT_ENDPOINT || 'https://api.hindsight.vectorize.io').replace(/\/$/, '');
const GROQ_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-120b';
const PORT = process.env.PORT || 3001;

const DATA_DIR = path.join(__dirname, 'data');
const PEOPLE_FILE = path.join(DATA_DIR, 'people.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const DRILLS_FILE = path.join(DATA_DIR, 'drills.json');
const LANGS = { en: 'English', te: 'Telugu', hi: 'Hindi' };
const SEVERITY = { 'LIKELY SAFE': 0, 'SUSPICIOUS': 1, 'SCAM': 2 };

// ---------- storage ----------
function ensureDataFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(PEOPLE_FILE)) {
    fs.writeFileSync(PEOPLE_FILE, JSON.stringify([
      { id: 'person_amma', name: 'Mom', relation: 'Mother' },
      { id: 'person_nana', name: 'Grandpa', relation: 'Grandfather' }
    ], null, 2));
  }
  if (!fs.existsSync(MESSAGES_FILE)) fs.writeFileSync(MESSAGES_FILE, '{}');
  if (!fs.existsSync(DRILLS_FILE)) fs.writeFileSync(DRILLS_FILE, '{}');
}
ensureDataFiles();

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf-8')); } catch { return fallback; }
}
const loadPeople = () => readJson(PEOPLE_FILE, []);
const savePeople = p => fs.writeFileSync(PEOPLE_FILE, JSON.stringify(p, null, 2));
const loadMessages = () => readJson(MESSAGES_FILE, {});
const saveMessages = m => fs.writeFileSync(MESSAGES_FILE, JSON.stringify(m, null, 2));
const loadDrills = () => readJson(DRILLS_FILE, {});
const saveDrills = d => fs.writeFileSync(DRILLS_FILE, JSON.stringify(d, null, 2));
const newId = prefix => prefix + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

// ---------- Hindsight (long-term memory) ----------
async function retainMemory(bankId, content) {
  if (!HINDSIGHT_API_KEY) return;
  const res = await fetch(`${HINDSIGHT_ENDPOINT}/v1/default/banks/${bankId}/memories`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${HINDSIGHT_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ items: [{ content }] })
  });
  if (!res.ok) throw new Error(`Hindsight retain ${res.status}: ${await res.text()}`);
}

async function recallMemory(bankId, query) {
  if (!HINDSIGHT_API_KEY) return [];
  const res = await fetch(`${HINDSIGHT_ENDPOINT}/v1/default/banks/${bankId}/memories/recall`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${HINDSIGHT_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query })
  });
  if (!res.ok) throw new Error(`Hindsight recall ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return (data.results || []).map(m => m.text).filter(Boolean);
}

// ---------- Groq ----------
async function askGroq(system, user, timeoutMs = 30000) {
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
    body: JSON.stringify({
      model: GROQ_MODEL,
      temperature: 0.4,
      messages: [{ role: 'system', content: system }, { role: 'user', content: user }]
    })
  });
  if (!res.ok) throw new Error(`Groq ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return data.choices[0].message.content || '';
}

function parseJson(text) {
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

// ---------- family memory insights (deterministic) ----------
function buildInsights(person, rules, people, messages) {
  const out = [];
  const mine = messages[person.id] || [];
  for (const cat of rules.categories) {
    const n = mine.filter(m => (m.categories || []).includes(cat)).length;
    if (n > 0) out.push(`Attempt #${n + 1} of this tactic on ${person.name}: "${LABELS[cat]}".`);
  }
  for (const other of people) {
    if (other.id === person.id) continue;
    const shared = rules.categories.filter(cat =>
      (messages[other.id] || []).some(m => (m.categories || []).includes(cat))
    );
    if (shared.length) {
      out.push(`A similar scam ("${LABELS[shared[0]]}") also targeted ${other.name}. Someone may be running a campaign against your family.`);
    }
  }
  return out.slice(0, 4);
}

function fallbackExplanation(rules) {
  if (!rules.flags.length) return 'No common scam signals were found in this message. Still, never share OTPs or PINs, and call the sender directly if unsure.';
  return `This message has ${rules.flags.length} scam warning sign(s): ${rules.flags.map(f => f.label.toLowerCase()).join('; ')}. Do not click links, pay money or share any codes.`;
}

function fallbackActions(level) {
  if (level === 'LIKELY SAFE') return ['Stay alert and never share OTPs or PINs.'];
  return [
    'Do not click any link or call any number in the message.',
    'Never share OTP, PIN or passwords with anyone.',
    'Call your bank or the sender on their official number to confirm.',
    'Report it at cybercrime.gov.in or call 1930.'
  ];
}

// ---------- people ----------
app.get('/api/people', (req, res) => {
  const messages = loadMessages();
  const drills = loadDrills();
  const people = loadPeople().map(p => {
    const list = messages[p.id] || [];
    const d = drills[p.id] || { played: 0, correct: 0 };
    return {
      ...p,
      checked: list.length,
      risky: list.filter(m => m.verdict !== 'LIKELY SAFE').length,
      played: d.played,
      iq: d.played ? Math.round((d.correct / d.played) * 100) : null
    };
  });
  res.json({ success: true, people });
});

app.post('/api/people', (req, res) => {
  const { name, relation } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'name is required' });
  const people = loadPeople();
  const person = { id: newId('person'), name: name.trim(), relation: (relation || '').trim() };
  people.push(person);
  savePeople(people);
  res.json({ success: true, person });
});

app.delete('/api/people/:id', (req, res) => {
  const people = loadPeople();
  const filtered = people.filter(p => p.id !== req.params.id);
  if (filtered.length === people.length) return res.status(404).json({ error: 'Person not found' });
  savePeople(filtered);
  const messages = loadMessages();
  delete messages[req.params.id];
  saveMessages(messages);
  const drills = loadDrills();
  delete drills[req.params.id];
  saveDrills(drills);
  res.json({ success: true });
});

app.get('/api/people/:id/messages', (req, res) => {
  res.json({ success: true, messages: loadMessages()[req.params.id] || [] });
});

// ---------- core: analyze ----------
app.post('/api/analyze', async (req, res) => {
  try {
    const { personId, message, language = 'en' } = req.body;
    if (!personId || !message || !message.trim()) {
      return res.status(400).json({ error: 'personId and message are required' });
    }
    const people = loadPeople();
    const person = people.find(p => p.id === personId);
    if (!person) return res.status(404).json({ error: 'Person not found' });

    const messages = loadMessages();
    const rules = analyzeRules(message);
    const insights = buildInsights(person, rules, people, messages);

    let recalled = [];
    try {
      recalled = await recallMemory(personId, `Scam messages and tactics that targeted ${person.name}`);
    } catch (e) { console.warn('Hindsight recall skipped:', e.message); }

    let ai = null;
    try {
      const langName = LANGS[language] || 'English';
      const system = `You are ShieldCircle, a scam-protection assistant for Indian families. A rule engine already scanned the message. Verify its findings and explain in very simple words an elderly, non-technical person understands. Use the family history if given. Respond with ONLY a JSON object, no markdown, in this exact shape:
{"verdict":"SCAM" | "SUSPICIOUS" | "LIKELY SAFE","scam_type":"short name of the scam type, or 'None'","explanation":"max 60 words, written in ${langName}","what_to_do":["up to 3 short action steps, written in ${langName}"]}`;
      const user = `Person being protected: ${person.name} (${person.relation || 'family member'})

Message:
"""${message}"""

Rule engine risk score: ${rules.score}/100 (${rules.level})
Red flags found: ${rules.flags.map(f => f.label).join('; ') || 'none'}
Link checks: ${rules.links.map(l => `${l.host}: ${l.issues.join(', ') || 'no issues'}`).join(' | ') || 'no links'}
Family memory insights: ${insights.join(' ') || 'none yet'}
Past memories recalled from long-term memory: ${recalled.slice(0, 5).join(' || ') || 'none'}`;
      ai = parseJson(await askGroq(system, user));
    } catch (e) { console.warn('Groq skipped:', e.message); }

    const aiVerdict = ai && SEVERITY[ai.verdict] !== undefined ? ai.verdict : null;
    const verdict = aiVerdict && SEVERITY[aiVerdict] > SEVERITY[rules.level] ? aiVerdict : rules.level;
    const floor = verdict === 'SCAM' ? 70 : verdict === 'SUSPICIOUS' ? 40 : 0;
    const riskScore = Math.max(rules.score, floor);

    const explanation = (ai && ai.explanation) || fallbackExplanation(rules);
    const whatToDo = (ai && Array.isArray(ai.what_to_do) && ai.what_to_do.length ? ai.what_to_do : fallbackActions(verdict)).slice(0, 4);
    const scamType = (ai && ai.scam_type && ai.scam_type !== 'None') ? ai.scam_type : (rules.flags[0] ? rules.flags[0].label : '');

    const entry = {
      id: newId('msg'),
      text: message,
      timestamp: new Date().toISOString(),
      verdict, riskScore, scamType, explanation,
      categories: rules.categories,
      flags: rules.flags.map(f => f.label),
      links: rules.links.map(l => l.url)
    };
    if (!messages[personId]) messages[personId] = [];
    messages[personId].unshift(entry);
    saveMessages(messages);

    retainMemory(personId, `${person.name} received a message (${verdict}, tactics: ${rules.flags.map(f => f.label).join(', ') || 'none'}): "${message}"`)
      .catch(e => console.warn('Hindsight retain skipped:', e.message));

    res.json({
      success: true, messageId: entry.id, verdict, riskScore, scamType, explanation, whatToDo,
      flags: rules.flags, links: rules.links, insights,
      memory: { hindsightRecalled: recalled.length, familyMatches: insights.length },
      aiUsed: !!ai
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- complaint draft ----------
app.post('/api/report', (req, res) => {
  const { personId, messageId } = req.body;
  const person = loadPeople().find(p => p.id === personId);
  const entry = ((loadMessages()[personId]) || []).find(m => m.id === messageId);
  if (!person || !entry) return res.status(404).json({ error: 'Message not found' });
  const when = new Date(entry.timestamp).toLocaleString('en-IN');
  const text = `DRAFT COMPLAINT: ONLINE FRAUD ATTEMPT
(Prepared with ShieldCircle. Review and edit before filing.)

Date and time received: ${when}
Received by: ${person.name}${person.relation ? ' (' + person.relation + ')' : ''}
Type of fraud: ${entry.scamType || entry.verdict}
Assessment: ${entry.verdict}, risk score ${entry.riskScore}/100

Message received:
"${entry.text}"

Warning signs detected:
${(entry.flags || []).map(f => '- ' + f).join('\n') || '- None recorded'}

Suspicious links in the message:
${(entry.links || []).map(l => '- ' + l).join('\n') || '- None'}

Financial loss: None reported (attempt only). EDIT THIS if any money was sent.

Request: Please register this complaint and take action against the sender and any linked websites or numbers.

HOW TO FILE
1. If money was lost, call 1930 (National Cyber Crime Helpline) immediately.
2. File the complaint at https://cybercrime.gov.in
3. Keep screenshots of the message and the sender's number.`;
  res.json({ success: true, text });
});

// ---------- scam drill ----------
const DRILL_BANK = [
  { text: 'SBI ALERT: Your account is blocked. Update KYC now at http://sbi-update-kyc.top or lose access today.', isScam: true, why: 'Real banks never block accounts by SMS link. A website ending in .top is not SBI.' },
  { text: 'Sir, this is Mumbai Cyber Police. Your Aadhaar is linked to a drug parcel. Stay on video call and transfer Rs 80000 for verification.', isScam: true, why: 'Police never arrest anyone on a video call or ask for money. "Digital arrest" does not exist in law.' },
  { text: 'Hi Mom, reached the station. Will be home in 20 minutes. Need anything from the shop?', isScam: false, why: 'A normal family message: no links, no money, no urgency.' },
  { text: 'Dear consumer, your electricity will be disconnected tonight at 9:30 pm. Call 9876543210 immediately to update your bill.', isScam: true, why: 'Electricity boards do not cut power through random mobile numbers. Scammers want you to call and pay.' },
  { text: 'Your Amazon order has been shipped and will arrive on Saturday. Track it in the Amazon app.', isScam: false, why: 'No link, no payment, no pressure. It tells you to use the official app.' },
  { text: 'Congratulations! You won Rs 25 lakh in a lucky draw. Pay Rs 5000 processing fee via UPI to claim your prize.', isScam: true, why: 'You cannot win a lottery you never entered, and real prizes never ask for a fee first.' },
  { text: 'Earn Rs 4000 per day from home! Just like YouTube videos. Join Telegram: https://bit.ly/easy-earn-now', isScam: true, why: 'Easy daily income for liking videos is a known fraud. The short link hides the real website.' },
  { text: 'Your OTP for the transaction of Rs 450 is 482913. Do not share it with anyone. - HDFC Bank', isScam: false, why: 'This OTP is for a payment you made yourself. It is only dangerous if someone asks you to read it out.' },
  { text: 'Download this app to complete your KYC: http://kyc-help.xyz/support.apk', isScam: true, why: 'Banks never send app files (APK) to install. These apps steal your messages and money.' },
  { text: 'Sir I am from your bank. Please install AnyDesk so I can fix your account problem quickly.', isScam: true, why: 'AnyDesk gives the caller full control of your phone. Banks never ask for it.' },
  { text: 'Reminder: Dr. Rao appointment tomorrow at 5 pm. Please arrive 10 minutes early.', isScam: false, why: 'Looks like a normal appointment reminder: no links, no payment, no pressure.' }
];

const DRILL_TYPES = ['fake bank KYC update', 'digital arrest by fake police', 'electricity bill disconnection threat', 'fake work-from-home job', 'fake courier or parcel problem', 'lottery or prize fee', 'fake UPI refund', 'fake government subsidy'];

async function generateDrill() {
  const isScam = Math.random() < 0.65;
  const type = DRILL_TYPES[Math.floor(Math.random() * DRILL_TYPES.length)];
  const system = 'You create short training examples that help Indian families learn to recognise scam messages. Respond with ONLY a JSON object, no markdown.';
  const user = isScam
    ? `Write ONE realistic SMS or WhatsApp message of this scam type: ${type}. Max 40 words. Use fictional names, numbers and websites only. Reply as {"text":"the message","why":"one simple sentence explaining why it is a scam, in words a grandparent understands"}`
    : `Write ONE realistic, completely legitimate SMS or WhatsApp message an Indian family might receive (family chat, appointment reminder, or normal delivery update with no links and no payment request). Max 40 words. Reply as {"text":"the message","why":"one simple sentence explaining why it is safe, in words a grandparent understands"}`;
  const out = parseJson(await askGroq(system, user, 9000));
  if (!out || typeof out.text !== 'string' || typeof out.why !== 'string' || out.text.length < 10 || out.text.length > 400) return null;
  return { text: out.text, why: out.why, isScam };
}

app.get('/api/drill/next', async (req, res) => {
  let item = null;
  let source = 'ai';
  if (GROQ_API_KEY && Math.random() < 0.6) {
    try { item = await generateDrill(); } catch (e) { console.warn('Drill generation skipped:', e.message); }
  }
  if (!item) {
    item = DRILL_BANK[Math.floor(Math.random() * DRILL_BANK.length)];
    source = 'bank';
  }
  const rules = analyzeRules(item.text);
  res.json({
    success: true, text: item.text, isScam: item.isScam, why: item.why, source,
    flags: item.isScam ? rules.flags.map(f => f.label) : []
  });
});

app.post('/api/drill/result', (req, res) => {
  const { personId, correct } = req.body;
  if (!personId) return res.status(400).json({ error: 'personId is required' });
  const drills = loadDrills();
  const d = drills[personId] || { played: 0, correct: 0 };
  d.played += 1;
  if (correct) d.correct += 1;
  drills[personId] = d;
  saveDrills(drills);
  res.json({ success: true, played: d.played, iq: Math.round((d.correct / d.played) * 100) });
});

// ---------- dashboard ----------
app.get('/api/dashboard', (req, res) => {
  const people = loadPeople();
  const messages = loadMessages();
  const all = Object.values(messages).flat();
  const byCategory = {};
  all.forEach(m => (m.categories || []).forEach(c => { byCategory[c] = (byCategory[c] || 0) + 1; }));

  const perPerson = people.map(p => {
    const list = messages[p.id] || [];
    return { id: p.id, name: p.name, relation: p.relation, count: list.length, risky: list.filter(m => m.verdict !== 'LIKELY SAFE').length };
  });

  res.json({
    success: true,
    totalChecked: all.length,
    scamsCaught: all.filter(m => m.verdict === 'SCAM').length,
    suspicious: all.filter(m => m.verdict === 'SUSPICIOUS').length,
    members: people.length,
    tactics: Object.entries(byCategory).map(([key, count]) => ({ key, label: LABELS[key] || key, count })).sort((a, b) => b.count - a.count),
    needsConversation: perPerson.filter(p => p.risky >= 3).sort((a, b) => b.risky - a.risky)
  });
});

// ---------- demo helpers ----------
const SEEDS = [
  { personId: 'person_amma', text: 'Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc-verify.xyz/login', daysAgo: 6 },
  { personId: 'person_amma', text: 'Your PAN card will expire. Update PAN immediately to avoid account suspension: https://bit.ly/pan-update-now', daysAgo: 3 },
  { personId: 'person_nana', text: 'This is CBI. A parcel in your name was seized by customs with illegal items. You are under digital arrest. Do not disconnect the video call.', daysAgo: 2 },
  { personId: 'person_nana', text: 'Congratulations! You won a lottery prize of Rs 25,00,000. Pay processing fee Rs 5000 via UPI to claim.', daysAgo: 1 }
];

app.post('/api/seed', (req, res) => {
  const people = loadPeople();
  const messages = loadMessages();
  for (const s of SEEDS) {
    if (!people.find(p => p.id === s.personId)) continue;
    const rules = analyzeRules(s.text);
    const list = (messages[s.personId] || []).filter(m => !m.seeded || m.text !== s.text);
    list.push({
      id: newId('msg'), seeded: true, text: s.text,
      timestamp: new Date(Date.now() - s.daysAgo * 86400000).toISOString(),
      verdict: rules.level, riskScore: rules.score,
      scamType: rules.flags[0] ? rules.flags[0].label : '',
      explanation: fallbackExplanation(rules),
      categories: rules.categories, flags: rules.flags.map(f => f.label),
      links: rules.links.map(l => l.url)
    });
    list.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    messages[s.personId] = list;
  }
  saveMessages(messages);
  res.json({ success: true });
});

app.post('/api/reset', (req, res) => {
  saveMessages({});
  saveDrills({});
  res.json({ success: true });
});

app.get('/api/health', (req, res) => res.json({ status: 'ShieldCircle server is running' }));

app.listen(PORT, () => console.log(`ShieldCircle server running on http://localhost:${PORT}`));