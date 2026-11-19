/**
 * Rule-based scam detector for ScamShield.
 *
 * Fast, free and explainable. It works on its own (no API key needed) and also
 * feeds its findings to the AI step as hints. Every rule explains itself in plain
 * language so people who are not tech-savvy understand WHY a message looks risky.
 */

import { extractUrls, analyzeUrl } from './urlTools.js';

const MAX_CHARS = 5000;
const SCAM_THRESHOLD = 50;
const SUSPICIOUS_THRESHOLD = 20;
const URL_WEIGHT_CAP = 60;

// ---- small matching helpers (all regexes are non-global, so no lastIndex surprises) ----

const first = (...patterns) => (text) => {
  for (const re of patterns) {
    const m = re.exec(text);
    if (m) return { start: m.index, end: m.index + m[0].length };
  }
  return null;
};

const both = (a, b) => (text) => {
  const m1 = a.exec(text);
  return m1 && b.test(text) ? { start: m1.index, end: m1.index + m1[0].length } : null;
};

const SECRET =
  '(?:otp|one[- ]time (?:password|code|pin)|pin(?: number| code)?|passcode|password|cvv|cvc|security code|verification code|token|bvn|seed phrase|recovery phrase|secret phrase|private key|card number)';

const SECRET_REQUESTS = [
  new RegExp(
    `\\b(?:send|share|give|provide|tell|read out|forward|reply with|text me|whatsapp me)\\b[^.\\n]{0,40}?\\b${SECRET}\\b`,
    'gi'
  ),
  new RegExp(
    `\\b(?:i need|we need|need your|what is your|what's your|kindly provide)\\b[^.\\n]{0,20}\\b${SECRET}\\b`,
    'gi'
  ),
  /\b(?:send|share|give|read out|forward|tell)\b[^.\n]{0,30}\bcode\b[^.\n]{0,25}\b(?:sent|received|texted|got)\b/gi,
];
const NEGATION = /\b(?:do not|don'?t|dont|never|not|no one|nobody|won'?t|will not|cannot|can'?t)\b/i;

// "Share your OTP" is a red flag, but "Do not share your OTP" is a normal bank warning.
function detectSecretRequest(text) {
  for (const re of SECRET_REQUESTS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const lead = text.slice(Math.max(0, m.index - 40), m.index + 8);
      if (!NEGATION.test(lead)) return { start: m.index, end: m.index + m[0].length };
    }
  }
  return null;
}

function detectShouting(text) {
  const letters = text.replace(/[^A-Za-z]/g, '');
  if (letters.length >= 25 && letters.replace(/[^A-Z]/g, '').length / letters.length > 0.6) {
    return { start: null, end: null };
  }
  return /[!?]{3,}/.test(text) ? { start: null, end: null } : null;
}

// ---- the rules ----

const RULES = [
  {
    id: 'urgency', category: 'pressure', weight: 15,
    title: 'Pressures you to act fast',
    detail: 'Scammers create a rush so you do not stop to think or check.',
    detect: first(
      /\b(?:urgent(?:ly)?|immediately|right away|act now|act fast|asap|hurry)\b/i,
      /\bwithin (?:the next )?\d+\s*(?:hours?|hrs?|minutes?|mins?)\b/i,
      /\b(?:final|last) (?:warning|notice|reminder|chance)\b/i,
      /\bexpir(?:es|ing|ed) (?:today|tonight|soon|now)\b/i,
      /\b(?:before|or) (?:it(?:'s| is) )?too late\b/i
    ),
  },
  {
    id: 'threat', category: 'pressure', weight: 12,
    title: 'Threatens you or your account',
    detail: 'Threats of blocked accounts, arrest or legal action are used to scare people into obeying.',
    detect: first(
      /\b(?:account|card|sim|line|number|wallet)\b[^.\n]{0,30}\b(?:suspended|blocked|locked|deactivated|closed|limited|compromised|terminated)\b/i,
      /\b(?:legal action|arrest(?:ed)?|prosecut\w*|warrant|lawsuit)\b/i
    ),
  },
  {
    id: 'credentials', category: 'credentials', weight: 25,
    type: 'Phishing (stealing your login or bank details)',
    title: 'Asks you to verify or update your details',
    detail: 'Real companies rarely ask you to confirm passwords, PINs or bank details through a message.',
    detect: first(
      /\b(?:verify|confirm|validate|update|re-?activate|restore|unlock|secure)\b[^.\n]{0,25}\b(?:account|identity|details|information|info|password|pin|bvn|nin|card|billing|payment|profile|wallet|login|credentials)\b/i,
      /\b(?:log ?in|sign ?in)\b[^.\n]{0,30}\b(?:to (?:verify|confirm|secure|restore|unlock|avoid|keep)|now|immediately)\b/i
    ),
  },
  {
    id: 'secret_request', category: 'credentials', weight: 30,
    type: 'Code or PIN theft',
    title: 'Asks you to share a code, PIN or password',
    detail: 'No real bank or company will ever ask you to send them your OTP, PIN or password.',
    detect: detectSecretRequest,
  },
  {
    id: 'click_prompt', category: 'links', weight: 10,
    title: 'Pushes you to tap a link',
    detail: 'Scam messages try to get you onto a fake website as quickly as possible.',
    detect: first(
      /\b(?:click|tap|open|follow|visit|go to)\b[^.\n]{0,25}\b(?:link|here|below|url|website|site|page)\b/i,
      /\bclick (?:now|here)\b/i
    ),
  },
  {
    id: 'payment_request', category: 'money', weight: 20,
    type: 'Upfront payment scam',
    title: 'Asks you to send money or pay a fee',
    detail: 'Being asked to pay a fee or send money first, to receive something, is a classic scam.',
    detect: first(
      /\b(?:pay|send|transfer|deposit|remit)\b[^.\n]{0,40}\b(?:fees?|charges?|tax|duty|duties|deposit|clearance|processing|registration|activation|release|insurance|shipping|delivery)\b/i,
      /\b(?:send|transfer|wire|lend)\b[^.\n]{0,20}\b(?:money|cash|funds|airtime|data)\b/i,
      /\b(?:send|transfer|wire|lend)\b[^.\n]{0,20}[₦$£€]\s?\d/i,
      /\b(?:account number|bank details|routing number|iban|sort code)\b/i
    ),
  },
  {
    id: 'gift_card', category: 'money', weight: 25,
    type: 'Gift card scam',
    title: 'Asks for gift cards',
    detail: 'Only scammers ask to be paid in gift cards, because they cannot be traced or refunded.',
    detect: first(/\b(?:gift ?cards?|itunes cards?|google play cards?|steam cards?|amazon cards?)\b/i),
  },
  {
    id: 'crypto_wire', category: 'money', weight: 15,
    title: 'Mentions hard-to-trace payment methods',
    detail: 'Bitcoin, crypto and wire services are favourites of scammers because the money cannot be recovered.',
    detect: first(/\b(?:western union|moneygram|wire transfer|bitcoin|btc|usdt|crypto(?:currency)?|ethereum)\b/i),
  },
  {
    id: 'prize', category: 'bait', weight: 25,
    type: 'Fake prize or lottery',
    title: 'Says you won something',
    detail: 'You cannot win a contest you never entered. Prize messages are bait for your details or money.',
    detect: first(
      /\byou(?:'ve| have)? (?:been )?(?:won|selected|chosen)\b/i,
      /\byou(?:'re| are| were)? (?:a |the )?(?:lucky )?winner\b/i,
      /\b(?:lottery|jackpot|raffle)\b/i,
      /\bcongratulations?\b[^.\n]{0,60}\b(?:won|win|selected|chosen|prize|reward|gift)\b/i,
      /\bclaim (?:your|the)\b[^.\n]{0,20}\b(?:prize|reward|gift|winnings|bonus|refund)\b/i,
      /\bfree (?:iphone|laptop|gift|data|airtime|money|cash)\b/i
    ),
  },
  {
    id: 'job_scam', category: 'bait', weight: 15,
    type: 'Fake job offer',
    title: 'Offers easy money or a too-good job',
    detail: 'Fake job offers promise high pay for little work and later ask for fees or personal details.',
    detect: first(
      /\b(?:work[- ]from[- ]home|remote job|part[- ]time job|online job)\b/i,
      /[$₦£€]\s?\d[\d,]*(?:\.\d+)?\s*(?:k|m)?\s*(?:per|a|\/)\s*(?:day|week|hour)\b/i,
      /\bno experience (?:needed|required|necessary)\b/i,
      /\b(?:daily|weekly) (?:pay|payment|income|salary)\b/i
    ),
  },
  {
    id: 'advance_fee', category: 'bait', weight: 25,
    type: 'Advance-fee scam',
    title: 'Promises a large sum of money',
    detail: 'Messages about inheritances, huge transfers or next of kin are an old scam to collect "fees" from you.',
    detect: first(
      /\b(?:inheritance|next of kin|unclaimed (?:funds?|money)|deceased|transfer of (?:funds?|money)|confidential business proposal)\b/i,
      /\b(?:late|barrister|attorney) (?:mr|mrs|dr|husband|father|client)\b/i,
      /\$\s?\d+(?:\.\d+)?\s?(?:million|billion)\b|\b\d+(?:\.\d+)?\s?(?:million|billion)\s(?:usd|dollars|us dollars)\b/i
    ),
  },
  {
    id: 'investment_scam', category: 'bait', weight: 22,
    type: 'Investment scam',
    title: 'Promises guaranteed profit',
    detail: 'No real investment guarantees returns. "Double your money" schemes collapse and take your savings.',
    detect: first(
      /\bguaranteed (?:returns?|profits?|income)\b/i,
      /\bdouble your (?:money|investment|capital)\b/i,
      /\b\d{2,4}\s?%\s?(?:daily|weekly|monthly)\b/i,
      /\brisk[- ]free (?:investment|profit|returns?)\b/i
    ),
  },
  {
    id: 'delivery_scam', category: 'bait', weight: 12,
    type: 'Fake delivery notice',
    title: 'Claims a delivery problem',
    detail: 'Fake "parcel on hold" messages are used to steal card details or collect small fees.',
    detect: first(
      /\b(?:parcel|package|shipment|delivery|courier)\b[^.\n]{0,60}\b(?:failed|held|pending|on hold|could not|couldn't|unable|undelivered|missed|customs|reschedule|redeliver)\b/i
    ),
  },
  {
    id: 'tech_support', category: 'bait', weight: 20,
    type: 'Tech support scam',
    title: 'Claims your device has a problem',
    detail: 'Warnings about viruses or hacked devices are used to get you to call scammers or install harmful software.',
    detect: first(
      /\b(?:virus|malware|trojan)\b[^.\n]{0,40}\b(?:detected|found|infected)\b/i,
      /\byour (?:device|computer|pc|phone|windows|mac)\b[^.\n]{0,30}\b(?:infected|hacked|compromised|at risk)\b/i,
      /\b(?:microsoft|apple|windows) (?:support|security|technician)\b/i
    ),
  },
  {
    id: 'family_emergency', category: 'bait', weight: 20,
    type: 'Family emergency scam',
    title: 'Pretends to be a relative with a new number',
    detail: '"Hi mum, this is my new number" is a common trick to get relatives to send money.',
    detect: both(
      /\b(?:new number|lost my phone|phone (?:is )?(?:broken|damaged|stolen|dead)|broke my phone|dropped my phone)\b/i,
      /\b(?:mum|mom|dad|mother|father|grandma|granny|auntie|uncle)\b/i
    ),
  },
  {
    id: 'security_alert', category: 'pressure', weight: 12,
    title: 'Vague "suspicious activity" warning',
    detail: 'Fake security alerts do not give details. They just try to alarm you into clicking.',
    detect: first(
      /\b(?:unusual|suspicious|unauthori[sz]ed)\b[^.\n]{0,30}\b(?:activity|login|sign[- ]?in|transaction|access|attempt|debit)\b/i
    ),
  },
  {
    id: 'refund_bait', category: 'bait', weight: 12,
    title: 'Dangles a refund or reward',
    detail: 'Unexpected refunds and cashback offers are bait to get your bank details.',
    detect: first(
      /\b(?:refund|rebate|reimbursement|cashback|compensation)\b[^.\n]{0,40}\b(?:pending|waiting|available|approved|eligible|claim)\b/i
    ),
  },
  {
    id: 'loan_offer', category: 'bait', weight: 10,
    title: 'Offers an instant loan',
    detail: 'Instant loan offers with no checks are often used to collect fees or personal data.',
    detect: first(/\b(?:instant|quick|easy) loan\b/i, /\bloan (?:approved|offer)\b/i, /\bno (?:collateral|credit check)\b/i),
  },
  {
    id: 'secrecy', category: 'pressure', weight: 10,
    title: 'Asks you to keep it secret',
    detail: 'Scammers isolate you so nobody can warn you. Real organisations do not ask for secrecy.',
    detect: first(
      /\b(?:don'?t|do not|dont) (?:tell|inform) (?:anyone|anybody|your (?:family|wife|husband|bank|friends))\b/i,
      /\bkeep (?:this|it) (?:secret|confidential|private|between us)\b/i,
      /\bstrictly confidential\b/i
    ),
  },
  {
    id: 'authority', category: 'pressure', weight: 10,
    title: 'Claims to be an official or authority',
    detail: 'Scammers pose as banks, police, customs or bosses so you trust them without checking.',
    detect: first(
      /\b(?:this is|i am|i'm) (?:your |the )?(?:ceo|boss|director|manager|bank manager|customer care|customer service|support team)\b/i,
      /\b(?:from|calling from) (?:the )?(?:bank|customs|immigration|efcc|police|cbn|irs|fbi|nafdac|fraud (?:department|team))\b/i
    ),
  },
  {
    id: 'off_platform', category: 'pressure', weight: 10,
    title: 'Wants to move the chat elsewhere',
    detail: 'Scammers push you to WhatsApp or Telegram where there are fewer protections.',
    detect: first(
      /\b(?:contact|message|text|chat|reach|dm|add) (?:me|us|him|her|our agent|the agent)\b[^.\n]{0,30}\b(?:whatsapp|telegram|signal|wechat)\b/i
    ),
  },
  {
    id: 'generic_greeting', category: 'pressure', weight: 8,
    title: 'Generic greeting instead of your name',
    detail: 'Real companies usually address you by name. Mass-sent scams say "Dear customer".',
    detect: first(
      /\bdear (?:customer|user|client|member|account holder|beneficiary|friend|sir\/madam|sir or madam|valued customer|winner|email owner)\b/i
    ),
  },
  {
    id: 'shouting', category: 'pressure', weight: 5,
    title: 'Shouting and excessive punctuation',
    detail: 'ALL CAPS and "!!!" are used to create panic.',
    detect: detectShouting,
  },
];

const SEVERITY = (w) => (w >= 25 ? 'high' : w >= 15 ? 'medium' : 'low');

const ADVICE = {
  scam: [
    'Do not click any links, open attachments, or reply.',
    'Never share OTPs, PINs, passwords or card details with anyone.',
    'If it claims to be from your bank or a company, contact them using the official number on your card or their real website, not the details in the message.',
    'Block the sender and delete the message. If you already shared details or sent money, contact your bank immediately.',
  ],
  suspicious: [
    'Do not click links or reply yet.',
    'Check by contacting the company or person through an official channel you find yourself.',
    'Show the message to someone you trust before you act.',
  ],
  safe: [
    'No strong warning signs were found, but stay careful.',
    'Never share OTPs or PINs, and open official websites directly instead of through links in messages.',
  ],
};

const SUMMARY = {
  scam: 'This message shows several strong warning signs of a scam.',
  suspicious: 'This message has some warning signs. Be careful and verify it before you act.',
  safe: 'No strong warning signs were found, but stay careful.',
};

function mergeHighlights(list) {
  const sorted = [...list].sort((a, b) => a.start - b.start);
  const out = [];
  for (const h of sorted) {
    const last = out[out.length - 1];
    if (last && h.start < last.end) continue; // skip overlaps, keep the earlier one
    out.push(h);
  }
  return out;
}

/** Analyze a message. Always returns a result object; never throws on odd input. */
function analyzeMessage(input) {
  const text = String(input ?? '').slice(0, MAX_CHARS);

  const signals = [];
  const highlights = [];
  const found = new Set();

  for (const rule of RULES) {
    const hit = rule.detect(text);
    if (!hit) continue;
    found.add(rule.id);
    signals.push({
      id: rule.id,
      category: rule.category,
      severity: SEVERITY(rule.weight),
      weight: rule.weight,
      title: rule.title,
      detail: rule.detail,
      evidence: hit.start == null ? null : text.slice(hit.start, hit.end).trim().slice(0, 80),
      type: rule.type || null,
    });
    if (hit.start != null) highlights.push({ start: hit.start, end: hit.end, kind: rule.id });
  }

  // Links
  const links = [];
  let urlWeight = 0;
  for (const { raw, index } of extractUrls(text)) {
    const result = analyzeUrl(raw);
    if (!result) continue;
    links.push({
      url: result.url,
      host: result.host,
      flagged: result.flags.length > 0,
      flags: result.flags.map((f) => f.title),
    });
    if (result.flags.length) highlights.push({ start: index, end: index + raw.length, kind: 'link' });
    for (const f of result.flags) {
      urlWeight += f.weight;
      signals.push({
        id: f.id,
        category: 'links',
        severity: f.severity,
        weight: f.weight,
        title: f.title,
        detail: f.detail,
        evidence: result.host,
        type: f.id === 'brand_lookalike' ? 'Fake website (phishing)' : null,
      });
    }
  }
  urlWeight = Math.min(urlWeight, URL_WEIGHT_CAP);

  // Combinations are more telling than single signals.
  let comboWeight = 0;
  const has = (id) => found.has(id);
  const pressure = has('urgency') || has('threat');
  const ask =
    has('credentials') || has('secret_request') || has('payment_request') ||
    has('gift_card') || has('click_prompt') || urlWeight > 0;
  if (pressure && ask) {
    comboWeight += 10;
    signals.push({
      id: 'combo_pressure', category: 'pressure', severity: 'high', weight: 10,
      title: 'Urgency combined with a request',
      detail: 'Rushing you while asking for information, money or a tap is the most common scam pattern.',
      evidence: null, type: null,
    });
  }
  const bait = ['prize', 'job_scam', 'investment_scam', 'advance_fee', 'refund_bait', 'delivery_scam', 'loan_offer'].some(has);
  if (bait && links.length > 0) {
    comboWeight += 15;
    signals.push({
      id: 'combo_bait_link', category: 'links', severity: 'high', weight: 15,
      title: 'Tempting offer with a link',
      detail: 'Offers that are too good to be true, paired with a link, are how most scams reach their victims.',
      evidence: null, type: null,
    });
  }

  const ruleWeight = RULES.reduce((sum, r) => sum + (found.has(r.id) ? r.weight : 0), 0);
  const score = Math.min(100, ruleWeight + urlWeight + comboWeight);
  const verdict = score >= SCAM_THRESHOLD ? 'scam' : score >= SUSPICIOUS_THRESHOLD ? 'suspicious' : 'safe';

  signals.sort((a, b) => b.weight - a.weight);
  const type = (signals.find((s) => s.type) || {}).type || null;

  return {
    engine: 'rules',
    verdict,
    score,
    type: verdict === 'safe' ? null : type,
    summary: SUMMARY[verdict],
    signals,
    links,
    highlights: mergeHighlights(highlights),
    advice: ADVICE[verdict],
  };
}

export { analyzeMessage, SCAM_THRESHOLD, SUSPICIOUS_THRESHOLD };
