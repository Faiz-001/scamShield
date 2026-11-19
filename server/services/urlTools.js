/**
 * URL helpers for ScamShield.
 * Finds links inside a message and flags the tricks scammers use to disguise them.
 * Pure functions, no dependencies.
 */

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly',
  'rebrand.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 's.id', 'bl.ink', 'lnkd.in', 't.ly',
  'v.gd', 'soo.gd', 'clck.ru', 'qr.ae', 'u.to', 'x.co',
]);

// Endings that are cheap to register and heavily used in scam campaigns.
const RISKY_TLDS = new Set([
  'top', 'xyz', 'click', 'link', 'work', 'gq', 'tk', 'ml', 'cf', 'ga', 'icu', 'buzz', 'cfd',
  'sbs', 'rest', 'monster', 'cyou', 'support', 'country', 'kim', 'loan', 'win', 'bid',
  'stream', 'download', 'men', 'review', 'party', 'trade', 'date', 'faith', 'racing',
  'accountant', 'science', 'cricket', 'zip', 'mov',
]);

const COMMON_TLDS = [
  'com', 'net', 'org', 'info', 'biz', 'io', 'co', 'me', 'ly', 'gl', 'to', 'ng', 'uk', 'us',
  'ca', 'de', 'in', 'za', 'gh', 'ke', 'app', 'dev', 'site', 'online', 'store', 'shop', 'live',
  'cc', 'tv', 'ws', 'vip', 'club', 'fun', 'help', 'pro', 'cloud', 'page', 'one', 'gov', 'edu',
  'fr', 'au', 'ae', 'ai', 'ru', 'cn', 'br', 'jp', 'kr', 'sg', 'tz', 'ug', 'rw', 'et', 'zm', 'zw',
];

// Without http:// or www., only treat text as a link if it ends in a known web ending.
// (.zip and .mov are left out because they usually mean a file name here.)
const BARE_TLDS = new Set([
  ...COMMON_TLDS,
  ...[...RISKY_TLDS].filter((t) => t !== 'zip' && t !== 'mov'),
]);

const SECOND_LEVELS = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'sch']);
const MALWARE_EXT = /\.(?:apk|exe|msi|scr|bat|cmd|jar|vbs|dmg|pkg)(?:$|[?#])/i;
const KEYWORD_HOST =
  /(?:login|log-in|signin|sign-in|verify|verification|secure|security|account|update|confirm|wallet|billing|support|recover|unlock|refund|claim)/;

const AMAZON = [
  'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.es', 'amazon.it',
  'amazon.ca', 'amazon.in', 'amazon.com.au', 'amazon.com.br', 'amazon.co.jp', 'amazon.ae',
  'amazon.sa', 'amazonaws.com', 'amzn.to', 'amzn.com', 'a.co',
];

// Brands scammers imitate most. `strict` brands have short or common-word names,
// so they only match when a whole piece of the address equals the name.
const BRANDS = [
  { name: 'PayPal', token: 'paypal', domains: ['paypal.com', 'paypal.me'] },
  { name: 'Amazon', token: 'amazon', domains: AMAZON },
  { name: 'Apple', token: 'apple', strict: true, domains: ['apple.com', 'icloud.com'] },
  { name: 'Microsoft', token: 'microsoft', domains: ['microsoft.com', 'microsoftonline.com', 'office.com', 'outlook.com', 'live.com', 'windows.com'] },
  { name: 'Google', token: 'google', domains: ['google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'google-analytics.com', 'withgoogle.com', 'google.com.ng', 'google.co.uk', 'goo.gl', 'g.co', 'youtube.com'] },
  { name: 'Netflix', token: 'netflix', domains: ['netflix.com'] },
  { name: 'Facebook', token: 'facebook', domains: ['facebook.com', 'fb.com', 'fb.me', 'fbcdn.net'] },
  { name: 'Instagram', token: 'instagram', domains: ['instagram.com', 'cdninstagram.com'] },
  { name: 'WhatsApp', token: 'whatsapp', domains: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
  { name: 'DHL', token: 'dhl', strict: true, domains: ['dhl.com', 'dhl.de', 'dhl.co.uk'] },
  { name: 'FedEx', token: 'fedex', domains: ['fedex.com'] },
  { name: 'UPS', token: 'ups', strict: true, domains: ['ups.com'] },
  { name: 'USPS', token: 'usps', strict: true, domains: ['usps.com'] },
  { name: 'Chase', token: 'chase', strict: true, domains: ['chase.com', 'jpmorganchase.com'] },
  { name: 'Wells Fargo', token: 'wellsfargo', domains: ['wellsfargo.com'] },
  { name: 'Bank of America', token: 'bankofamerica', domains: ['bankofamerica.com'] },
  { name: 'the IRS', token: 'irs', strict: true, domains: ['irs.gov'] },
  { name: 'Coinbase', token: 'coinbase', domains: ['coinbase.com'] },
  { name: 'Binance', token: 'binance', domains: ['binance.com', 'binance.us'] },
  { name: 'GTBank', token: 'gtbank', domains: ['gtbank.com'] },
  { name: 'Zenith Bank', token: 'zenithbank', domains: ['zenithbank.com'] },
  { name: 'Access Bank', token: 'accessbank', domains: ['accessbankplc.com'] },
  { name: 'First Bank', token: 'firstbank', domains: ['firstbanknigeria.com'] },
  { name: 'Paystack', token: 'paystack', domains: ['paystack.com'] },
  { name: 'Flutterwave', token: 'flutterwave', domains: ['flutterwave.com'] },
  { name: 'Kuda', token: 'kuda', strict: true, domains: ['kuda.com'] },
];

/** Pull links out of free text. Returns [{ raw, index }]. */
function extractUrls(text, limit = 10) {
  const re =
    /\b(?:https?:\/\/|www\.)[^\s<>"'`]+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?:[/?#][^\s<>"'`]*)?/gi;
  const found = [];
  const seen = new Set();
  let m;

  while ((m = re.exec(text)) !== null && found.length < limit) {
    const raw = m[0].replace(/[.,;:!?)\]}>]+$/, '');
    const index = m.index;
    if (!raw) continue;
    if (index > 0 && text[index - 1] === '@') continue; // the domain part of an email address

    if (!/^(?:https?:\/\/|www\.)/i.test(raw)) {
      const host = raw.split(/[/?#]/)[0].toLowerCase();
      const tld = host.split('.').pop();
      if (!BARE_TLDS.has(tld)) continue;
    }

    const key = raw.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    found.push({ raw, index });
  }
  return found;
}

function parseUrl(raw) {
  const hasScheme = /^https?:\/\//i.test(raw);
  try {
    const u = new URL(hasScheme ? raw : `https://${raw}`);
    return {
      raw,
      host: u.hostname.toLowerCase().replace(/^www\./, ''),
      path: `${u.pathname}${u.search}`,
      hasCredentials: Boolean(u.username || u.password),
      insecure: hasScheme && u.protocol === 'http:',
    };
  } catch {
    return null;
  }
}

/** example.co.uk -> example.co.uk, a.b.example.com -> example.com */
function registrable(host) {
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const tld = labels[labels.length - 1];
  const sld = labels[labels.length - 2];
  if (tld.length === 2 && SECOND_LEVELS.has(sld)) return labels.slice(-3).join('.');
  return labels.slice(-2).join('.');
}

/** Undo common look-alike swaps: paypa1 -> paypal, rnicrosoft -> microsoft. */
function variants(part) {
  const swap = (s, map) => s.replace(/[0-9]/g, (d) => map[d] || d);
  return [
    part,
    swap(part, { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's' }),
    swap(part, { 0: 'o', 1: 'i', 3: 'e', 4: 'a', 5: 's' }),
    part.replace(/rn/g, 'm').replace(/vv/g, 'w'),
  ];
}

function isOfficial(brand, host) {
  return brand.domains.some((d) => host === d || host.endsWith(`.${d}`));
}

function matchesToken(part, brand) {
  return variants(part).some((v) => {
    if (v === brand.token) return true;
    return !brand.strict && brand.token.length >= 5 && v.includes(brand.token);
  });
}

function findImpersonatedBrand(host) {
  const parts = host
    .split('.')
    .slice(0, -1)
    .flatMap((label) => label.split('-'));
  for (const brand of BRANDS) {
    if (isOfficial(brand, host)) continue;
    if (parts.some((p) => matchesToken(p, brand))) return brand;
  }
  return null;
}

/** Inspect one link. Returns { url, host, registrable, flags[] } or null if it cannot be parsed. */
function analyzeUrl(raw) {
  const parsed = parseUrl(raw);
  if (!parsed) return null;

  const { host, path } = parsed;
  const flags = [];
  const add = (id, weight, title, detail) =>
    flags.push({
      id,
      weight,
      severity: weight >= 30 ? 'high' : weight >= 15 ? 'medium' : 'low',
      title,
      detail,
    });

  const labels = host.split('.');
  const tld = labels[labels.length - 1];
  const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.startsWith('[');

  if (isIp) {
    add('ip_host', 30, 'Link uses numbers instead of a website name',
      'Real companies use proper website names. A link made of numbers is a common trick.');
  }
  if (parsed.hasCredentials) {
    add('at_sign', 30, 'Link hides its real destination',
      'The text before the @ sign is there to fool you. The link actually goes to a different site.');
  }
  if (host.includes('xn--')) {
    add('punycode', 30, 'Link uses look-alike characters',
      'The address mixes in unusual letters that look like normal ones, to imitate a real site.');
  }
  if (MALWARE_EXT.test(path)) {
    add('malware_file', 40, 'Link downloads an app or program',
      'Downloading apps or files from messages can install malware that steals your data.');
  }
  if (!isIp) {
    if (SHORTENERS.has(host) || SHORTENERS.has(registrable(host))) {
      add('shortener', 12, 'Shortened link hides where it goes',
        'You cannot see the real website before you tap it.');
    }
    if (RISKY_TLDS.has(tld)) {
      add('risky_tld', 15, `Unusual web address ending (.${tld})`,
        'This ending is cheap to buy and very common in scam websites.');
    }
    const brand = findImpersonatedBrand(host);
    if (brand) {
      add('brand_lookalike', 40, `Fake-looking ${brand.name} website`,
        `The address (${host}) uses the name of ${brand.name}, but it is not one of its usual website addresses.`);
    }
    if (labels.length >= 5) {
      add('many_subdomains', 10, 'Unusually long, confusing web address',
        'Scammers pile on extra words to make a fake address look real.');
    }
    if (host.includes('-') && KEYWORD_HOST.test(host)) {
      add('keyword_host', 15, 'Web address stuffed with login or security words',
        'Words like "secure", "verify" or "login" joined with dashes are typical of phishing sites.');
    }
  }
  if (parsed.insecure) {
    add('http', 5, 'Link is not secure (http, not https)',
      'Legitimate sites that ask for logins or payments use https.');
  }

  return { url: parsed.raw, host, registrable: registrable(host), flags };
}

export { extractUrls, analyzeUrl, registrable, BRANDS };
