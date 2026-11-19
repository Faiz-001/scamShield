/**
 * Orchestrates a full check:
 *   1. rule-based detection (always runs, instant)
 *   2. AI analysis and Google Safe Browsing (optional, run in parallel)
 *   3. combine everything into one result, always leaning towards caution
 *
 * Nothing here stores the message. Only the links (never the message text)
 * are sent to Google Safe Browsing, and only when a key is configured.
 */

import { analyzeMessage, SCAM_THRESHOLD, SUSPICIOUS_THRESHOLD } from './heuristics.js';
import { analyzeWithAI, isEnabled as aiEnabled } from './ai.js';

const SAFE_BROWSING_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const SAFE_BROWSING_TIMEOUT_MS = 5000;
const KNOWN_THREAT_WEIGHT = 60;

const verdictFor = (score) =>
  score >= SCAM_THRESHOLD ? 'scam' : score >= SUSPICIOUS_THRESHOLD ? 'suspicious' : 'safe';

const withScheme = (url) => (/^https?:\/\//i.test(url) ? url : `https://${url}`);

/** Returns the links Google lists as dangerous. Any failure just means "no extra information". */
async function checkSafeBrowsing(urls) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key || urls.length === 0) return [];

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SAFE_BROWSING_TIMEOUT_MS);
  try {
    const res = await fetch(`${SAFE_BROWSING_URL}?key=${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'scamshield', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: urls.map((url) => ({ url: withScheme(url) })),
        },
      }),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`Safe Browsing error ${res.status}`);
    const data = await res.json();
    return (data.matches || []).map((m) => m.threat && m.threat.url).filter(Boolean);
  } catch (err) {
    console.warn('Safe Browsing check failed:', err.name === 'AbortError' ? 'timeout' : err.message);
    return [];
  } finally {
    clearTimeout(timer);
  }
}

async function runAI(message, rules) {
  if (!aiEnabled()) return { status: 'disabled', ai: null };
  try {
    return { status: 'ok', ai: await analyzeWithAI(message, rules) };
  } catch (err) {
    // Log the reason only, never the message.
    console.warn('AI check failed, using rules only:', err.name === 'AbortError' ? 'timeout' : err.message);
    return { status: 'unavailable', ai: null };
  }
}

function addHighlight(highlights, start, end) {
  if (start < 0 || highlights.some((h) => start < h.end && h.start < end)) return highlights;
  return [...highlights, { start, end, kind: 'link' }].sort((a, b) => a.start - b.start);
}

/** Mark links that Google reports as dangerous and raise the score accordingly. */
function applyKnownThreats(message, rules, threatUrls) {
  if (threatUrls.length === 0) return rules;
  const flagged = new Set(threatUrls.map((u) => withScheme(u).toLowerCase()));

  let { highlights } = rules;
  const signals = [...rules.signals];
  let hit = false;

  const links = rules.links.map((link) => {
    if (!flagged.has(withScheme(link.url).toLowerCase())) return link;
    hit = true;
    signals.push({
      id: 'known_malicious',
      category: 'links',
      severity: 'high',
      weight: KNOWN_THREAT_WEIGHT,
      title: 'Listed as dangerous by Google Safe Browsing',
      detail: 'This link is on Google\'s list of websites known for scams, malware or phishing.',
      evidence: link.host,
      type: 'Fake website (phishing)',
    });
    const start = message.indexOf(link.url);
    if (start !== -1) highlights = addHighlight(highlights, start, start + link.url.length);
    return { ...link, flagged: true, flags: [...link.flags, 'Listed as dangerous by Google'] };
  });

  if (!hit) return rules;
  signals.sort((a, b) => b.weight - a.weight);
  const score = Math.min(100, rules.score + KNOWN_THREAT_WEIGHT);
  const verdict = verdictFor(score);
  return {
    ...rules,
    score,
    verdict,
    // The rules' own summary and advice were written for the old verdict, so refresh them.
    summary: verdict === rules.verdict ? rules.summary : undefined,
    advice: verdict === rules.verdict ? rules.advice : undefined,
    type: rules.type || 'Fake website (phishing)',
    signals,
    links,
    highlights,
  };
}

/**
 * Final verdict comes from the higher of the two risk scores, so a miss by one
 * method is covered by the other. Text (summary, reasons, advice) comes from
 * whichever method agrees with the final verdict.
 */
function combine(rules, ai, aiStatus) {
  const score = Math.max(rules.score, ai ? ai.risk : 0);
  const verdict = verdictFor(score);
  const aiAgrees = ai && verdictFor(ai.risk) === verdict;

  const ruleReasons = rules.signals.slice(0, 5).map((s) => ({
    title: s.title,
    detail: s.detail,
    severity: s.severity,
    source: 'rules',
  }));

  return {
    engine: ai ? 'ai+rules' : 'rules',
    aiStatus,
    verdict,
    score,
    type: verdict === 'safe' ? null : (aiAgrees && ai.type) || rules.type || (ai && ai.type) || null,
    summary: (aiAgrees && ai.summary) || rules.summary || FALLBACK_SUMMARY[verdict],
    reasons:
      aiAgrees && ai.reasons.length
        ? ai.reasons.map((r) => ({ ...r, source: 'ai' }))
        : ruleReasons,
    advice: (aiAgrees && ai.advice.length ? ai.advice : rules.advice) || FALLBACK_ADVICE[verdict],
    signals: rules.signals,
    links: rules.links,
    highlights: rules.highlights,
  };
}

const FALLBACK_SUMMARY = {
  scam: 'This message shows strong warning signs of a scam.',
  suspicious: 'This message has some warning signs. Be careful and verify it before you act.',
  safe: 'No strong warning signs were found, but stay careful.',
};

const FALLBACK_ADVICE = {
  scam: [
    'Do not click links, open attachments, or reply.',
    'Never share OTPs, PINs, passwords or card details.',
    'Contact the company using the official number on your card or their real website.',
    'Block the sender and delete the message.',
  ],
  suspicious: [
    'Do not click links or reply yet.',
    'Check with the company or person through an official channel you find yourself.',
  ],
  safe: ['Stay careful and never share OTPs or PINs.'],
};

/** Run a full check on one message. Always resolves with a result, even if the AI is down. */
async function analyze(message) {
  const rules = analyzeMessage(message);

  const [{ status, ai }, threatUrls] = await Promise.all([
    runAI(message, rules),
    checkSafeBrowsing(rules.links.map((l) => l.url)),
  ]);

  return combine(applyKnownThreats(message, rules, threatUrls), ai, status);
}

export { analyze, combine, verdictFor };
