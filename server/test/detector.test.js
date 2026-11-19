// Run from the server folder with:  node --test
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { analyzeMessage } from '../services/heuristics.js';
import { extractUrls, analyzeUrl } from '../services/urlTools.js';

const flagIds = (url) => analyzeUrl(url).flags.map((f) => f.id);

describe('link analysis', () => {
  test('finds links, ignores email addresses and plain words', () => {
    const text = 'Mail john.doe@gmail.com or visit www.example.com, also bit.ly/3abc. That is e.g. fine.';
    assert.deepEqual(extractUrls(text).map((u) => u.raw), ['www.example.com', 'bit.ly/3abc']);
  });

  test('flags look-alike brand domains, including digit swaps', () => {
    assert.ok(flagIds('http://paypa1-secure.com/login').includes('brand_lookalike'));
    assert.ok(flagIds('https://paypal.com.account-verify.xyz').includes('brand_lookalike'));
    assert.ok(flagIds('https://gtbank-update.top').includes('brand_lookalike'));
  });

  test('does not flag real brand websites', () => {
    assert.deepEqual(flagIds('https://www.amazon.com/orders'), []);
    assert.deepEqual(flagIds('https://secure.paypal.com/signin'), []);
    assert.deepEqual(flagIds('https://www.applebees.com'), []);
  });

  test('flags shorteners, IP addresses, risky endings and app downloads', () => {
    assert.ok(flagIds('https://bit.ly/abc').includes('shortener'));
    assert.ok(flagIds('http://192.168.4.20/pay').includes('ip_host'));
    assert.ok(flagIds('https://free-data.click').includes('risky_tld'));
    assert.ok(flagIds('https://example.com/update.apk').includes('malware_file'));
  });
});

const CASES = [
  {
    name: 'fake bank alert with look-alike link',
    text: 'GTBank ALERT: Your account has been suspended. Verify your details immediately: http://gtbank-secure-login.xyz/verify',
    expect: 'scam',
  },
  {
    name: 'prize message with shortened link',
    text: 'Congratulations! You have won $5,000. Claim your prize now at bit.ly/win-big',
    expect: 'scam',
  },
  {
    name: 'fake delivery fee',
    text: 'DHL: Your parcel is on hold. Pay the customs fee within 24 hours: http://dhl-parcel-track.top/pay',
    expect: 'scam',
  },
  {
    name: 'advance-fee letter',
    text: 'I am the barrister of the late Mr. Okoro. You are the next of kin to $12 million. Keep this confidential and send your bank details.',
    expect: 'scam',
  },
  {
    name: 'asks for the OTP',
    text: 'Hello, I sent you a code by mistake. Please send me the code you just received.',
    expect: ['suspicious', 'scam'],
  },
  {
    name: 'family emergency',
    text: 'Hi mum, I lost my phone, this is my new number. Please send money for airtime.',
    expect: ['suspicious', 'scam'],
  },
  {
    name: 'normal bank OTP with a warning not to share',
    text: 'Your OTP is 482913. Do not share it with anyone. Never send your PIN to anybody, including bank staff.',
    expect: 'safe',
  },
  {
    name: 'friendly message',
    text: 'Hey, are we still meeting at 5? I will bring the documents. Call me when you arrive.',
    expect: 'safe',
  },
  {
    name: 'real Amazon link',
    text: 'Your order has shipped. Track it here: https://www.amazon.com/gp/your-account/order-history',
    expect: 'safe',
  },
];

describe('message verdicts', () => {
  for (const c of CASES) {
    test(c.name, () => {
      const result = analyzeMessage(c.text);
      const allowed = Array.isArray(c.expect) ? c.expect : [c.expect];
      assert.ok(
        allowed.includes(result.verdict),
        `expected ${allowed.join(' or ')} but got ${result.verdict} (score ${result.score}): ${result.signals.map((s) => s.id).join(', ')}`
      );
    });
  }

  test('returns a safe, well-formed result for empty or odd input', () => {
    for (const input of ['', '   ', null, undefined, 12345]) {
      const r = analyzeMessage(input);
      assert.equal(r.verdict, 'safe');
      assert.ok(Array.isArray(r.signals) && Array.isArray(r.advice));
    }
  });

  test('highlights point at real text and never overlap', () => {
    const text = 'URGENT: verify your account at http://paypa1-login.xyz now';
    const r = analyzeMessage(text);
    assert.ok(r.highlights.length > 0);
    let prevEnd = 0;
    for (const h of r.highlights) {
      assert.ok(h.start >= prevEnd && h.end > h.start && h.end <= text.length);
      prevEnd = h.end;
    }
  });
});
