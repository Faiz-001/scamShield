import { useEffect, useRef, useState } from 'react';
import { checkMessage } from './api.js';
import ResultView from './components/ResultView.jsx';

const MAX_CHARS = 3000;

// Realistic examples so anyone (including judges) can try the app in one tap.
const EXAMPLES = [
  {
    label: 'Fake bank alert',
    text: 'GTBank ALERT: Your account has been suspended due to unusual activity. Verify your details immediately to avoid permanent closure: http://gtbank-secure-login.xyz/verify',
  },
  {
    label: 'Fake prize',
    text: 'Congratulations! You have been selected as a winner of $5,000. Claim your prize now: bit.ly/claim-5000-prize',
  },
  {
    label: 'Parcel fee',
    text: 'DHL: Your parcel is on hold because of an unpaid customs fee. Pay within 24 hours to avoid return: http://dhl-parcel-track.top/pay',
  },
  {
    label: '"Hi mum" message',
    text: "Hi mum, I dropped my phone and this is my new number. Please save it. I need you to send ₦45,000 urgently, I'll explain later.",
  },
  {
    label: 'Fake job offer',
    text: 'Work from home and earn $300 per day. No experience needed! Pay a ₦5,000 registration fee within 24 hours to secure your slot. Chat me on WhatsApp.',
  },
  {
    label: 'Real bank OTP',
    text: 'Your OTP is 482913. Do not share it with anyone. It is valid for 10 minutes.',
  },
];

export default function App() {
  const [message, setMessage] = useState('');
  const [status, setStatus] = useState('idle'); // idle | loading | done | error
  const [result, setResult] = useState(null);
  const [checkedText, setCheckedText] = useState('');
  const [error, setError] = useState('');

  const textareaRef = useRef(null);
  const outputRef = useRef(null);
  const abortRef = useRef(null);

  const trimmed = message.trim();
  const tooLong = message.length > MAX_CHARS;
  const canCheck = trimmed.length >= 3 && !tooLong && status !== 'loading';

  // Cancel any request still running if the page is closed.
  useEffect(() => () => abortRef.current?.abort(), []);

  // When a result or error appears, bring it into view and move focus there for screen readers.
  useEffect(() => {
    if (status !== 'done' && status !== 'error') return;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    outputRef.current?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    outputRef.current?.focus({ preventScroll: true });
  }, [status]);

  async function handleCheck(event) {
    event?.preventDefault();
    if (!canCheck) return;

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setStatus('loading');
    setError('');
    try {
      const data = await checkMessage(trimmed, { signal: controller.signal });
      setResult(data);
      setCheckedText(trimmed);
      setStatus('done');
    } catch (err) {
      if (err.name === 'AbortError') return;
      setError(err.message || 'Something went wrong. Please try again.');
      setStatus('error');
    }
  }

  function reset(nextText = '') {
    abortRef.current?.abort();
    setMessage(nextText);
    setResult(null);
    setError('');
    setStatus('idle');
    textareaRef.current?.focus();
  }

  function handleKeyDown(event) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') handleCheck(event);
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-3xl flex-col px-4 py-6 sm:py-10">
      <header className="flex items-center gap-3">
        <span className="text-3xl" aria-hidden="true">🛡️</span>
        <div>
          <p className="text-xl font-bold leading-tight text-teal-800">ScamShield</p>
          <p className="text-sm text-slate-600">Free · No signup · Nothing is saved</p>
        </div>
      </header>

      <main className="mt-8 flex-1">
        <h1 className="text-3xl font-extrabold leading-tight sm:text-4xl">
          Got a message that feels off?
        </h1>
        <p className="mt-3 text-lg text-slate-700">
          Paste a text, WhatsApp message, email or link below. We will tell you if it looks like a
          scam, and explain why in plain words.
        </p>

        <form onSubmit={handleCheck} className="mt-6">
          <label htmlFor="message" className="block text-lg font-semibold">
            Paste the message here
          </label>
          <textarea
            id="message"
            ref={textareaRef}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            rows={6}
            placeholder="For example: 'Your account has been suspended. Click this link to verify…'"
            aria-describedby="message-help"
            className="mt-2 w-full resize-y rounded-2xl border border-slate-300 bg-white p-4 text-lg leading-relaxed shadow-sm placeholder:text-slate-400 focus:border-teal-700 focus:outline-none focus:ring-4 focus:ring-teal-700/20"
          />
          <div id="message-help" className="mt-1 flex justify-between gap-4 text-sm">
            <span className="text-slate-600">
              Do not include passwords or PINs. Tip: press Ctrl+Enter to check.
            </span>
            <span className={tooLong ? 'font-semibold text-red-700' : 'text-slate-500'}>
              {message.length} / {MAX_CHARS}
            </span>
          </div>
          {tooLong && (
            <p role="alert" className="mt-2 text-red-700">
              This message is too long. Please paste a shorter part of it (up to {MAX_CHARS}{' '}
              characters).
            </p>
          )}

          <div className="mt-4 flex flex-wrap gap-3">
            <button
              type="submit"
              disabled={!canCheck}
              className="rounded-xl bg-teal-700 px-6 py-3 text-lg font-semibold text-white shadow-sm transition hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {status === 'loading' ? 'Checking…' : 'Check this message'}
            </button>
            {message && status !== 'loading' && (
              <button
                type="button"
                onClick={() => reset()}
                className="rounded-xl border border-slate-300 bg-white px-5 py-3 text-lg font-semibold text-slate-700 hover:bg-slate-100"
              >
                Clear
              </button>
            )}
          </div>
        </form>

        <section className="mt-6" aria-labelledby="examples-heading">
          <h2 id="examples-heading" className="text-sm font-semibold uppercase tracking-wide text-slate-600">
            Not sure? Try an example
          </h2>
          <div className="mt-2 flex flex-wrap gap-2">
            {EXAMPLES.map((example) => (
              <button
                key={example.label}
                type="button"
                onClick={() => reset(example.text)}
                className="rounded-full border border-teal-700/30 bg-white px-4 py-2 text-sm font-medium text-teal-900 hover:bg-teal-50"
              >
                {example.label}
              </button>
            ))}
          </div>
        </section>

        <div
          ref={outputRef}
          tabIndex={-1}
          aria-live="polite"
          className="mt-8 scroll-mt-4 outline-none"
        >
          {status === 'loading' && <LoadingPanel />}
          {status === 'error' && (
            <div role="alert" className="rounded-2xl border-2 border-red-300 bg-red-50 p-5 text-red-900">
              <p className="text-lg font-semibold">We could not check that message</p>
              <p className="mt-1">{error}</p>
            </div>
          )}
          {status === 'done' && result && (
            <ResultView result={result} message={checkedText} onCheckAnother={() => reset()} />
          )}
        </div>
      </main>

      <footer className="mt-12 border-t border-slate-200 pt-6 text-sm text-slate-600">
        <p>
          ScamShield does not save your messages. Results are guidance, not a guarantee: if you are
          unsure, contact the company using the number on your card or their official website.
        </p>
        <p className="mt-2 font-medium">
          Never share your OTP, PIN or password with anyone, even if they say they are from your bank.
        </p>
      </footer>
    </div>
  );
}

function LoadingPanel() {
  return (
    <div className="flex items-center gap-4 rounded-2xl border border-slate-200 bg-white p-5">
      <span
        className="h-7 w-7 shrink-0 animate-spin rounded-full border-4 border-teal-700 border-t-transparent"
        aria-hidden="true"
      />
      <p className="text-lg">Checking for warning signs…</p>
    </div>
  );
}
