import HighlightedMessage from './HighlightedMessage.jsx';

const VERDICTS = {
  scam: {
    icon: '🚨',
    label: 'Likely a scam',
    box: 'border-red-300 bg-red-50',
    heading: 'text-red-900',
    bar: 'bg-red-600',
  },
  suspicious: {
    icon: '⚠️',
    label: 'Suspicious: be careful',
    box: 'border-amber-300 bg-amber-50',
    heading: 'text-amber-950',
    bar: 'bg-amber-500',
  },
  safe: {
    icon: '✅',
    label: 'No strong warning signs',
    box: 'border-emerald-300 bg-emerald-50',
    heading: 'text-emerald-950',
    bar: 'bg-emerald-600',
  },
};

const SEVERITY = {
  high: { label: 'Serious', className: 'bg-red-100 text-red-900' },
  medium: { label: 'Moderate', className: 'bg-amber-100 text-amber-900' },
  low: { label: 'Minor', className: 'bg-slate-100 text-slate-700' },
};

export default function ResultView({ result, message, onCheckAnother }) {
  const v = VERDICTS[result.verdict] || VERDICTS.suspicious;
  const links = Array.isArray(result.links) ? result.links : [];
  const highlights = Array.isArray(result.highlights) ? result.highlights : [];

  return (
    <div className="space-y-6">
      {/* Verdict */}
      <section className={`rounded-2xl border-2 p-5 sm:p-6 ${v.box}`}>
        <div className="flex items-center gap-3">
          <span className="text-4xl" aria-hidden="true">{v.icon}</span>
          <div>
            <h2 className={`text-2xl font-bold ${v.heading}`}>{v.label}</h2>
            {result.type && <p className="text-slate-700">{result.type}</p>}
          </div>
        </div>

        <div
          role="progressbar"
          aria-label="Risk level"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={result.score}
          className="mt-4 h-3 overflow-hidden rounded-full bg-white/80 ring-1 ring-black/5"
        >
          <div className={`h-full ${v.bar}`} style={{ width: `${Math.max(result.score, 4)}%` }} />
        </div>
        <p className="mt-1 text-sm text-slate-600">Risk level: {result.score} out of 100</p>

        <p className="mt-4 text-lg">{result.summary}</p>

        {result.verdict === 'safe' && (
          <p className="mt-3 rounded-xl bg-white/70 p-3 text-slate-800">
            This does not guarantee the message is safe. If it asks for money, a code or a login,
            check with the sender through an official channel first.
          </p>
        )}
      </section>

      {/* The message, marked up */}
      {highlights.length > 0 && message && (
        <section aria-labelledby="marked-heading">
          <h3 id="marked-heading" className="text-lg font-bold">What we spotted in your message</h3>
          <div className="mt-2">
            <HighlightedMessage text={message} highlights={highlights} />
          </div>
        </section>
      )}

      {/* Reasons */}
      {result.reasons?.length > 0 && (
        <section aria-labelledby="why-heading">
          <h3 id="why-heading" className="text-lg font-bold">Why we think so</h3>
          <ul className="mt-2 space-y-3">
            {result.reasons.map((reason, i) => {
              const sev = SEVERITY[reason.severity];
              return (
                <li key={i} className="rounded-xl border border-slate-200 bg-white p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-semibold">{reason.title}</p>
                    {sev && (
                      <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${sev.className}`}>
                        {sev.label}
                      </span>
                    )}
                  </div>
                  {reason.detail && <p className="mt-1 text-slate-700">{reason.detail}</p>}
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {/* Links */}
      {links.length > 0 && (
        <section aria-labelledby="links-heading">
          <h3 id="links-heading" className="text-lg font-bold">Links in this message</h3>
          <p className="mt-1 text-sm text-slate-600">
            Do not open these. We only looked at the address, we never visited it.
          </p>
          <ul className="mt-2 space-y-2">
            {links.map((link, i) => (
              <li key={i} className="rounded-xl border border-slate-200 bg-white p-3">
                <p className="break-all font-mono text-sm">{link.host}</p>
                {link.flagged ? (
                  <ul className="mt-1 list-disc pl-5 text-sm text-red-800">
                    {link.flags.map((flag, j) => (
                      <li key={j}>{flag}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-1 text-sm text-slate-600">
                    Nothing unusual in the address, but still be careful.
                  </p>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* What to do */}
      {result.advice?.length > 0 && (
        <section aria-labelledby="todo-heading" className="rounded-2xl border border-teal-200 bg-teal-50 p-5">
          <h3 id="todo-heading" className="text-lg font-bold text-teal-950">What to do</h3>
          <ol className="mt-2 list-decimal space-y-2 pl-6 text-teal-950">
            {result.advice.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        </section>
      )}

      {/* Actions */}
      <div className="flex flex-wrap gap-3">
        <button
          type="button"
          onClick={onCheckAnother}
          className="rounded-xl border border-slate-300 bg-white px-5 py-3 text-lg font-semibold text-slate-700 hover:bg-slate-100"
        >
          Check another message
        </button>
      </div>

      {result.aiStatus === 'unavailable' && (
        <p className="text-sm text-slate-600">
          The AI explanation is not available right now, so this result comes from our built-in checks.
        </p>
      )}
    </div>
  );
}
