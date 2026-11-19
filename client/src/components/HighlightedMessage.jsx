import { buildSegments } from '../utils/segments.js';

/** Shows the user's own message with the suspicious parts marked. */
export default function HighlightedMessage({ text, highlights }) {
  const segments = buildSegments(text, highlights);
  const hasLinks = segments.some((s) => s.kind === 'link');
  const hasPhrases = segments.some((s) => s.kind && s.kind !== 'link');

  return (
    <div>
      <p
        aria-label="Your message, with suspicious parts marked"
        className="whitespace-pre-wrap break-words rounded-xl border border-slate-200 bg-white p-4 text-lg leading-relaxed text-slate-800"
      >
        {segments.map((segment, i) =>
          segment.kind ? (
            <mark
              key={i}
              className={
                segment.kind === 'link'
                  ? 'rounded bg-red-200 px-0.5 font-semibold text-red-950 underline decoration-red-700 decoration-wavy underline-offset-4'
                  : 'rounded bg-amber-200 px-0.5 text-amber-950 underline decoration-amber-700 underline-offset-4'
              }
            >
              {segment.text}
            </mark>
          ) : (
            <span key={i}>{segment.text}</span>
          )
        )}
      </p>

      {(hasLinks || hasPhrases) && (
        <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-sm text-slate-600">
          {hasLinks && (
            <span>
              <mark className="rounded bg-red-200 px-1 underline decoration-red-700 decoration-wavy underline-offset-4">
                Wavy red
              </mark>{' '}
              = risky link
            </span>
          )}
          {hasPhrases && (
            <span>
              <mark className="rounded bg-amber-200 px-1 underline decoration-amber-700 underline-offset-4">
                Underlined yellow
              </mark>{' '}
              = warning phrase
            </span>
          )}
        </p>
      )}
    </div>
  );
}
