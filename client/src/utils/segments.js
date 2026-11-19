/**
 * Split a message into plain and highlighted pieces.
 * `highlights` come from the server as [{ start, end, kind }] character ranges.
 * Bad, overlapping or out-of-range entries are skipped so the UI can never crash on them.
 */
export function buildSegments(text, highlights = []) {
  const source = typeof text === 'string' ? text : '';

  const valid = (Array.isArray(highlights) ? highlights : [])
    .filter(
      (h) =>
        h &&
        Number.isInteger(h.start) &&
        Number.isInteger(h.end) &&
        h.start >= 0 &&
        h.end > h.start &&
        h.start < source.length
    )
    .map((h) => ({ ...h, end: Math.min(h.end, source.length) }))
    .sort((a, b) => a.start - b.start);

  const segments = [];
  let pos = 0;
  for (const h of valid) {
    if (h.start < pos) continue; // overlaps the previous highlight
    if (h.start > pos) segments.push({ text: source.slice(pos, h.start), kind: null });
    segments.push({ text: source.slice(h.start, h.end), kind: h.kind || 'signal' });
    pos = h.end;
  }
  if (pos < source.length) segments.push({ text: source.slice(pos), kind: null });
  return segments;
}
