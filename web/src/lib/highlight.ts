export type HighlightRange = { start: number; end: number; flag: boolean };
export function matchRanges(
  text: string,
  regexes: (RegExp | undefined)[],
  flag = false,
): HighlightRange[] {
  const ranges: HighlightRange[] = [];
  for (const regex of regexes) {
    if (!regex) continue;
    for (const match of text.matchAll(regex)) {
      if (match[0].length)
        ranges.push({
          start: match.index,
          end: match.index + match[0].length,
          flag,
        });
    }
  }
  return ranges;
}
export function renderHighlights(
  escaped: string[],
  ranges: HighlightRange[],
): string {
  // Emit disjoint spans, preserving selection offsets even when matches overlap.
  const normalized = ranges
    .filter((r) => r.end > r.start && r.start < escaped.length && r.end > 0)
    .map((r) => ({
      ...r,
      start: Math.max(0, r.start),
      end: Math.min(escaped.length, r.end),
    }));
  const boundaries = [
    ...new Set([
      0,
      escaped.length,
      ...normalized.flatMap((r) => [r.start, r.end]),
    ]),
  ].sort((a, b) => a - b);
  return boundaries
    .slice(0, -1)
    .map((start, i) => {
      const end = boundaries[i + 1];
      const active = normalized.filter((r) => r.start <= start && r.end >= end);
      const cls = active.some((r) => r.flag)
        ? "mark flag-mark"
        : active.length
          ? "mark"
          : "";
      return `<span data-offset="${start}"${cls ? ` class="${cls}"` : ""}>${escaped.slice(start, end).join("")}</span>`;
    })
    .join("");
}
