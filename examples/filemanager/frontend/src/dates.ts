// A share or a link "until" a day holds to the end of that day where the person is, not to its start in UTC.

/** The end of a day picked in a date input ("2026-10-20"), in the person's time zone: the next day's midnight. */
export function endOfDay(picked: string): string {
  const [y, m, d] = picked.split("-").map(Number);
  return new Date(y, m - 1, d + 1).toISOString();
}

/** The last day something that ends at `end` holds, as the person reads dates. */
export function lastDay(end: string): string {
  return new Date(new Date(end).getTime() - 1).toLocaleDateString();
}
