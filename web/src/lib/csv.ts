/** One CSV cell. Quotes as needed and defuses spreadsheet formulas ("=", "+", "-", "@" at the start). */
export function csvCell(value: string | number | boolean | null | undefined): string {
  let text = value === null || value === undefined ? "" : String(value)
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

export function toCsv(rows: (string | number | boolean | null | undefined)[][]): string {
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n"
}
