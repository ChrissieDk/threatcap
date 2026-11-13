import { describe, expect, it } from "vitest"
import { csvCell, toCsv } from "./csv"

describe("csv", () => {
  it("quotes commas, quotes and newlines", () => {
    expect(csvCell('a,"b"')).toBe('"a,""b"""')
    expect(csvCell("line\nbreak")).toBe('"line\nbreak"')
  })

  it("defuses spreadsheet formulas", () => {
    expect(csvCell("=HYPERLINK(1)")).toBe("'=HYPERLINK(1)")
    expect(csvCell("@SUM(A1)")).toBe("'@SUM(A1)")
  })

  it("renders empty values and rows", () => {
    expect(toCsv([["a", null, 1, true]])).toBe("a,,1,true\r\n")
  })
})
