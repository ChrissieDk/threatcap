import { describe, expect, it } from "vitest"
import { safeExternalUrl } from "./safe-url"

describe("safeExternalUrl", () => {
  it("allows http and https", () => {
    expect(safeExternalUrl("https://osv.dev/vulnerability/GHSA-1")).toBe("https://osv.dev/vulnerability/GHSA-1")
    expect(safeExternalUrl("http://example.com/a")).toBe("http://example.com/a")
  })

  it("rejects script, data, file and relative URLs", () => {
    for (const bad of ["javascript:alert(1)", " JavaScript:alert(1)", "data:text/html,x", "file:///etc/passwd", "/relative", "//evil.com", "not a url", "", null, undefined]) {
      expect(safeExternalUrl(bad)).toBeNull()
    }
  })
})
