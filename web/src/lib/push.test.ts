import { describe, expect, it } from "vitest"
import { describeBrowser, urlBase64ToUint8Array } from "@/lib/push"

describe("urlBase64ToUint8Array", () => {
  it("decodes url-safe base64 without padding", () => {
    expect(Array.from(urlBase64ToUint8Array("AQID"))).toEqual([1, 2, 3])
    expect(Array.from(urlBase64ToUint8Array("-_8"))).toEqual([251, 255])
  })
})

describe("describeBrowser", () => {
  it("names browser and OS", () => {
    expect(
      describeBrowser("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120 Safari/537.36")
    ).toBe("Chrome on macOS")
    expect(describeBrowser("Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0")).toBe(
      "Firefox on Linux"
    )
  })
})
