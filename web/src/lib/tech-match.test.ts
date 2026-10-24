import { describe, expect, it } from "vitest"
import type { Technology } from "@/lib/api/types"
import {
  catalogMatchForPackage,
  isEcosystemWide,
  technologyMatchesPackage,
} from "@/lib/tech-match"

function tech(partial: Partial<Technology> & Pick<Technology, "slug" | "name" | "type">): Technology {
  return {
    id: partial.id ?? partial.slug,
    aliases: partial.aliases ?? [],
    ecosystem: partial.ecosystem ?? null,
    following: partial.following ?? false,
    ...partial,
  }
}

describe("technologyMatchesPackage", () => {
  it("treats ecosystem catalog entries as covering every package in that ecosystem", () => {
    const npm = tech({ name: "npm", slug: "npm", type: "Ecosystem", ecosystem: "Npm" })
    expect(isEcosystemWide(npm)).toBe(true)
    expect(technologyMatchesPackage(npm, "Npm", "left-pad")).toBe(true)
    expect(technologyMatchesPackage(npm, "PyPI", "left-pad")).toBe(false)
  })

  it("matches prefixed and scoped packages for a framework", () => {
    const react = tech({ name: "React", slug: "react", type: "Framework", ecosystem: "Npm" })
    expect(technologyMatchesPackage(react, "Npm", "react")).toBe(true)
    expect(technologyMatchesPackage(react, "Npm", "react-dom")).toBe(true)
    expect(technologyMatchesPackage(react, "Npm", "@types/react")).toBe(true)
    expect(technologyMatchesPackage(react, "Npm", "preact")).toBe(false)
  })
})

describe("catalogMatchForPackage", () => {
  const catalog = [
    tech({ name: "npm", slug: "npm", type: "Ecosystem", ecosystem: "Npm" }),
    tech({ name: "React", slug: "react", type: "Framework", ecosystem: "Npm", following: true }),
    tech({ name: "lodash", slug: "pkg-lodash", type: "Package", ecosystem: "Npm" }),
  ]

  it("prefers a non-ecosystem catalog technology", () => {
    expect(catalogMatchForPackage(catalog, "Npm", "react-dom")?.slug).toBe("react")
    expect(catalogMatchForPackage(catalog, "Npm", "lodash")?.slug).toBe("pkg-lodash")
  })

  it("returns undefined when nothing specific matches", () => {
    expect(catalogMatchForPackage(catalog, "Npm", "left-pad")).toBeUndefined()
  })
})
