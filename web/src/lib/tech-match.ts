import type { Technology } from "@/lib/api/types"

const MIN_FUZZY = 4

export function isEcosystemWide(tech: Technology): boolean {
  return tech.type === "Ecosystem" && tech.ecosystem != null
}

export function technologyMatchesPackage(
  tech: Technology,
  ecosystem: string,
  packageName: string,
  displayName?: string
): boolean {
  if (isEcosystemWide(tech)) {
    return tech.ecosystem === ecosystem
  }
  if (tech.ecosystem && tech.ecosystem !== ecosystem) {
    return false
  }
  const tokens = namesOf(tech)
  return tokenMatches(tokens, packageName) || (displayName ? tokenMatches(tokens, displayName) : false)
}

export function catalogMatchForPackage(
  catalog: Technology[],
  ecosystem: string,
  packageName: string,
  displayName?: string
): Technology | undefined {
  return catalog.find(
    (tech) =>
      !isEcosystemWide(tech) &&
      technologyMatchesPackage(tech, ecosystem, packageName, displayName)
  )
}

function namesOf(tech: Technology): string[] {
  const names = [tech.name, tech.slug, ...tech.aliases]
  if (tech.slug.startsWith("pkg-")) names.push(tech.slug.slice(4))
  return names.filter((name) => name.trim().length > 0)
}

function tokenMatches(tokens: string[], packageName: string): boolean {
  const value = packageName.trim()
  if (!value) return false
  const lastSlash = value.lastIndexOf("/")
  const lastSegment = lastSlash >= 0 ? value.slice(lastSlash + 1) : value

  return tokens.some((token) => {
    if (equalsIgnoreCase(value, token) || equalsIgnoreCase(lastSegment, token)) return true
    if (token.length < MIN_FUZZY) return false
    const lower = value.toLowerCase()
    const t = token.toLowerCase()
    return (
      lower.startsWith(`${t}-`) ||
      lower.startsWith(`${t}/`) ||
      lower.startsWith(`@${t}/`) ||
      lower.endsWith(`/${t}`)
    )
  })
}

function equalsIgnoreCase(a: string, b: string): boolean {
  return a.localeCompare(b, undefined, { sensitivity: "accent" }) === 0
}
