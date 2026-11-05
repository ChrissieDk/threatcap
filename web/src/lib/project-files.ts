export const PASTE_FILE_TYPES: { name: string; label: string }[] = [
  { name: "package.json", label: "package.json (npm)" },
  { name: "package-lock.json", label: "package-lock.json (npm)" },
  { name: "yarn.lock", label: "yarn.lock (npm)" },
  { name: "pnpm-lock.yaml", label: "pnpm-lock.yaml (npm)" },
  { name: "requirements.txt", label: "requirements.txt (Python)" },
  { name: "pasted.csproj", label: ".csproj (.NET)" },
  { name: "go.mod", label: "go.mod (Go)" },
  { name: "Cargo.toml", label: "Cargo.toml (Rust)" },
  { name: "Cargo.lock", label: "Cargo.lock (Rust)" },
  { name: "pom.xml", label: "pom.xml (Maven)" },
  { name: "bom.json", label: "CycloneDX / SPDX SBOM" },
]

/** Guesses which kind of dependency file pasted text is. Returns a file name the server understands. */
export function detectFileName(content: string): string {
  const text = content.trim()
  if (text.startsWith("{")) {
    if (/"bomFormat"\s*:\s*"CycloneDX"/.test(text) || /"spdxVersion"/.test(text)) return "bom.json"
    if (/"lockfileVersion"\s*:/.test(text)) return "package-lock.json"
    return "package.json"
  }
  if (text.startsWith("<")) {
    return /<modelVersion>|<artifactId>/.test(text) && !/<PackageReference|<PackageVersion/.test(text)
      ? "pom.xml"
      : "pasted.csproj"
  }
  if (/^lockfileVersion:/m.test(text) || /^packages:\s*$/m.test(text)) return "pnpm-lock.yaml"
  if (/^\[\[package\]\]/m.test(text)) return "Cargo.lock"
  if (/^\[(dependencies|dev-dependencies|package)\]/m.test(text)) return "Cargo.toml"
  if (/^module\s+\S+/m.test(text) || /^require\s/m.test(text)) return "go.mod"
  if (/^# yarn lockfile/m.test(text) || /^__metadata:/m.test(text)) return "yarn.lock"
  return "requirements.txt"
}
