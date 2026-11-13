// The falcon mark, painted with currentColor through a mask so it follows the theme.
export function LogoMark({ size = 24, className }: { size?: number; className?: string }) {
  const style = {
    width: size * (434 / 508),
    height: size,
    backgroundColor: "currentColor",
    maskImage: "url(/logo-mark.png)",
    WebkitMaskImage: "url(/logo-mark.png)",
    maskSize: "contain",
    WebkitMaskSize: "contain",
    maskRepeat: "no-repeat",
    WebkitMaskRepeat: "no-repeat",
    maskPosition: "center",
    WebkitMaskPosition: "center",
  } as const
  return <span aria-hidden className={`inline-block shrink-0 ${className ?? ""}`} style={style} />
}
