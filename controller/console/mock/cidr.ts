// Input/output behavior is calibrated by cidr-corpus.json, not a general PG compatibility claim.
function ipv4Parts(address: string, strict = false): number[] | undefined {
  const parts = address.split('.')
  if (parts.length > 4 || strict && parts.length !== 4) return
  if (parts.some(p => !/^\d+$/.test(p) || Number(p) > 255 || strict && String(Number(p)) !== p)) return
  return parts.map(Number)
}
function ipv6Parts(address: string): number[] | undefined {
  if (address.includes('.')) {
    const last = address.lastIndexOf(':')
    if (last < 0) return
    const tail = ipv4Parts(address.slice(last + 1), true)
    if (!tail) return
    address = address.slice(0, last + 1)
      + ((tail[0]! << 8) + tail[1]!).toString(16) + ':' + ((tail[2]! << 8) + tail[3]!).toString(16)
  }
  const halves = address.split('::')
  if (halves.length > 2) return
  const split = (s: string) => s ? s.split(':') : []
  const left = split(halves[0]!), right = split(halves[1] ?? '')
  if ([...left, ...right].some(p => !/^[0-9a-fA-F]{1,4}$/.test(p))) return
  const zeros = 8 - left.length - right.length
  if (halves.length === 1 ? zeros !== 0 : zeros < 1) return
  return [...left.map(p => parseInt(p, 16)), ...Array(zeros).fill(0), ...right.map(p => parseInt(p, 16))]
}
function ipv6Text(groups: number[]): string {
  // Corpus distinguishes compatible/mapped dotted tails from :: and ::1.
  if (groups.slice(0, 5).every(n => n === 0)
    && (groups[5] === 0xffff || groups[5] === 0 && groups[6] !== 0)) {
    const tail = [groups[6]! >> 8, groups[6]! & 255, groups[7]! >> 8, groups[7]! & 255].join('.')
    return (groups[5] === 0xffff ? '::ffff:' : '::') + tail
  }
  let best = -1, length = 1
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] !== 0) continue
    let end = i
    while (end < groups.length && groups[end] === 0) end++
    if (end - i > length) {
      best = i
      length = end - i
    }
    i = end - 1
  }
  const parts = groups.map(n => n.toString(16))
  return best < 0 ? parts.join(':')
    : parts.slice(0, best).join(':') + '::' + parts.slice(best + length).join(':')
}
export function cidrText(raw: string): string | undefined {
  const [address = '', width, extra] = raw.split('/')
  if (extra !== undefined || width !== undefined && !/^\d+$/.test(width)) return
  const ipv6 = address.includes(':')
  let groups: number[], mask: number
  if (ipv6) {
    const parsed = ipv6Parts(address)
    if (!parsed || width !== undefined && width.length > 1 && width.startsWith('0')) return
    groups = parsed
    mask = width === undefined ? 128 : Number(width)
  } else {
    const parsed = ipv4Parts(address)
    if (!parsed) return
    const first = parsed[0]!
    const inferred = first < 128 ? 8 : first < 192 ? 16 : first < 224 ? 24 : first < 240 ? 4 : 32
    mask = width === undefined
      ? parsed.length === 1 && inferred === 4 ? 4 : Math.max(inferred, parsed.length * 8) : Number(width)
    groups = [...parsed, ...Array(4 - parsed.length).fill(0)]
  }
  const bits = ipv6 ? 128 : 32, size = ipv6 ? 16 : 8
  if (mask > bits) return
  const value = groups.reduce((n, g) => (n << BigInt(size)) + BigInt(g), 0n)
  if (value & ((1n << BigInt(bits - mask)) - 1n)) return
  return (ipv6 ? ipv6Text(groups) : groups.join('.')) + '/' + mask
}
// Match the Go handler's parsed-address predicate, independently of mask syntax.
export function isIPv4MappedPrefix(raw: string): boolean {
  const address = raw.split('/')[0]!, zone = address.indexOf('%')
  if (zone >= 0 && zone === address.length - 1) return false
  const groups = ipv6Parts(zone < 0 ? address : address.slice(0, zone))
  return !!groups && groups.slice(0, 5).every(n => n === 0) && groups[5] === 0xffff
}
// net.ParseCIDR checks the address and mask, but need not have zero host bits.
export function ipv6DefaultPrefix(raw: string): boolean {
  const [address = '', width, extra] = raw.split('/')
  return extra === undefined && width !== undefined && /^\d+$/.test(width)
    && Number(width) === 0 && !!ipv6Parts(address)
}
