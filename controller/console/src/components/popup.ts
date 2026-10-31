export interface Rect {
  left: number
  top: number
  right: number
  bottom: number
  width: number
}

export function placePopup(rect: Rect, viewport: { width: number; height: number }, height = 240) {
  const width = Math.min(Math.max(rect.width, 180), Math.max(0, viewport.width - 16))
  const below = Math.max(0, viewport.height - rect.bottom - 12)
  const above = Math.max(0, rect.top - 12)
  const up = below < height && above > below
  const maxHeight = Math.min(height, up ? above : below)
  return {
    position: 'fixed' as const,
    left: `${Math.max(8, Math.min(rect.left, viewport.width - width - 8))}px`,
    top: `${up ? rect.top - maxHeight - 4 : rect.bottom + 4}px`,
    width: `${width}px`,
    maxHeight: `${maxHeight}px`,
    up,
  }
}
