// Значки сервисов каталога: логотипы simple-icons (CC0) там, где они есть, иначе значки Lucide (ISC).
// Импорт по одному значку: в сборку попадают только используемые.

import type { Component } from 'vue'
import { siAdguard, siCloudflare, siDigitalocean, siDiscord, siGooglegemini, siGooglemeet, siGoogle, siGoogleplay, siHetzner, siNextdns, siInstagram, siOvh, siQuad9, siRoblox, siTelegram, siTiktok, siX, siYoutube } from 'simple-icons'
import { Ban, Cloud, Earth, Film, Globe, Landmark, Layers, Newspaper, Server, Tv } from 'lucide-vue-next'

export type ServiceIcon = { kind: 'brand'; path: string; hex: string } | { kind: 'lucide'; icon: Component }

const brand = (i: { path: string; hex: string }): ServiceIcon => ({ kind: 'brand', path: i.path, hex: `#${i.hex}` })
const lucide = (icon: Component): ServiceIcon => ({ kind: 'lucide', icon })

const ICONS: Record<string, ServiceIcon> = {
  youtube: brand(siYoutube),
  meta: brand(siInstagram),
  discord: brand(siDiscord),
  telegram: brand(siTelegram),
  google_ai: brand(siGooglegemini),
  tiktok: brand(siTiktok),
  twitter: brand(siX),
  google_play: brand(siGoogleplay),
  google_meet: brand(siGooglemeet),
  roblox: brand(siRoblox),
  hdrezka: lucide(Film),
  anime: lucide(Tv),
  news: lucide(Newspaper),
  block: lucide(Ban),
  geoblock: lucide(Earth),
  russia_inside: lucide(Landmark),
  cloudflare: brand(siCloudflare),
  cloudfront: lucide(Cloud),
  digitalocean: brand(siDigitalocean),
  hetzner: brand(siHetzner),
  ovh: brand(siOvh),
  hodca: lucide(Layers),
}

export function serviceIcon(id: string): ServiceIcon {
  return ICONS[id] ?? lucide(Globe)
}

/** Значки готовых DNS-серверов (manage.ts: DNS_PRESETS); «Свой адрес» — значок сервера. */
const DNS_ICONS: Record<string, ServiceIcon> = {
  cloudflare: brand(siCloudflare),
  quad9: brand(siQuad9),
  google: brand(siGoogle),
  adguard: brand(siAdguard),
  nextdns: brand(siNextdns),
}

export function dnsIcon(id: string): ServiceIcon {
  return DNS_ICONS[id] ?? lucide(Server)
}

/** Почти чёрный цвет бренда (X, TikTok, Roblox) рисуется цветом текста: иначе пропадёт в тёмной теме. */
export function brandColor(hex: string): string | null {
  const n = Number.parseInt(hex.slice(1), 16)
  return Math.max((n >> 16) & 255, (n >> 8) & 255, n & 255) < 100 ? null : hex
}
