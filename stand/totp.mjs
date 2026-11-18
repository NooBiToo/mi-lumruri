// TOTP RFC 6238 (HMAC-SHA1, 6 цифр, шаг 30 с) на node:crypto — независимая от контроллера реализация
// для тестов стенда и ручной проверки входа. В панель и комплект не входит.
//   node stand/totp.mjs            — код по секрету из переменной MITT_TOTP_SECRET (секрет не передаётся аргументом)

import { createHmac } from 'node:crypto'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function base32decode(s) {
  let bits = 0
  let value = 0
  const out = []
  for (const ch of s.replace(/=+$/, '').toUpperCase()) {
    const i = ALPHABET.indexOf(ch)
    if (i < 0) throw new Error('не base32')
    value = (value << 5) | i
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

export function totp(secretB32, unixSeconds = Math.floor(Date.now() / 1000), digits = 6, step = 30) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / step)))
  const h = createHmac('sha1', base32decode(secretB32)).update(counter).digest()
  const o = h[h.length - 1] & 0xf
  const n = (h.readUInt32BE(o) & 0x7fffffff) % 10 ** digits
  return String(n).padStart(digits, '0')
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const s = process.env.MITT_TOTP_SECRET
  if (!s) {
    console.error('задайте MITT_TOTP_SECRET')
    process.exit(2)
  }
  console.log(totp(s))
}
