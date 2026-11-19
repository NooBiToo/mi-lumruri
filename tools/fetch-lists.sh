#!/usr/bin/env bash
# Снимок списков сайтов itdoginfo/allow-domains в package/lists (закреплённый коммит), с проверкой каждого файла
# через mi-tt-ctl category-check и записью catalog.json.
#   tools/fetch-lists.sh <sha коммита | main>
# Нужны: curl, node и собранный `bash tools/cargo.sh build --release --locked` (controller/target/release/mi-tt-ctl).
# Файл, не прошедший проверку (HTML вместо списка, неразбираемые строки), в каталог не попадает; список таких — в конце.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=itdoginfo/allow-domains
REF=${1:?укажите коммит или main}
SHA=$(curl -sSfL --proto '=https' "https://api.github.com/repos/$REPO/commits/$REF" -H 'Accept: application/vnd.github.sha')
[[ $SHA =~ ^[0-9a-f]{40}$ ]] || { echo "не удалось определить коммит: $SHA" >&2; exit 2; }
DATE=$(curl -sSfL --proto '=https' "https://api.github.com/repos/$REPO/commits/$SHA" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).commit.committer.date.slice(0,10)))')
CTL=controller/target/release/mi-tt-ctl; [ -x "$CTL" ] || CTL=$CTL.exe
[ -x "$CTL" ] || { echo "нет $CTL: bash tools/cargo.sh build --release --locked" >&2; exit 2; }
RAW="https://raw.githubusercontent.com/$REPO/$SHA"
OUT=package/lists
rm -rf "$OUT"; mkdir -p "$OUT/Services" "$OUT/Categories" "$OUT/Russia" "$OUT/Subnets/IPv4"

# id|название|группа|путь к списку доменов (регистр подсетей — нижний)
ROWS='youtube|YouTube|Сервисы|Services/youtube.lst
meta|Instagram и Facebook|Сервисы|Services/meta.lst
discord|Discord|Сервисы|Services/discord.lst
telegram|Telegram|Сервисы|Services/telegram.lst
google_ai|ChatGPT и Google AI|Сервисы|Services/google_ai.lst
tiktok|TikTok|Сервисы|Services/tiktok.lst
twitter|X (Twitter)|Сервисы|Services/twitter.lst
google_play|Google Play|Сервисы|Services/google_play.lst
google_meet|Google Meet|Сервисы|Services/google_meet.lst
roblox|Roblox|Сервисы|Services/roblox.lst
hdrezka|HDRezka|Сервисы|Services/hdrezka.lst
anime|Аниме|Категории|Categories/anime.lst
news|Новости|Категории|Categories/news.lst
block|Заблокированные сайты|Категории|Categories/block.lst
geoblock|Сайты, закрытые для России|Категории|Categories/geoblock.lst
russia_inside|Всё заблокированное в России (общий список)|Россия|Russia/inside-raw.lst
cloudflare|Cloudflare|Хостинги и CDN|Services/cloudflare.lst
cloudfront|Amazon CloudFront|Хостинги и CDN|Services/cloudfront.lst
digitalocean|DigitalOcean|Хостинги и CDN|Services/digitalocean.lst
hetzner|Hetzner|Хостинги и CDN|Services/hetzner.lst
ovh|OVH|Хостинги и CDN|Services/ovh.lst
hodca|Хостинги (Hetzner, OVH, Cloudflare…)|Хостинги и CDN|Categories/hodca.lst'

fetch() { curl -sSfL --proto '=https' "$RAW/$1" -o "$OUT/$1"; }
: > "$OUT/.rows"; BAD=()
while IFS='|' read -r id name group dom; do
  if ! fetch "$dom" || ! "$CTL" category-check domain "$OUT/$dom" >/dev/null; then
    BAD+=("$dom"); rm -f "$OUT/$dom"; continue
  fi
  ip=null; sub="Subnets/IPv4/$id.lst"
  if curl -sfL --proto '=https' "$RAW/$sub" -o "$OUT/$sub"; then
    if "$CTL" category-check ip "$OUT/$sub" >/dev/null; then ip=$sub; else BAD+=("$sub"); rm -f "$OUT/$sub"; fi
  else rm -f "$OUT/$sub"; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$name" "$group" "$dom" "$ip" >> "$OUT/.rows"
done <<< "$ROWS"

node -e '
const fs=require("fs"),[,sha,date,out]=process.argv;
const services=fs.readFileSync(out+"/.rows","utf8").trim().split("\n").map(l=>{const [id,name,group,domains,ip]=l.split("\t");return {id,name,group,domains,ipv4:ip==="null"?null:ip}});
fs.writeFileSync(out+"/catalog.json",JSON.stringify({source:"itdoginfo/allow-domains",commit:sha,date,services},null,2)+"\n");
' "$SHA" "$DATE" "$OUT"
rm -f "$OUT/.rows"
echo "коммит $SHA ($DATE), размер: $(du -sk "$OUT" | cut -f1) КБ"
[ ${#BAD[@]} -eq 0 ] || echo "НЕ ПРОШЛИ ПРОВЕРКУ: ${BAD[*]}"
