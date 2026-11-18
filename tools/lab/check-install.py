"""Проверка лаборатории установщика (этап 12): коды и состояние после каждого шага, раскладка и права, автозапуск."""
import json
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
S = {}
for line in (OUT / "steps.jsonl").read_text(encoding="utf-8").splitlines():
    d = json.loads(line)
    S[d["id"]] = d
L = json.loads((OUT / "layout.json").read_text(encoding="utf-8")) if (OUT / "layout.json").exists() else {}
checks = []


def check(name, ok, detail=""):
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})


def st(i):
    d = S.get(i, {})
    return (d.get("exit"), d.get("current"), d.get("previous"), d.get("releases"), d.get("include"))


V1, V2, V5 = "0.1.0-stage12", "0.1.1-stage12", "0.1.2-stage12"
check("свежая установка: код 0, current = v1, автозапуск зарегистрирован в firewall (uci стока)", st("I1-fresh")[:2] == (0, V1) and st("I1-fresh")[4], st("I1-fresh"))
check("пробный запуск ARM64-программ пакета (mi-tt-ctl, mi-tt-admin, mihomo, dnscrypt-proxy, nfqws2) под qemu прошёл при установке",
      S.get("I1-fresh", {}).get("exit") == 0, S.get("I1-fresh", {}).get("out", "")[-200:])
check("повторная установка того же релиза: код 0, «уже установлен», current без изменений",
      st("I2-repeat")[:2] == (0, V1) and "уже установлен" in S.get("I2-repeat", {}).get("out", ""), st("I2-repeat"))
check("обновление: current = v2, previous = v1", st("I3-update")[:3] == (0, V2, V1), st("I3-update"))
check("подменённый файл (подпись манифеста верна, хэш файла нет): отказ, current = v2, релиз не скопирован",
      st("I4-tampered")[0] == 3 and st("I4-tampered")[1] == V2 and not any("0.1.4" in r for r in st("I4-tampered")[3]), S.get("I4-tampered", {}).get("out", "")[-200:])
check("пакет, подписанный чужим ключом: отказ по закреплённому ключу, current = v2",
      st("I5-foreign-key")[0] == 3 and st("I5-foreign-key")[1] == V2 and "подпись" in S.get("I5-foreign-key", {}).get("out", ""), S.get("I5-foreign-key", {}).get("out", "")[-200:])
check("прерывание во время копирования (kill -9): current = v2 (прежний), незавершённая копия .tmp не стала релизом",
      st("I6-interrupted")[0] not in (0, None) and st("I6-interrupted")[1] == V2 and f"{V5}.tmp" in st("I6-interrupted")[3] and V5 not in st("I6-interrupted")[3], st("I6-interrupted"))
check("повтор после прерывания: current = v5, .tmp убран, хранятся только current и previous",
      st("I7-after-interrupt")[:3] == (0, V5, V2) and st("I7-after-interrupt")[3] == [V2, V5], st("I7-after-interrupt"))
check("откат: current = v2, previous = v5", st("I8-rollback")[:3] == (0, V2, V5), st("I8-rollback"))
check("права: /data/mi-trusttunnel, etc, auth — 700; ключ TLS и secrets.json — 600",
      (L.get("data"), L.get("etc"), L.get("auth"), L.get("tls_key"), L.get("secrets")) == ("700", "700", "700", "600", "600"), L)
check("сертификат панели выпущен штатным openssl для устройства; ключ релиза закреплён при первой установке",
      L.get("cert", "").startswith("-----BEGIN CERTIFICATE-----") and len(L.get("pinned", "")) == 16, L.get("pinned"))
fi = L.get("fw_include") or ""
check("автозапуск: config include 'mitt' (type script, path /data/mi-trusttunnel/mitt-boot.sh — постоянная точка входа, reload 1)",
      "option type 'script'" in fi and "/data/mi-trusttunnel/mitt-boot.sh" in fi and "option reload '1'" in fi, fi)
au = (OUT / "after-uninstall.txt").read_text(encoding="utf-8") if (OUT / "after-uninstall.txt").exists() else ""
check("удаление: автозапуск снят, релизы удалены, настройки и ключи сохранены",
      st("I9-uninstall")[0] == 0 and not st("I9-uninstall")[4] and "etc" in au and "releases" not in au and "current.ver" not in au, [st("I9-uninstall"), au.split()])
check("другая модель (RA70): отказ до изменений", st("I10-wrong-model")[0] == 3 and "RA70" in S.get("I10-wrong-model", {}).get("out", "") and st("I10-wrong-model")[1] is None,
      S.get("I10-wrong-model", {}).get("out", "")[-160:])
ns = (OUT / "no-space-data.txt").read_text(encoding="utf-8").strip() if (OUT / "no-space-data.txt").exists() else "?"
check("мало места на /data (tmpfs 4 МиБ): отказ с указанием свободного и нужного объёма, /data не изменён",
      st("I11-no-space")[0] == 3 and "свободно" in S.get("I11-no-space", {}).get("out", "") and ns == "", [S.get("I11-no-space", {}).get("out", "")[-200:], ns])
ok = all(c["ok"] for c in checks)
json.dump({"ok": ok, "checks": checks, "steps": S}, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
md = ["| Проверка | Детали | Итог |", "|---|---|---|"] + [f"| {c['check']} | {c['detail'].replace('|', '/')} | {'да' if c['ok'] else 'НЕТ'} |" for c in checks]
(OUT / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print("\n".join(md))
print(f"проверок: {sum(c['ok'] for c in checks)} из {len(checks)}")
print("ИТОГ:", "ПРОЙДЕНО" if ok else "НЕ ПРОЙДЕНО")
sys.exit(0 if ok else 1)
