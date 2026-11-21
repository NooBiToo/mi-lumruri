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
check("пробный запуск ARM64-программ пакета (mi-tt-ctl, mi-tt-admin, trusttunnel_client, nfqws2) под qemu прошёл при установке",
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
check("права: /data/mi-lumruri, etc, auth — 700; ключ TLS и secrets.json — 600",
      (L.get("data"), L.get("etc"), L.get("auth"), L.get("tls_key"), L.get("secrets")) == ("700", "700", "700", "600", "600"), L)
check("сертификат панели выпущен штатным openssl для устройства; ключ релиза закреплён при первой установке",
      L.get("cert", "").startswith("-----BEGIN CERTIFICATE-----") and len(L.get("pinned", "")) == 16, L.get("pinned"))
fi = L.get("fw_include") or ""
check("автозапуск: config include 'mitt' (type script, path /data/mi-lumruri/mitt-boot.sh — постоянная точка входа, reload 1)",
      "option type 'script'" in fi and "/data/mi-lumruri/mitt-boot.sh" in fi and "option reload '1'" in fi, fi)
au = (OUT / "after-uninstall.txt").read_text(encoding="utf-8") if (OUT / "after-uninstall.txt").exists() else ""
check("удаление: автозапуск снят, релизы удалены, настройки и ключи сохранены",
      st("I9-uninstall")[0] == 0 and not st("I9-uninstall")[4] and "etc" in au and "releases" not in au and "current.ver" not in au, [st("I9-uninstall"), au.split()])
check("другая модель (RA70): отказ до изменений", st("I10-wrong-model")[0] == 3 and "RA70" in S.get("I10-wrong-model", {}).get("out", "") and st("I10-wrong-model")[1] is None,
      S.get("I10-wrong-model", {}).get("out", "")[-160:])
ns = (OUT / "no-space-data.txt").read_text(encoding="utf-8").strip() if (OUT / "no-space-data.txt").exists() else "?"
check("мало места на /data (tmpfs 4 МиБ): отказ с указанием свободного и нужного объёма, /data не изменён",
      st("I11-no-space")[0] == 3 and "свободно" in S.get("I11-no-space", {}).get("out", "") and ns == "", [S.get("I11-no-space", {}).get("out", "")[-200:], ns])
V4 = "0.1.3-stage12"
ffp = (OUT / "foreign-fp.txt").read_text(encoding="utf-8").strip() if (OUT / "foreign-fp.txt").exists() else ""
k2 = S.get("K2-foreign-no-flag", {}).get("out", "")
check("другой ключ без --trust-key: отказ, в сообщении оба отпечатка и подсказка --trust-key=<новый>, current = v1",
      st("K2-foreign-no-flag")[:2] == (3, V1) and len(ffp) == 16 and f"--trust-key={ffp}" in k2 and "закреплён" in k2, k2[-300:])
check("--trust-key с чужим отпечатком: отказ, current = v1",
      st("K3-foreign-wrong-fp")[:2] == (3, V1) and "не совпадает" in S.get("K3-foreign-wrong-fp", {}).get("out", ""), S.get("K3-foreign-wrong-fp", {}).get("out", "")[-200:])
kat = (OUT / "key-after-trust.txt").read_text(encoding="utf-8").strip() if (OUT / "key-after-trust.txt").exists() else ""
check("--trust-key с верным отпечатком: установлено, current = v4, previous = v1, закреплён новый ключ",
      st("K4-foreign-trusted")[:3] == (0, V4, V1) and "закреплён новый ключ" in S.get("K4-foreign-trusted", {}).get("out", "") and kat and kat != L.get("pinned"),
      [st("K4-foreign-trusted"), S.get("K4-foreign-trusted", {}).get("out", "")[-200:], kat])
check("после смены ключа пакет со старым ключом не принимается: отказ, current = v4",
      st("K5-old-key-refused")[:2] == (3, V4), S.get("K5-old-key-refused", {}).get("out", "")[-200:])
X = {}
if (OUT / "store.jsonl").exists():
    for line in (OUT / "store.jsonl").read_text(encoding="utf-8").splitlines():
        d = json.loads(line)
        X[d["id"]] = d


def xs(i):
    d = X.get(i, {})
    # пустой каталог releases в /data равнозначен его отсутствию
    return (S.get(i, {}).get("exit"), d.get("current"), d.get("previous"), d.get("data_releases") or None, d.get("store_releases"))


check("внешнее хранилище (--store): релиз лежит на накопителе, в /data только указатели; точка входа ждёт накопитель",
      xs("S1-store-fresh") == (0, V1, None, None, [V1]) and (X.get("S1-store-fresh", {}).get("store") or "").endswith("/mnt/usb/mi-lumruri")
      and X.get("S1-store-fresh", {}).get("stub_waits"), [xs("S1-store-fresh"), X.get("S1-store-fresh", {}).get("store")])
check("обновление без --store: хранилище запомнено, current = v2, previous = v1, оба на накопителе",
      xs("S2-store-update") == (0, V2, V1, None, [V1, V2]), xs("S2-store-update"))
check("откат при внешнем хранилище: current = v1, previous = v2", xs("S3-store-rollback")[:3] == (0, V1, V2), xs("S3-store-rollback"))
check("удаление при внешнем хранилище: релизы убраны с накопителя, указатель store снят",
      xs("S4-store-uninstall")[0] == 0 and xs("S4-store-uninstall")[4] is None and X.get("S4-store-uninstall", {}).get("store") is None, xs("S4-store-uninstall"))
check("перенос из /data на накопитель при обновлении: /data освобождён, current = v2, откат на прежний релиз снят",
      xs("S6-move") == (0, V2, None, None, [V2]), xs("S6-move"))
sa = (OUT / "store-absent-data.txt").read_text(encoding="utf-8").strip() if (OUT / "store-absent-data.txt").exists() else "?"
check("накопитель не подключён: отказ до изменений, /data не тронут",
      S.get("S7-store-absent", {}).get("exit") == 3 and "накопитель" in S.get("S7-store-absent", {}).get("out", "") and sa == "", [S.get("S7-store-absent", {}).get("out", "")[-200:], sa])
M = {}
if (OUT / "migrate.jsonl").exists():
    for line in (OUT / "migrate.jsonl").read_text(encoding="utf-8").splitlines():
        d = json.loads(line)
        M[d["id"]] = d
OLD = "ci-05a1131e08df"
m1, m2, m3, m4, m5, m6 = (M.get(k, {}) for k in ("M1-old040", "M2-migrate-refused", "M3-migrate", "M4-repeat", "M5-rollback-040", "M6-uninstall"))
check("перенос 0.4.0 → новая версия: релиз 0.4.0 установлен в прежнюю раскладку /data/mi-trusttunnel",
      S.get("M1-old040", {}).get("exit") == 0 and m1.get("old_link") == "dir" and m1.get("current") == OLD and "/data/mi-trusttunnel/mitt-boot.sh" in (m1.get("fw") or ""), [S.get("M1-old040", {}).get("out", "")[-200:], m1])
check("перенос при отказе по ключу: настройки уже в /data/mi-lumruri, ссылка на месте, current = 0.4.0, автозапуск через ссылку работает",
      S.get("M2-migrate-refused", {}).get("exit") == 3 and m2.get("new_dir") and m2.get("old_link") == "mi-lumruri" and m2.get("current") == OLD, [S.get("M2-migrate-refused", {}).get("out", "")[-200:], m2])
check("установка новой версии: current = v2, previous = 0.4.0, настройки и вход сохранены, новый ключ закреплён",
      S.get("M3-migrate", {}).get("exit") == 0 and m3.get("current") == V2 and m3.get("previous") == OLD and m3.get("marker") == "user-settings" and m3.get("auth")
      and m3.get("pinned") == L.get("pinned"), [S.get("M3-migrate", {}).get("out", "")[-300:], m3])
check("после переноса: автозапуск firewall — /data/mi-lumruri/mitt-boot.sh, точка входа с новыми путями, /tmp/mi-trusttunnel убран",
      "/data/mi-lumruri/mitt-boot.sh" in (m3.get("fw") or "") and m3.get("stub_new") and not m3.get("tmp_old"), m3)
check("повторная установка: переноса нет (ссылка), current = v2",
      S.get("M4-repeat", {}).get("exit") == 0 and "перенос" not in S.get("M4-repeat", {}).get("out", "") and m4.get("current") == V2 and m4.get("old_link") == "mi-lumruri", m4)
check("откат на 0.4.0 после переноса: current = 0.4.0, его загрузчик доступен через ссылку",
      S.get("M5-rollback-040", {}).get("exit") == 0 and m5.get("current") == OLD and m5.get("previous") == V2, [S.get("M5-rollback-040", {}).get("out", "")[-200:], m5])
m5b = M.get("M5b-reinstall", {})
ob = (OUT / "old-boot.log").read_text(encoding="utf-8").split() if (OUT / "old-boot.log").exists() else []
check("установка после отката на 0.4.0: служба 0.4 остановлена её загрузчиком из /tmp/mi-trusttunnel, каталог убран, current = v2",
      S.get("M5b-reinstall", {}).get("exit") == 0 and ob == ["stop"] and not m5b.get("tmp_old") and m5b.get("current") == V2, [ob, m5b])
check("удаление: ссылка /data/mi-trusttunnel снята, настройки в /data/mi-lumruri сохранены",
      S.get("M6-uninstall", {}).get("exit") == 0 and m6.get("old_link") is None and m6.get("marker") == "user-settings", m6)
ok = all(c["ok"] for c in checks)
json.dump({"ok": ok, "checks": checks, "steps": S}, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
md = ["| Проверка | Детали | Итог |", "|---|---|---|"] + [f"| {c['check']} | {c['detail'].replace('|', '/')} | {'да' if c['ok'] else 'НЕТ'} |" for c in checks]
(OUT / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print("\n".join(md))
print(f"проверок: {sum(c['ok'] for c in checks)} из {len(checks)}")
print("ИТОГ:", "ПРОЙДЕНО" if ok else "НЕ ПРОЙДЕНО")
sys.exit(0 if ok else 1)
