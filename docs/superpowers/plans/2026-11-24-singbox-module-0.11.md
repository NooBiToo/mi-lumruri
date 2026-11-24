# Модуль sing-box (0.11.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** серверы VLESS (в т. ч. Reality), Hysteria2, Trojan и Shadowsocks через модуль sing-box, который ставится со
страницы «Модули» на флешку или во внутреннюю память; слежение за флешкой с уведомлениями.

**Architecture:** модуль — отдельный подписанный ключом релиза tar `mitt-mod-sing-box-<версия sing-box>.tar`
(манифест того же формата, что у пакета; `payload/sing-box.xz`). Каталог модулей (`payload/modules.json`: имя, версия,
имя ассета, SHA-256 и размеры) входит в подписанный основной пакет. Профиль с видом vless/hysteria2/trojan/shadowsocks
хранит в настройках только сводку (сервер, порт, параметры для показа), ссылка целиком — секрет (`secrets.profiles[id].link`).
Рендер разбирает ссылку и пишет `sing-box.json` туннеля (TUN `mitt<n>`, `auto_route: false`, один выход); служба запускает
`sing-box run` на каждый такой туннель вместо `trusttunnel_client`. Маршрутизация (метки, таблицы) не меняется.

**Spec:** `docs/superpowers/specs/2026-11-24-modules-multi-tunnel-design.md` (разделы 2–4).

## Global Constraints

- sing-box 1.14.4, официальная сборка `linux-arm64` (SHA-256 архива закреплён), x86_64 — только для лаборатории.
- Имя ассета модуля не начинается с `mi-lumruri-` (обновление пакета ищет `mi-lumruri-*.tar`).
- Модуль не связан с версией пакета: каталог в пакете называет нужную версию; другая установленная — «есть обновление».
- Проверка модуля: SHA-256 tar из каталога (подписанный пакет) и подпись манифеста закреплённым ключом.
- Хранение: `<накопитель>/mi-lumruri-modules/<имя>/` (xz как есть, FAT без exec); запуск — из RAM `$RUN/mod/<имя>/`.
- Запись об установке — `$ETC/modules.json` в /data. Удаление модуля, который использует профиль, — отказ.
- Флешка пропала: уже запущенные движки работают (RAM), уведомление одно; после перезагрузки без флешки — туннели
  модуля не поднимаются, правила по политике отказа; флешка вернулась — запуск и уведомление.
- Одиночная установка без модулей не меняется (те же файлы, процессы, правила).

## Tasks

1. **Ссылки и конфигурация sing-box (Rust, `controller/src/proxy.rs`).** Разбор `vless://`, `hysteria2://`/`hy2://`,
   `trojan://`, `ss://` (SIP002 и base64), проверка, сводка без секрета, выход sing-box и полный `sing-box.json`.
   Тесты: каждая схема, Reality, ws/grpc, IPv6-хост, процентное кодирование, ошибки.
2. **Модель, секреты, проверка.** `ProfileKind` += vless, hysteria2, trojan, shadowsocks; `Profile.proxy` (сводка);
   `ProfileSecret.link`; для видов sing-box нет endpoint/backup; `/secrets` принимает link; `/profiles` и проверки.
3. **Рендер.** `TunRender.engine` (trusttunnel | sing-box), `sing-box.json` (600) вместо client.toml; `tunnels.list`
   с четвёртым полем — движок. Тесты рендера.
4. **Модули (Rust).** `modules.rs`: каталог, установленные, `GET /modules`, `POST /modules/install` (путь — /data или
   накопитель из storage.json с местом), `POST /modules/remove` (не используется профилями) — заявки службе.
5. **Пакет и CI.** `tools/package.mjs`: tar модуля и `payload/modules.json`; CI выкладывает tar модуля в артефакт.
6. **Служба.** `mitt-module.sh install|remove` (загрузка с GitHub, проверка, распаковка), `modules_prepare` (в RAM при
   старте), движок sing-box в `tun_ctx`/`engines_start`/сторож/уведомления, `modules_watch` (флешка), уведомления
   `module_missing`/`module_back`. Лаборатория: `test-module.sh` (qemu, ARM64-модуль), загрузка — сервер sing-box
   (x86_64) в «интернете», профиль VLESS и Hysteria2 через модуль, пропажа и возврат флешки.
7. **Панель.** «Модули»: каталог, выбор накопителя, установка с ходом, обновление, удаление. «Сервер»: ссылки
   vless/hy2/trojan/ss распознаются, сервер добавляется видом sing-box (без модуля — ссылка на «Модули»), сводка.
   i18n, e2e.
8. **Документы, версия 0.11.0, релиз** (ассет модуля в релизе).
