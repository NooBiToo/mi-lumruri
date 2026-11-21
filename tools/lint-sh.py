"""Сценарии роутера под штатный BusyBox ash 1.25.1 (RC06 1.1.38): запрет конструкций, которых там нет или которые
ведут себя иначе. Пример, ради которого проверка появилась: `sleep 0.2` в этом BusyBox сразу завершается с ошибкой,
и цикл ожидания не ждёт (паузы меньше секунды — `usleep` или функция `nap`).
  python tools/lint-sh.py            — проверить package/install.sh и package/scripts/*.sh; код 1 при нарушениях
Строку можно пропустить комментарием `# lint-sh: allow <причина>`."""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = [ROOT / "package" / "install.sh", *sorted((ROOT / "package" / "scripts").glob("*.sh")), *sorted((ROOT / "tools" / "device").glob("*.sh"))]
RULES = [
    (r"\bsleep\s+[0-9]*\.[0-9]", "дробный sleep: BusyBox стока сразу выходит с ошибкой — usleep <мкс> или nap"),
    (r"\[\[", "[[ … ]] — это bash, в ash используйте [ … ]"),
    (r"\$'", "$'…' — это bash"),
    (r"(^|[;&|]\s*)(function)\s+\w+", "function name — это bash, пишите name() { … }"),
    (r"\becho\s+-e\b", "echo -e ведёт себя по-разному, используйте printf"),
    (r"\bgrep\s+(-\w*P|--perl)", "grep -P нет в BusyBox"),
    (r"\breadlink\s+-f\b", "readlink -f может отсутствовать — используйте cd \"$(dirname …)\" && pwd"),
    (r"\bmv\s+-T\b", "mv -T нет в BusyBox 1.25"),
    (r"\blocal\s+-[aA]\b|\bdeclare\b", "массивы и declare — это bash"),
    (r"<<<", "here-string <<< — это bash"),
    (r"\$\{[A-Za-z_]+:[0-9]", "${var:offset} — это bash"),
    (r"\$\{[A-Za-z_]+//", "${var//a/b} — это bash"),
    (r"(^|\s)source\s", "source — это bash, используйте ."),
    (r"\bsed\s+-E\b|\bsed\s+-r\b", "sed -E/-r: держимся базовых регулярных выражений BusyBox"),
]


def main():
    bad = 0
    for f in FILES:
        heredoc = None
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            # тело here-document (например, Lua или конфигурация) — не сценарий
            if heredoc:
                if line.strip() == heredoc:
                    heredoc = None
                continue
            m = re.search(r"<<-?\s*'?\"?([A-Z_]+)'?\"?", line)
            code = line.split(" #", 1)[0] if not line.lstrip().startswith("#") else ""
            if "lint-sh: allow" not in line:
                for pat, why in RULES:
                    if re.search(pat, code):
                        print(f"{f.relative_to(ROOT)}:{n}: {why}\n    {line.strip()}")
                        bad += 1
            if m and "<<<" not in line:
                heredoc = m.group(1)
    print(f"lint-sh: {len(FILES)} файлов, нарушений: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
