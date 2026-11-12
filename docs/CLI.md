# CLI Reference

Полное описание всех скриптов сборки, публикации и диагностики.

---

## `scripts/build.py`

**Назначение:** Сборка rule-setов (`*.srs`), `manifest.json`, `catalog.json`, `domain-changes.json`, `report.html`, `presets.user.json`, `SHA256SUMS` и `routing-evidence.zip`.

**Зависимости:** `config/sources.json` (включая Public Suffix List), `config/service-networks.json`, `config/registry-ip-sources.json`, `config/policy.json`, `config/probes.json`, `config/tools-lock.json`, `config/manual-vpn.json`, `config/direct-exceptions.json`.

**Режимы:**
- **Онлайн** (по умолчанию) — загружает источники в `cache/sources/`.
- **Офлайн** (`--offline`) — использует только кэш, проверяет хеши.
- **Только загрузка** (`--fetch-only`) — скачивает и проверяет источники, не собирает rule-setы.

**Аргументы:**
| Аргумент | Описание |
|---|---|
| `--root PATH` | Корень репозитория (по умолчанию родительская директория скрипта). |
| `--offline` | Не обращаться к сети, использовать только кэш. |
| `--fetch-only` | Только скачать и проверить источники, не собирать. |
| `--previous PATH` | Путь к предыдущему `manifest.json` для сравнения и baseline validation. |
| `--previous-rules PATH` | Путь к предыдущему `blocked-domains.json` для семантического diff. |
| `--output PATH` | Директория результата (создаётся атомарно через временную staging-директорию). |
| `--sing-box PATH` | Путь к бинарнику sing-box (по умолчанию `.tools/sing-box[.exe]`). |

**Переменные окружения:**
| Переменная | Описание |
|---|---|
| `GITHUB_REPOSITORY` | `owner/repo` для ссылок в `catalog.json` и `manifest.json` (по умолчанию `Vanilla-SilQ-HD/Routing`). |
| `GITHUB_SHA` | Коммит, записывается в `manifest.json.environment.github_commit`. |

**Коды выхода:** `0` — успех; `1` — ошибка сборки (BuildError, валидация, компиляция, sing-box check).

**Примеры (PowerShell):**
```powershell
# Полная онлайн-сборка
& ./.venv/Scripts/python.exe scripts/build.py --output dist/first

# Офлайн-повторная сборка по кэшу
& ./.venv/Scripts/python.exe scripts/build.py --offline --previous dist/first/manifest.json --output dist/second

# Только обновление кэша источников
& ./.venv/Scripts/python.exe scripts/build.py --fetch-only
```

**Первый запуск форка:**
1. `python -m venv .venv`
2. `& ./.venv/Scripts/python.exe -m pip install --require-hashes -r requirements.txt`
3. `& ./.venv/Scripts/python.exe scripts/install_tools.py`
4. `& ./.venv/Scripts/python.exe scripts/build.py --output dist/first`