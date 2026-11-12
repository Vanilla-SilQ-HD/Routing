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
---

## `scripts/publish_release.py`

**Назначение:** Проверка кандидата (инвентарь, SHA-256, рецепт, компилятор) и публикация через draft → verify → Latest. Запускается только из доверенного main-workflow (`GITHUB_REF=refs/heads/main`, события `push`/`schedule`/`workflow_dispatch`).

**Аргументы:**

| Аргумент | Описание |
|---|---|
| `--input PATH` | Каталог кандидата (по умолчанию `incoming/dist`). |
| `--output PATH` | Каталог подготовленных release-ассетов (по умолчанию `release`). |
| `--root PATH` | Корень checkout для сверки рецепта (по умолчанию `.`). |

**Переменные окружения:** `GITHUB_REPOSITORY`, `GITHUB_SHA`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_TOKEN`, опционально `RESET_BASELINE=true` (только `workflow_dispatch`), `GITHUB_STEP_SUMMARY`.

**Гарантии:** опубликованный Latest никогда не перезаписывается и не удаляется. При сбое загрузки или проверки ассета черновик удаляется (rollback); при сбое самого `publish` удаления не происходит. Если fingerprint не изменился — результат `unchanged`, новый релиз не создаётся.

### Очистка старых релизов (retention)

```powershell
# Dry-run (по умолчанию): только показывает, что было бы удалено
& ./.venv/Scripts/python.exe scripts/publish_release.py retention --keep 5

# Реальное удаление: оставить Latest + 5 новейших опубликованных релизов
& ./.venv/Scripts/python.exe scripts/publish_release.py retention --keep 5 --apply
```

Latest и черновики защищены всегда. Требуются `GITHUB_REPOSITORY` и `GITHUB_TOKEN` с правом `contents: write`.

---

## Проверка качества

```powershell
& ./.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
& ./.venv/Scripts/python.exe -m ruff check scripts tests
& ./.venv/Scripts/python.exe -m coverage run -m unittest discover -s tests -v
& ./.venv/Scripts/python.exe -m coverage report --fail-under=60
```

Те же проверки выполняет job `quality` в GitHub Actions для push и pull request; публикация релиза возможна только из main.
