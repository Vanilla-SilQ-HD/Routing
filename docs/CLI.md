# CLI Reference

Команды выполняются из корня репозитория. В примерах используется `.venv/Scripts/python.exe` для Windows PowerShell; в Linux замените его на `.venv/bin/python`.

## Установка

```powershell
python -m venv .venv
& ./.venv/Scripts/python.exe -m pip install --require-hashes -r requirements.txt
& ./.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
& ./.venv/Scripts/python.exe scripts/install_tools.py
```

Runtime-зависимости закреплены версией и SHA-256 в `requirements.txt`. Версии инструментов разработки зафиксированы в `requirements-dev.txt`. Python API можно установить локально командой `python -m pip install .` и затем импортировать `routing`.

Общая переменная `ROUTING_LOG_LEVEL` принимает `DEBUG`, `INFO`, `WARNING` или `ERROR`. У основных CLI есть также флаг `--debug`.

## `scripts/build.py`

Собирает шесть SRS, исходные JSON/TXT, `manifest.json`, `catalog.json`, `presets.user.json`, `domain-changes.json`, `report.html` и `SHA256SUMS`.

| Аргумент | Назначение |
|---|---|
| `--root PATH` | Корень репозитория; по умолчанию определяется из расположения скрипта. |
| `--offline` | Использовать только проверенный кеш; сетевые запросы запрещены. |
| `--fetch-only` | Только скачать и хешировать источники. |
| `--previous PATH` | Предыдущий `manifest.json` для drift- и baseline-проверок. |
| `--previous-rules PATH` | Предыдущий `blocked-domains.json` для semantic diff. |
| `--output PATH` | Новый или пустой каталог результата. |
| `--sing-box PATH` | Закреплённый компилятор; по умолчанию `.tools/sing-box[.exe]`. |
| `--max-workers 1..16` | Число параллельных загрузок, по умолчанию 3. |
| `--cache-max-age-days N` | Удалять файлы кеша старше N дней, по умолчанию 30. |
| `--cache-max-bytes N` | Максимальный размер кеша, по умолчанию 1 ГиБ. |
| `--debug` | Подробный лог. |

Очистка кеша выполняется только в online-режиме. Offline-replay не удаляет старые входы и проверяет их SHA-256 и URL.

```powershell
& ./.venv/Scripts/python.exe scripts/build.py --output dist/first --max-workers 4
& ./.venv/Scripts/python.exe scripts/build.py --offline --previous dist/first/manifest.json --previous-rules dist/first/blocked-domains.json --output dist/replay
```

`GITHUB_REPOSITORY` задаёт ссылки в артефактах; `GITHUB_SHA` записывается как commit сборки.

## `scripts/publish_release.py`

Проверяет кандидата и публикует его через draft → повторное скачивание и проверка → Latest. Разрешён только в trusted main-workflow (`push`, `schedule`, `workflow_dispatch`).

| Аргумент | Назначение |
|---|---|
| `--input PATH` | Каталог кандидата, по умолчанию `incoming/dist`. |
| `--output PATH` | Каталог release-ассетов, по умолчанию `release`. |
| `--root PATH` | Корень checkout для сверки рецепта, по умолчанию `.`. |
| `--dry-run` | Полная локальная проверка без GitHub API, токена и создания релиза. |
| `--keep-releases N` | После успешной публикации оставить Latest и N более новых старых релизов. |
| `--debug` | Подробный лог. |

Обязательные переменные: `GITHUB_REPOSITORY`, `GITHUB_SHA`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`; для настоящей публикации также `GITHUB_TOKEN`. Опционально: `RESET_BASELINE=true` только при `workflow_dispatch`, `GITHUB_STEP_SUMMARY`.

Тег имеет вид `vYYYY.MM.DD-<run_id>-<attempt>`. `release.json` содержит `previous_release_tag`, если предыдущий релиз существовал. При сбое загрузки или проверки ассета черновик удаляется; опубликованный Latest не перезаписывается. При неизменном fingerprint возвращается `unchanged`.

```powershell
& ./.venv/Scripts/python.exe scripts/publish_release.py --input incoming/dist --output release --dry-run
```

### Очистка старых релизов

```powershell
& ./.venv/Scripts/python.exe scripts/publish_release.py retention --keep 5
& ./.venv/Scripts/python.exe scripts/publish_release.py retention --keep 5 --apply
```

Без `--apply` выполняется dry-run. Latest и черновики защищены. Workflow запускает retention после успешной публикации и оставляет Latest плюс пять более новых старых релизов.

## `scripts/validate_config.py`

Проверяет девять файлов `config/` по локальным JSON Schema из `schemas/`, уникальность идентификаторов источников и согласованность probes.

```powershell
& ./.venv/Scripts/python.exe scripts/validate_config.py
& ./.venv/Scripts/python.exe scripts/validate_config.py --root /path/to/checkout
```

## Остальные команды

- `scripts/install_tools.py` — скачивает закреплённый sing-box и проверяет SHA-256 архива.
- `scripts/load_baseline.py` — восстанавливает предыдущие manifest и domain rules из GitHub Actions/Releases.
- `scripts/monitor.py --output monitoring.json --html monitoring.html` — внешняя выборочная проверка доступности; `--offline` не создаёт новых измерений.
- `scripts/issue_candidate.py` — формирует кандидата из issue; `--comment` публикует комментарий через GitHub API.
- `scripts/measure_memory.py --seconds 5 <SRS...>` — измеряет RSS sing-box с локальными наборами.
- `scripts/validate_awg_outputs.py <build_dir>` — проверяет состав catalog и пресетов AWG Manager без сети.

## Проверка качества

```powershell
& ./.venv/Scripts/python.exe -m ruff check scripts tests routing
& ./.venv/Scripts/python.exe -m mypy
& ./.venv/Scripts/python.exe scripts/validate_config.py
& ./.venv/Scripts/python.exe -m bandit -q -r scripts --severity-level medium
& ./.venv/Scripts/python.exe scripts/install_tools.py
& ./.venv/Scripts/python.exe -m coverage run -m unittest discover -s tests -v
& ./.venv/Scripts/python.exe -m coverage report --fail-under=75
```

Те же проверки выполняет job `quality` для push и pull request. Тесты включают изолированную offline-сборку и dry-run публикации без сети. CodeQL запускается отдельным workflow, Dependabot еженедельно проверяет Python-зависимости и GitHub Actions.
