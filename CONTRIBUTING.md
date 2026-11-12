# CONTRIBUTING.md

Вклад в проект Routing
======================

Приветствуются issue с сообщениями о пропущенных ресурсах, предложения по новым источникам и исправления документации. Код и конфигурация требуют проверки перед слиянием.

## Как сообщить об ошибке маршрутизации

1. Убедитесь, что проблема воспроизводится после обновления до последнего релиза.
2. Откройте issue по форме **«Ресурс идёт не по тому маршруту»**.
3. Заполните поля:
   - `hostname` — домен или точный IP (`/32`, `/128`);
   - `expected_route` — `VPN` или `Direct`;
   - `matched_rule` — сработавшее правило (например, `blocked-registry-ip`, `blocked-domains`, `direct-exceptions`);
   - `ipv4_diag`, `ipv6_diag` — диагностика маршрута (опционально);
   - `review_after` — ISO-дата пересмотра (обязательна для Direct);
   - `reason` — обоснование.
4. Скрипт `issue_candidate.py` сгенерирует markdown-кандидата для соответствующего JSON-файла.
5. После ручной проверки кандидат добавляется в `config/manual-vpn.json`, `config/direct-exceptions.json` или `config/manual-registry-ip.json`.

## Предложение нового источника

1. Источник должен быть публичным, стабильным и обновляемым.
2. Проверьте отсутствие дублирования с существующими источниками.
3. Добавьте источник в `config/sources.json` (для доменов) или `config/registry-ip-sources.json` (для IP).
4. Укажите `format`, `sha256` (если фиксированный снимок) или `update_policy`.
5. Запустите локальную сборку и убедитесь, что покрытие не регрессирует.
6. Откройте pull request с описанием источника и примерами записей.

## Требования к коду

- Python 3.13+.
- Линтер `ruff`, форматирование `ruff format`.
- Типизация: `mypy --strict`.
- Тесты: `python -m unittest discover -s tests -v`.
- Все конфиги проходят валидацию по JSON Schema.

## Запуск CI локально

```powershell
# Установка зависимостей
python -m pip install --require-hashes -r requirements-dev.txt

# Линт и типизация
ruff check scripts tests
ruff format scripts tests --check
mypy scripts tests

# Тесты
python -m unittest discover -s tests -v

# Валидация конфигов
python scripts/validate_config.py --root . --all
```

## Процесс ревью

1. Проверка семантического diff (`domain-changes.json`): нет ли потери критического покрытия.
2. Проверка IP-покрытия: точные IP не перезаписываются, агрегируются.
3. Проверка ручных правил: наличие `reason` и `review_after` (для Direct).
4. Проверка релиза: `publish_release.py --dry-run` показывает план публикации.

## Коммиты

- Один коммит на логическое изменение.
- Сообщение на английском, императив: `Add Telegram IP ranges`, `Fix IP aggregation`.
- Автор: `Vanilla-SilQ-HD <vanilla.silq.hd@example.com>` (или ваш).

## Лицензия

Проект распространяется под той же лицензией, что и основной репозиторий.