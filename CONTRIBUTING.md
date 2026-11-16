# Вклад в проект Routing

Приветствуются issue с сообщениями о пропущенных ресурсах, предложения новых источников и исправления документации. Код и конфигурация проходят обязательные проверки перед слиянием.

## Как сообщить об ошибке маршрутизации

1. Убедитесь, что проблема воспроизводится на последнем релизе.
2. Откройте issue через форму **«Ресурс идёт не по тому маршруту»**.
3. Заполните поля:
   - **Resource** — один домен, IPv4 `/32` или IPv6 `/128`;
   - **Провайдер и регион**;
   - **Ожидаемый маршрут** — `VPN` или `Direct`;
   - **Фактический маршрут** — `Direct` или `VPN` (должен отличаться от ожидаемого);
   - **Версия manifest или релиза**;
   - **Диагностика** — сработавшее правило, DNS-результат, описание недоступности.
4. Бот оставит комментарий с JSON-кандидатом (обновляет существующий, не дублирует).
5. После ручной проверки кандидат добавляется в [`config/manual-vpn.json`](config/manual-vpn.json) (для VPN) или [`config/direct-exceptions.json`](config/direct-exceptions.json). Точные IP добавляются вручную с указанием причины и даты пересмотра.

**Полуавтоматический PR:** когда мейнтейнер ставит на issue метку `approved`, workflow `approved-candidate.yml` создаёт ветку и pull request с кандидатом из комментария бота. Мерж остаётся ручным.

## Предложение нового источника

1. Источник должен быть публичным, стабильным и регулярно обновляемым.
2. Проверьте отсутствие дублирования с существующими источниками. Если источник — агрегат других подключённых списков, укажите это в поле `aggregates`.
3. Добавьте источник в [`config/sources.json`](config/sources.json) (домены) или [`config/registry-ip-sources.json`](config/registry-ip-sources.json) (IP).
4. Заполните обязательные поля по схеме: `id`, `url` (только HTTPS), `format`, `min_entries`, `max_bytes`, `description`. Дополнительно: `reference`, `caveat`, `aggregates`. Полей `sha256` / `update_policy` в схеме нет — свежесть обеспечивается ETag/Last-Modified и SHA-256 кэша.
5. Запустите локальную сборку и убедитесь, что покрытие не регрессирует (`domain-changes.json`).
6. Откройте pull request с описанием источника и примерами записей.

## Требования к коду

- Python **3.11+** (CI проверяет матрицу 3.11–3.14).
- Линтер: `ruff check` (форматирование не навязано).
- Типизация: `mypy` в strict-режиме (конфигурация в `pyproject.toml`).
- Тесты: `python -m unittest discover -s tests`.
- Все конфиги валидируются по JSON Schema, артефакты сборки — по output-схемам.

## Быстрый старт

```bash
# Клонирование и установка зависимостей
git clone https://github.com/Vanilla-SilQ-HD/Routing.git
cd Routing
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

## Запуск проверок локально

Все команды можно запустить через Makefile (см. ниже) или вручную:

```bash
# Линт, типизация, безопасность
python -m ruff check scripts tests routing
python -m mypy
python -m bandit -q -r scripts --severity-level medium

# Валидация конфигов и схем
python scripts/validate_config.py

# Компилятор для интеграционных тестов
python scripts/install_tools.py

# Тесты с покрытием
python -m coverage run -m unittest discover -s tests
python -m coverage report --fail-under=75

# Офлайн-сборка и валидация артефактов
python scripts/build.py --offline --output dist
python scripts/validate_outputs.py dist
```

## Makefile

Для удобства локальной разработки используйте Makefile:

```make
.PHONY: install lint typecheck security test coverage build validate clean

install:
	python -m pip install -r requirements.txt
	python -m pip install -r requirements-dev.txt

lint:
	python -m ruff check scripts tests routing

typecheck:
	python -m mypy

security:
	python -m bandit -q -r scripts --severity-level medium

test:
	python -m unittest discover -s tests

coverage:
	python -m coverage run -m unittest discover -s tests
	python -m coverage report --fail-under=75

build:
	python scripts/build.py --offline --output dist

validate:
	python scripts/validate_config.py
	python scripts/validate_outputs.py dist

clean:
	python -m coverage erase
	rm -rf dist/* incoming/* previous/*
```

Примеры использования:

```bash
make install      # Установка зависимостей
make lint         # Проверка стиля
make typecheck    # Проверка типов
make test         # Запуск тестов
make coverage     # Тесты с отчётом о покрытии
make build        # Офлайн-сборка
make validate     # Валидация конфигов и артефактов
make clean        # Очистка артефактов
```

## Процесс ревью

1. Семантический diff (`domain-changes.json`): нет ли потери критического покрытия.
2. IP-покрытие: точные `/32` и `/128` не расширяются до подсетей.
3. Ручные правила: наличие `reason` и `review_after` (для Direct обязательна).
4. Релиз: `python scripts/publish_release.py --dry-run` показывает план публикации без обращения к GitHub.

## Коммиты

- Один коммит на логическое изменение.
- Сообщение на английском, императив: `Add Telegram IP ranges`, `Fix IP aggregation`.
- Автор — ваш GitHub-аккаунт; бот-коммиты подписываются `github-actions[bot]`.

## Лицензия

Код — MIT (см. [`LICENSE`](LICENSE)). Данные наборов — CC0 (см. [`LICENSE-DATA`](LICENSE-DATA)), с учётом лицензий исходных источников, перечисленных в [`README.md`](README.md).
