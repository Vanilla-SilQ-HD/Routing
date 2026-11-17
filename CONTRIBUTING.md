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

## Требования и быстрый старт

- Python **3.11+** (CI проверяет версии 3.11–3.14).
- Для запуска проверок нужны зависимости из `requirements.txt` и `requirements-dev.txt`.
- Установка из корня репозитория:

```bash
git clone https://github.com/Vanilla-SilQ-HD/Routing.git
cd Routing
make install
```

Зависимости зафиксированы с хешами; в CI они устанавливаются с `pip --require-hashes`.

## Проверки и локальная сборка

Makefile — основной интерфейс локальных команд и источник их точного определения. `just` (если установлен) делегирует в Makefile.

```bash
make lint       # Ruff для scripts, tests и routing
make typecheck  # mypy (strict)
make security   # Bandit
make test       # unittest
make coverage   # unittest с порогом покрытия 75%
make validate   # проверка конфигов и dist/
make docs       # генерация docs/DATA_FORMATS.md
make build      # офлайн-сборка в dist/
```

CI дополнительно проверяет примеры sing-box через установленный закреплённый компилятор. Для локального запуска этого шага выполните `python scripts/install_tools.py`, затем:

```bash
.tools/sing-box check --config examples/singbox-router.json
.tools/sing-box check --config examples/singbox-client.json
```

Для проверки, что сгенерированная справка форматов актуальна, используйте `python scripts/gen_docs.py --check`. Список точных проверок CI см. в [workflow сборки](.github/workflows/build.yml).

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
