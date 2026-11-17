# Data Formats

Описание всех форматов данных, используемых в проекте.

---

## 1. Rule-set (SRS) — бинарный формат sing-box v3

Все `*.srs` файлы — это скомпилированные rule-set формата **source format v3** sing-box.
Структура исходного JSON перед компиляцией:

```json
{
  "version": 3,
  "rules": [
    { "domain": ["example.com", "test.example.com"] },
    { "domain_suffix": ["example.org", "google.com"] },
    { "ip_cidr": ["1.2.3.4/32", "2001:db8::1/128", "10.0.0.0/8"] }
  ]
}
```

- `domain` — точное совпадение домена.
- `domain_suffix` — совпадение домена и всех поддоменов.
- `ip_cidr` — IPv4/IPv6 префиксы (в VPN‑наборе только `/32` и `/128`; широкие CIDR только в `blocked-registry-ip-cidr.srs`).

**Пустой rule-set** — валиден: `"rules": []` (нет условий, не match‑all).

---

## 2. Текстовые экспорты (`*.txt`)

Человекочитаемые дампы для отладки и внешних инструментов.

Формат строки:
- `full:example.com` — точное доменное правило (`domain`).
- `domain:example.org` — суффиксное правило (`domain_suffix`).
- `1.2.3.4/32` — точный IPv4 (`ip_cidr`).
- `2001:db8::1/128` — точный IPv6 (`ip_cidr`).
- `10.0.0.0/8` — широкий CIDR (только в `blocked-registry-ip-cidr.txt`).

Порядок: точные домены → суффиксы → IP (сортировка внутри групп).

---

## 3. manifest.json

Машинное описание сборки. Проверяется по `schemas/output/manifest_schema.json`.

Поля `sources` (число условий, IP, отфильтрованные записи, SHA-256), `public_suffix_list`,
`output` (`total_conditions`, `exact`, `suffix`, `srs_bytes`, `files`), профили `core` и `smart`,
`compiler` (версия sing-box, `roundtrip`, `sing_box_check`), `validation` (база сравнения и
предупреждения), `scope` и `configuration_sha256` описаны в справочнике полей (раздел 8).

## 4. catalog.json

Каталог для AWG Manager. Схема: `schemas/output/catalog_schema.json`.
`names` — полный список наборов из `routing/datasets.py`; URL-шаблон содержит `{}`,
который заменяется именем набора.

## 5. presets.user.json

Готовые пресеты AWG Manager. Схема: `schemas/output/presets_schema.json`.
Direct-исключения никогда не включаются в VPN-пресеты: `routing-direct-exceptions`
подключается в конфигурации отдельным правилом с `action: "route"` до правила туннеля.

## 6. monitoring.json

Внешняя проверка доступности через Globalping. Схема: `schemas/output/monitoring_schema.json`.
VPN-маршрут внешними пробами не проверяется (`vpn_measurement: "not_performed"`), правила
по наблюдениям не меняются (`automatic_route_changes: false`). Сопутствующий
`stale-candidates.json` содержит только список кандидатов на ручной пересмотр.

## 7. domain-changes.json

Семантический diff покрытия между текущей и предыдущей сборкой: `baseline`, `by_kind` (добавленные/удалённые условия по типам), `effective_added`, `effective_removed` и выборки `*_sample`. Позволяет отличить минимизацию от реальной потери покрытия.

## 8. Справочник полей

Блок ниже генерируется из JSON-схем командой `python scripts/gen_docs.py`; CI проверяет
актуальность через `make docs-check`. Описания полей берутся из схем, поэтому формат
документации совпадает с форматом валидации.

<!-- BEGIN GENERATED:schemas -->

### `manifest.json`

Рецепт, контрольные суммы и результаты последней сборки правил маршрутизации.

| Поле | Тип | Описание |
| --- | --- | --- |
| `schema_version` | const `1` | Версия формата манифеста. |
| `built_at` | string | Время сборки в UTC. |
| `offline_replay` | boolean | Сборка из проверенного кеша без сети. |
| `sources` | array<any> | Источники данных и статистика их обработки. |
| `public_suffix_list` | object | Происхождение и статистика Public Suffix List. |
| `output` | object | Основной Full-набор и хеши опубликованных файлов. |
| `output.total_conditions` | integer | Общее число условий маршрутизации. |
| `output.exact` | integer | Число точных доменных правил. |
| `output.suffix` | integer | Число суффиксных доменных правил. |
| `output.srs_bytes` | integer | Размер основного SRS в байтах. |
| `output.files` | object<string, string> | Имена выходных файлов и их SHA-256. |
| `output.files.<key>` | string | SHA-256 соответствующего файла из этого же релиза. |
| `validation` | object | Сравнение с предыдущей одобренной сборкой. |
| `validation.baseline` | enum `first-build` / `previous-successful-or-approved-manifest` / `large-change-candidate` | Тип базы сравнения или кандидат на пересмотр крупного изменения. |
| `validation.baseline_built_at` | string | Время сборки базы сравнения. |
| `validation.warnings` | array<string> | Предупреждения проверок покрытия. |
| `configuration_sha256` | object<string, string> | SHA-256 файлов рецепта сборки. |
| `configuration_sha256.<key>` | string | SHA-256 файла рецепта (config, scripts, sources). |
| `compiler` | object | Версия компилятора sing-box и результаты проверок SRS. |
| `environment` | object | Среда исполнения и коммит сборки. |
| `environment.python` | string | Версия Python. |
| `environment.idna` | string | Версия библиотеки IDNA. |
| `environment.github_commit` | string / null | Git-коммит рецепта; null вне CI. |
| `environment.repository` | string | Репозиторий сборки. |
| `scope` | object | Ограничения и область применения наборов. |
| `core` | object | Статистика и файлы профиля Compact. |
| `smart` | object | Статистика и файлы профиля Smart. |
| `service_networks` | object | Сети сервисов, включённые в VPN-набор. |
| `registry_ip` | object | Точечные IP-правила реестра блокировок. |
| `registry_cidr` | object | Широкие CIDR из реестра блокировок. |
| `direct_exceptions` | object | Исключения для прямого маршрута. |
| `domain_diff` | object | Изменения доменных правил по сравнению с базой. |
| `domain_changes` | object | Изменения фактического покрытия доменов. |
| `counts` | object | Промежуточные счётчики обработки. |
| `exact_intersections_before_minimization` | array<any> | Пересечения точных правил до минимизации. |
| `manual_vpn` | object | Статистика ручных VPN-правил. |
| `elapsed_seconds` | number | Длительность сборки в секундах. |

### `catalog.json`

Каталог наборов правил для импорта в AWG Manager.

| Поле | Тип | Описание |
| --- | --- | --- |
| `generated` | string | Время генерации каталога. |
| `sources` | array<object> | Единственный источник набора правил Routing. |
| `sources[].id` | const `"routing"` | Идентификатор источника. |
| `sources[].url` | string | HTTPS-шаблон URL релиза: {} заменяется именем набора. |
| `sources[].names` | array<string> | Доступные имена наборов из routing/datasets.py. |

### `presets.user.json`

Готовые пресеты маршрутизации для импорта в AWG Manager.

| Поле | Тип | Описание |
| --- | --- | --- |
| `presets` | array<object> | Список готовых профилей для VPN-маршрута. |
| `presets[].id` | string | Уникальный идентификатор пресета. |
| `presets[].name` | string | Отображаемое имя пресета. |
| `presets[].iconSlug` | string | Идентификатор иконки для интерфейса. |
| `presets[].category` | string | Категория пресета в интерфейсе. |
| `presets[].notice` | string | Подсказка по применению пресета. |
| `presets[].engines` | object | Настройки пресета по движкам маршрутизации. |
| `presets[].engines.singbox` | object | Правила пресета для sing-box. |
| `presets[].engines.singbox.action` | const `"tunnel"` | Направлять совпавший трафик в туннель. |
| `presets[].engines.singbox.ruleSets` | array<object> | SRS-наборы, составляющие пресет. |
| `presets[].engines.singbox.ruleSets[].tag` | string | Имя набора правил в конфигурации sing-box. |
| `presets[].engines.singbox.ruleSets[].url` | string | HTTPS-адрес бинарного SRS-набора. |

### `monitoring.json`

Наблюдения о доступности ресурсов из внешних проб, без автоматической смены маршрутов.

| Поле | Тип | Описание |
| --- | --- | --- |
| `schema_version` | const `1` | Версия формата отчёта. |
| `generated_at` | string / null | Время формирования отчёта; null, если измерение недоступно. |
| `provider` | string | Сервис внешних проб доступности. |
| `vpn_measurement` | const `"not_performed"` | VPN-маршрут внешними пробами не проверяется. |
| `automatic_route_changes` | const `false` | Наблюдения не изменяют правила маршрутизации автоматически. |
| `history_restored` | boolean | Удалось ли восстановить историю предыдущих запусков. |
| `unavailable` | boolean | Проверка не состоялась из-за недоступности сервиса проб. |
| `stale_candidates` | array<object> | Кандидаты на ручную проверку после последовательных успешных прямых проб. |
| `stale_candidates[].domain` | string | Домен-кандидат на пересмотр. |
| `stale_candidates[].consecutive_works_direct` | integer | Число подряд успешных прямых проверок. |
| `history` | array<object> | История запусков мониторинга. |
| `history[].generated_at` | string | Время запуска проб. |
| `history[].rotated_sample` | array<string> | Случайная выборка доменов этого запуска. |
| `history[].results` | array<object> | Ответы проб по целям. |
| `history[].results[].target` | string | Проверяемый ресурс. |
| `history[].results[].status` | enum `works_direct` / `blocked_or_geo` / `down_or_error` / `unknown` | Классификация результата прямой проверки. |
| `history[].results[].http_status` | integer / null | Полученный HTTP-код, если он известен. |
| `history[].results[].expected` | string | Ожидаемый маршрут контрольной цели. |
| `history[].results[].error` | string / null | Сообщение об ошибке пробы, если оно есть. |

<!-- END GENERATED:schemas -->

