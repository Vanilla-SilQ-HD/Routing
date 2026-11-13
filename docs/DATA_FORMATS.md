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

Ключевые поля:

- `schema_version` — всегда `1`.
- `built_at` — ISO-время сборки (единое для всего релиза).
- `offline_replay` — `true`, если сборка выполнена только из проверенного кеша без сети.
- `sources` — список источников с числом условий, IP, отфильтрованных записей и SHA-256.
- `public_suffix_list` — источник PSL и число правил.
- `output` — итоговый набор: `total_conditions`, `exact`, `suffix`, `srs_bytes`, `files` (имя → SHA-256).
- `core`, `smart` — компактный и Smart профили с собственными `output` и `compiler`.
- `service_networks`, `registry_ip`, `registry_cidr`, `direct_exceptions` — соответствующие наборы с `output`, `validation`, `compiler`.
- `domain_diff`, `domain_changes` — семантический diff покрытия.
- `configuration_sha256` — хеши всех файлов рецепта (конфиги, скрипты, схемы, workflow).
- `compiler` — версия sing-box, `source_format_version`, результаты `roundtrip` и `sing_box_check`.
- `environment` — версия Python, idna, коммит, репозиторий.
- `validation` — `baseline` (`first-build`, `previous-successful-or-approved-manifest`, `large-change-candidate`) и `warnings`.
- `scope` — декларация области сборки (без личных правил, без доступа к роутеру и т.д.).

## 4. catalog.json

Каталог для AWG Manager. Схема: `schemas/output/catalog_schema.json`.

```json
{
  "generated": "2026-11-13T00:00:00+00:00",
  "sources": [
    { "id": "routing", "url": "https://github.com/.../releases/latest/download/{}", "names": ["blocked-domains", "..."] }
  ]
}
```

`names` — полный список наборов (см. `routing/datasets.py`).

## 5. presets.user.json

Готовые пресеты AWG Manager. Схема: `schemas/output/presets_schema.json`.

Каждый пресет: `id`, `name`, `iconSlug`, `category`, `notice`, `engines.singbox` с `ruleSets` (массив `{tag, url}`) и `action: "tunnel"`. Direct-исключения никогда не включаются в VPN-пресеты.

## 6. monitoring.json

Внешняя проверка доступности через Globalping. Схема: `schemas/output/monitoring_schema.json`.

- `history` — массив запусков: `generated_at`, `results` (по целям), `rotated_sample`.
- Каждый результат: `target`, `status` (`works_direct`, `blocked_or_geo`, `down_or_error`, `unknown`), `http_status`, `error`.
- `stale_candidates` — домены, которые несколько запусков подряд отвечают `works_direct` из RU (кандидаты на ручной пересмотр).
- `history_restored` — `false`, если прошлую историю не удалось загрузить (она не перезаписывается).
- `automatic_route_changes` — всегда `false`.
- `vpn_measurement` — всегда `not_performed`.

Сопутствующий `stale-candidates.json` содержит только список кандидатов на пересмотр.

## 7. domain-changes.json

Семантический diff покрытия между текущей и предыдущей сборкой: `baseline`, `by_kind` (добавленные/удалённые условия по типам), `effective_added`, `effective_removed` и выборки `*_sample`. Позволяет отличить минимизацию от реальной потери покрытия.

