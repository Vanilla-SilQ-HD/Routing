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
