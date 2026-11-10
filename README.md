<p align="center">
  <img src="docs/assets/routing-banner.svg" alt="Routing — точная маршрутизация без лишнего VPN" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml"><img src="https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml/badge.svg" alt="Сборка"></a>
  <a href="https://vanilla-silq-hd.github.io/Routing/"><img src="https://img.shields.io/endpoint?url=https://vanilla-silq-hd.github.io/Routing/status.json" alt="Доменных условий"></a>
  <a href="https://vanilla-silq-hd.github.io/Routing/"><img src="https://img.shields.io/endpoint?url=https://vanilla-silq-hd.github.io/Routing/updated.json" alt="Обновлено"></a>
  <img src="https://img.shields.io/badge/sing--box-1.14.4-546e7a" alt="sing-box 1.14.4">
</p>

Автообновляемые наборы для **sing-box** и **AWG Manager**: заблокированные и недоступные в России ресурсы — через VPN, остальной трафик — напрямую.

[Подключение к AWG Manager](#подключение-к-awg-manager) · [Готовый JSON](#готовый-json-для-sing-box) · [Состав наборов](#состав-наборов) · [Последний релиз](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest) · [Routing Dashboard](https://vanilla-silq-hd.github.io/Routing/) · [Мониторинг](https://vanilla-silq-hd.github.io/Routing/monitoring.html) · [Catalog](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/catalog.json)

## Подключение к AWG Manager

Требуется **sing-box 1.14+** и существующее VPN-подключение. В JSON используется универсальный tag `vpn`; в интерфейсе AWG Manager выберите своё подключение.

### Быстрый вариант: готовые пресеты

- [AWG Manager Catalog](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/catalog.json) — полный, compact и отдельный Wide CIDR профили.
- [presets.user.json](https://vanilla-silq-hd.github.io/Routing/presets.user.json) — пользовательский overlay для AWG Manager. Сохраните его в каталог данных AWG Manager под тем же именем. Если файл уже существует, объедините массив `presets` вручную, не перезаписывая свои настройки.

Пресеты добавляют только VPN-наборы: в AWG Manager одно действие применяется ко всем наборам пресета. После применения Full или Compact отдельно добавьте `routing-direct-exceptions` с действием **Direct** и поставьте это правило выше VPN, как показано ниже.

### 1. Добавьте четыре Remote Rule Set

| Tag | Назначение |
| --- | --- |
| `routing` | Полная доменная база |
| `routing-core` | Compact: база без двух крупнейших реестров |
| `routing-services` | Проверенные сети приложений, сейчас Telegram |
| `routing-registry-ip` | Точные IP-адреса из блок-листов |
| `routing-registry-ip-cidr` | Необязательные широкие CIDR с предупреждением |
| `routing-direct-exceptions` | Приоритетные Direct-исключения |

Прямые URL для поля **Source**:

```text
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains.srs
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains-core.srs
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-services-ip.srs
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-registry-ip.srs
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-registry-ip-cidr.srs
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/routing-direct-exceptions.srs
```

Резервные URL на GitHub Pages:

```text
https://vanilla-silq-hd.github.io/Routing/blocked-domains.srs
https://vanilla-silq-hd.github.io/Routing/blocked-domains-core.srs
https://vanilla-silq-hd.github.io/Routing/blocked-services-ip.srs
https://vanilla-silq-hd.github.io/Routing/blocked-registry-ip.srs
https://vanilla-silq-hd.github.io/Routing/blocked-registry-ip-cidr.srs
https://vanilla-silq-hd.github.io/Routing/routing-direct-exceptions.srs
```

Для каждого набора укажите:

- **Type:** `Remote`;
- **Format:** `Binary`;
- **Update interval:** `6h`;
- **Download detour:** `direct`, если GitHub доступен. Если GitHub заблокирован у провайдера — `ваш VPN`.

Скачивание через `direct` позволяет загрузить наборы ещё до запуска VPN. При скачивании через VPN обязательно включите кеш и проверьте холодный старт.

### 2. Настройте правила маршрутизации

Правила применяются сверху вниз: **первое совпадение побеждает**. Системные `sniff`, `hijack-dns` и локальные исключения AWG Manager оставьте на своих местах.

| Порядок | Условие | Действие |
| --- | --- | --- |
| После системных правил | `routing-direct-exceptions` | **Напрямую** |
| Ниже | `routing`, `routing-services`, `routing-registry-ip` | **ваш VPN** |
| Final outbound | Всё остальное | **direct** |

Вместо `routing` можно использовать `routing-core` для экономии памяти. Набор `routing-registry-ip-cidr` необязателен: подключайте его отдельным VPN-правилом только после проверки, что широкие сети не захватывают нужные Direct-ресурсы. Если `1.1.1.1` используется как Direct DNS, уже предусмотрено Direct-исключение для этого адреса.

Пустой набор `routing-direct-exceptions` безопасен: у него нет совпадений, и он ни на что не влияет.

### 3. Настройте DNS

**В DNS-правилах используйте только `routing`.** Наборы `routing-services` и `routing-registry-ip` содержат IP и в DNS не добавляются.

Для **TProxy**:

- создайте DNS-сервер через `ваш VPN`;
- добавьте DNS-правило `routing` → этот сервер;
- остальные DNS-запросы оставьте на прямом сервере;
- при подмене DNS-ответов используйте пресет **«Анти-подмена»** AWG Manager или повторный резолв через VPN.

Для **FakeIP**:

- выберите в FakeIP DNS только набор `routing`, чтобы не гонять через движок лишние запросы;
- клиенты должны использовать FakeIP DNS роутера;
- собственный DoH/DoT на устройстве может обойти FakeIP — проверьте такие клиенты отдельно.

### 4. Проверьте результат

В **Соединениях** откройте несколько заблокированных и обычных ресурсов и проверьте outbound и сработавшее правило:

- ожидаемый VPN-ресурс → `ваш VPN`;
- `ozon.ru`, `yandex.ru`, `google.com` → `direct`;
- Telegram и хотя бы один адрес из `blocked-registry-ip.srs` → `ваш VPN`;
- IPv4 и IPv6 — отдельно.

![Пример готовой конфигурации AWG Manager](docs/assets/awg-manager-example.svg)

Подробнее: [документация AWG Manager](https://awgm.hoaxisr.ru/guide/singbox/router/).

## Готовый JSON для sing-box

Это фрагмент существующего конфига. Теги `vpn` и `direct` должны совпадать с вашими outbound. URL постоянные и всегда указывают на последний опубликованный релиз.

<details>
<summary>Показать JSON</summary>

```json
{
  "experimental": {
    "cache_file": { "enabled": true }
  },
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "routing-direct-exceptions",
        "format": "binary",
        "url": "https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/routing-direct-exceptions.srs",
        "http_client": { "detour": "direct" },
        "update_interval": "6h"
      },
      {
        "type": "remote",
        "tag": "routing",
        "format": "binary",
        "url": "https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains.srs",
        "http_client": { "detour": "direct" },
        "update_interval": "6h"
      },
      {
        "type": "remote",
        "tag": "routing-services",
        "format": "binary",
        "url": "https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-services-ip.srs",
        "http_client": { "detour": "direct" },
        "update_interval": "6h"
      },
      {
        "type": "remote",
        "tag": "routing-registry-ip",
        "format": "binary",
        "url": "https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-registry-ip.srs",
        "http_client": { "detour": "direct" },
        "update_interval": "6h"
      }
    ],
    "rules": [
      { "action": "sniff" },
      {
        "rule_set": ["routing-direct-exceptions"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": ["routing", "routing-services", "routing-registry-ip"],
        "action": "route",
        "outbound": "vpn"
      }
    ],
    "final": "direct"
  }
}
```

</details>

Если GitHub недоступен напрямую, замените `http_client.detour` на `vpn` у всех наборов. Свои приоритетные исключения размещайте перед VPN-правилом. Другие VPN-правила в конфиге могут изменить итоговый маршрут. Подробнее: [Remote Rule Set в sing-box](https://sing-box.sagernet.org/configuration/rule-set/).

## Состав наборов

| Файл | Что содержит |
| --- | --- |
| `blocked-domains.srs` | Полная доменная база для маршрутизации и DNS |
| `blocked-domains-core.srs` | Compact: те же источники без Antifilter full и RKN |
| `blocked-services-ip.srs` | Официальные сети Telegram и маршруты пяти выделенных AS из RIPE RIS |
| `blocked-registry-ip.srs` | Только публичные IPv4 `/32` и IPv6 `/128`, без объединения в подсети |
| `blocked-registry-ip-cidr.srs` | Необязательные широкие CIDR с сохранением исходных границ |
| `routing-direct-exceptions.srs` | Подтверждённые ложные и устаревшие срабатывания с датой пересмотра |

### Источники доменов

- [Antifilter](https://antifilter.download/list/domains.lst) и [Antifilter community](https://community.antifilter.download/list/domains.lst);
- [Re-filter](https://github.com/1andrevich/Re-filter-lists);
- [itdog allow-domains — Russia/inside](https://github.com/itdoginfo/allow-domains);
- [itdog — отдельный Google AI](https://github.com/itdoginfo/allow-domains/blob/main/Services/google_ai.lst);
- [hoaxisr/vernette — RKN](https://github.com/hoaxisr/rulesets);
- зависимости [Bungie, Kinopub, Gemini и TikTok](https://github.com/hoaxisr/rulesets);
- [unavailable-in-russia](https://github.com/hoaxisr/rulesets).

Отдельные IP-источники: [ipresolve.lst](https://antifilter.download/list/ipresolve.lst), [subnet.lst](https://antifilter.download/list/subnet.lst), [community.lst](https://community.antifilter.download/list/community.lst) и [ipsum.lst](https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst).

Antifilter full уже включает community и Re-filter: отдельная загрузка нужна для свежих дополнений и происхождения записей, а не для независимого подтверждения. Дубли и условия, покрытые существующим suffix, удаляются без потери покрытия. Целые зоны и общие платформы фильтруются по [Public Suffix List](https://publicsuffix.org/) и [политике проекта](config/policy.json).

### Почему IP добавляются консервативно

Один IP может обслуживать множество независимых сайтов. Поэтому проект не преобразует все домены в IP через DNS и не добавляет целиком облачные ASN, CDN, Meta, широкие диапазоны Discord voice и Roblox. Точные registry-IP выделены отдельно, чтобы их можно было отключить или переопределить Direct-правилом.

[Подробный разбор IP-источников и ограничений →](docs/IP-COVERAGE.md)

## Ручные включения и исключения

- VPN-дополнения: [config/manual-vpn.json](config/manual-vpn.json);
- Direct-исключения: [config/direct-exceptions.json](config/direct-exceptions.json).

Для каждого правила нужны `kind`, `domain` и `reason`; для Direct-исключений также `review_after`. Public suffixes запрещены. Личные правила конкретного роутера в общий репозиторий не добавляются.

## Мониторинг и сообщения о пропусках

[Мониторинг](https://vanilla-silq-hd.github.io/Routing/monitoring.html) ежедневно проверяет небольшую контрольную выборку через Globalping и сохраняет историю. Статусы `works_direct`, `blocked_or_geo`, `down_or_error` и `unknown` являются внешними наблюдениями, а не доказательством блокировки у конкретного провайдера. Маршруты по этим результатам автоматически не меняются.

Если ресурс идёт не по тому маршруту, используйте форму issue **«Ресурс идёт не по тому маршруту»**. Она проверяет домен или точный IP и формирует кандидата с причиной и датой пересмотра; публикация в базу выполняется только вручную после проверки.

## Обновления и проверки

GitHub Actions проверяет источники четыре раза в сутки: **03:35, 09:35, 15:35 и 21:35 по Москве**. Возможны задержки запуска на стороне GitHub.

Перед публикацией выполняются:

- unit-тесты и обязательные ожидания VPN/Direct;
- компиляция и обратное чтение всех SRS;
- `sing-box check` и проверка контрольных сумм;
- semantic diff в `domain-changes.json`, включая фактически потерянное покрытие.

Новый релиз появляется при изменении набора или рецепта; постоянные URL остаются прежними. При ошибке обязательного доменного источника предыдущий релиз сохраняется. При сбое Telegram/RIPE допускается только полный проверенный сервисный набор не старше 24 часов, никогда — частичный.

[Интерактивный Routing Dashboard](https://vanilla-silq-hd.github.io/Routing/) показывает источники, маршруты probes, изменения покрытия и результаты проверок. Исходники правил и диагностические файлы дополнительно собираются в `routing-evidence.zip`.

## Ограничения

- Абсолютно полного списка не существует: блокировки зависят от провайдера и времени, а источники могут устаревать или содержать ошибки.
- Клиентский DoH/DoT, ECH и подключения по IP могут скрыть имя назначения. DNS и реальные маршруты нужно проверять на своих устройствах.
- P2P-звонки и динамические голосовые серверы нельзя полностью и точно покрыть статическим списком.
- На устройствах с небольшим объёмом RAM измерьте RSS sing-box: размер `.srs` не равен потреблению памяти.

Нашли ошибку или пропущенный ресурс — [откройте issue](https://github.com/Vanilla-SilQ-HD/Routing/issues), указав домен/IP или приложение, ожидаемый маршрут, сработавшее правило и версию набора.

## Документация

- [Сборка, измерение памяти и сопровождение](docs/BUILD.md)
- [IP-источники и охват](docs/IP-COVERAGE.md)
- [Последний релиз, manifest и отчёты](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest)
