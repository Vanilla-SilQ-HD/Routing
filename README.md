# Routing

[![Сборка и публикация](https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml/badge.svg)](https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml)

Автообновляемые наборы правил для выборочной маршрутизации в **sing-box**. Помогают направлять заблокированные и недоступные из России ресурсы через VPN, оставляя остальной трафик напрямую.

**[Домены .srs](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains.srs)** · **[Сети приложений .srs](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-services-ip.srs)** · [Релизы, отчёты и SHA-256](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest)

## Подключение

Пример подключения обоих наборов для **sing-box 1.14+**. Это фрагмент для существующего конфига: `vpn` и `direct` должны совпадать с тегами ваших подключений. URL постоянные и всегда указывают на последний опубликованный релиз.

```json
{
  "experimental": {
    "cache_file": { "enabled": true }
  },
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "routing",
        "format": "binary",
        "url": "https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains.srs",
        "http_client": { "detour": "vpn" },
        "update_interval": "6h"
      },
      {
        "type": "remote",
        "tag": "routing-services",
        "format": "binary",
        "url": "https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-services-ip.srs",
        "http_client": { "detour": "vpn" },
        "update_interval": "6h"
      }
    ],
    "rules": [
      { "action": "sniff" },
      { "rule_set": ["routing", "routing-services"], "action": "route", "outbound": "vpn" }
    ],
    "final": "direct"
  }
}
```

Совпадения с любым из наборов идут через `vpn`, остальные соединения — через `direct`. Добавьте фрагмент к существующим настройкам; свои приоритетные исключения разместите перед этим VPN-правилом. Другие правила VPN в конфиге могут изменить эту схему.

Файлы в примере скачиваются через VPN и сохраняются в кеш. В панели управления, например AWG Manager, используются те же параметры: два удалённых набора, формат `binary`, URL из примера и нужное VPN-подключение.

**DNS настраивается отдельно.** Для выбора DNS-сервера по домену используйте только `routing` (`blocked-domains.srs`). Набор `routing-services` с IP-сетями предназначен только для маршрутизации соединений. Подробнее: [удалённые наборы sing-box](https://sing-box.sagernet.org/configuration/rule-set/).

## Что входит в наборы

`blocked-domains.srs` объединяет доменные записи из пяти источников:

- [Antifilter](https://antifilter.download/list/domains.lst).
- [Antifilter community](https://community.antifilter.download/list/domains.lst).
- [Re-filter](https://github.com/1andrevich/Re-filter-lists).
- [itdog allow-domains — Russia/inside](https://github.com/itdoginfo/allow-domains).
- [hoaxisr/rulesets — unavailable-in-russia](https://github.com/hoaxisr/rulesets).

Дубли и избыточные условия удаляются. Правила для целых доменных зон и выбранных общих платформ фильтруются, а отдельно перечисленные поддомены сохраняются. Основа фильтрации — [Public Suffix List](https://publicsuffix.org/) и [политика проекта](config/policy.json).

`blocked-services-ip.srs` дополняет его сетями приложений, которые подключаются прямо к IP. Сейчас это [официальный список Telegram](https://core.telegram.org/resources/cidr.txt) и IPv4/IPv6-маршруты пяти выделенных AS Telegram из RIPE RIS. Домены Telegram уже есть в доменной базе, но соединение без имени назначения требует IP-правила.

Сервисные сети обновляются из отдельно проверенных источников. Общие категории «все ИИ», полные сети облачных провайдеров и широкие списки заблокированных IP автоматически не добавляются: общие адреса могут обслуживать посторонние ресурсы. Преобразование всех заблокированных доменов в IP не сохраняет точность доменных правил. [Разбор IP-источников и охвата →](docs/IP-COVERAGE.md)

## Обновления

GitHub Actions проверяет источники четыре раза в сутки: **03:35, 09:35, 15:35 и 21:35 по Москве**. GitHub может задерживать запуск. Новый релиз появляется при изменении набора или рецепта сборки; постоянный URL остаётся прежним.

Перед публикацией проверяются данные, компиляция, обратное чтение `.srs` и контрольные суммы. Если сборка или загрузка не удалась, предыдущий релиз остаётся доступен. Дату последней проверки источников смотрите в [Actions](https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml), а не только в дате релиза.

## Ограничения

- Источники могут содержать устаревшие или ошибочные записи. База не проверяет доступность каждого сайта у вашего провайдера и не гарантирует охват всех блокировок.
- IP-набор охватывает только перечисленные сервисные сети. Он не распознаёт любое приложение и не охватывает произвольные адреса собеседников в P2P-звонках. Доменные правила требуют получения имени назначения; настройка DNS выполняется отдельно.
- На устройствах с небольшим объёмом RAM проверьте расход памяти: размер файла `.srs` не равен размеру набора в памяти.

Нашли ошибку — [откройте issue](https://github.com/Vanilla-SilQ-HD/Routing/issues), указав домен или приложение, ожидаемый маршрут и версию набора.

[Сборка, проверка файлов и сопровождение проекта →](docs/BUILD.md)
