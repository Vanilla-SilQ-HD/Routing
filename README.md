# Routing

[![Сборка и публикация](https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml/badge.svg)](https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml)

Автообновляемый список доменов для выборочной маршрутизации в **sing-box**. Помогает направлять заблокированные и недоступные из России ресурсы через VPN, оставляя остальной трафик напрямую.

**[Скачать .srs](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains.srs)** · [Релизы и отчёты](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest) · [SHA-256](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains.srs.sha256)

## Подключение

Постоянный URL для удалённого набора правил:

```text
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains.srs
```

Пример для **sing-box 1.14+**. Это фрагмент для существующего конфига: `vpn` и `direct` должны совпадать с тегами ваших подключений.

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
      }
    ],
    "rules": [
      { "action": "sniff" },
      { "rule_set": ["routing"], "action": "route", "outbound": "vpn" }
    ],
    "final": "direct"
  }
}
```

Совпадения с набором идут через `vpn`, остальные соединения — через `direct`. Добавьте фрагмент к существующим настройкам; свои приоритетные исключения разместите перед правилом `routing`. Другие правила VPN в конфиге могут изменить эту схему.

Сам файл в примере скачивается через VPN и сохраняется в кеш. Для прямой загрузки укажите `"detour": "direct"`. В панели управления, например AWG Manager, используются те же параметры: удалённый набор, формат `binary`, URL выше и нужное VPN-подключение.

Подробнее: [удалённые наборы sing-box](https://sing-box.sagernet.org/configuration/rule-set/). DNS и получение имени назначения должны быть настроены в вашем клиенте; один список доменов этого не заменяет.

## Что входит в список

База объединяет доменные записи из пяти источников:

- [Antifilter](https://antifilter.download/list/domains.lst).
- [Antifilter community](https://community.antifilter.download/list/domains.lst).
- [Re-filter](https://github.com/1andrevich/Re-filter-lists).
- [itdog allow-domains — Russia/inside](https://github.com/itdoginfo/allow-domains).
- [hoaxisr/rulesets — unavailable-in-russia](https://github.com/hoaxisr/rulesets).

Дубли и избыточные условия удаляются. Правила для целых доменных зон и выбранных общих платформ фильтруются, а отдельно перечисленные поддомены сохраняются. Основа фильтрации — [Public Suffix List](https://publicsuffix.org/) и [политика проекта](config/policy.json).

В набор не добавляются IP-подсети и общие категории вроде «все ИИ» или «все зарубежные сайты». Наличие конкретного сервиса определяется исходными списками.

## Обновления

GitHub Actions проверяет источники четыре раза в сутки: **03:35, 09:35, 15:35 и 21:35 по Москве**. GitHub может задерживать запуск. Новый релиз появляется при изменении набора или рецепта сборки; постоянный URL остаётся прежним.

Перед публикацией проверяются данные, компиляция, обратное чтение `.srs` и контрольные суммы. Если сборка или загрузка не удалась, предыдущий релиз остаётся доступен. Дату последней проверки источников смотрите в [Actions](https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml), а не только в дате релиза.

## Ограничения

- Источники могут содержать устаревшие или ошибочные записи. База не проверяет доступность каждого сайта у вашего провайдера и не гарантирует охват всех блокировок.
- Набор работает по доменам. Соединения по IP и приложения, скрывающие имя назначения, могут не совпасть с правилами. Настройка DNS выполняется отдельно.
- На устройствах с небольшим объёмом RAM проверьте расход памяти: размер файла `.srs` не равен размеру набора в памяти.

Нашли ошибку — [откройте issue](https://github.com/Vanilla-SilQ-HD/Routing/issues), указав домен, ожидаемый маршрут и версию набора.

[Сборка, проверка файлов и сопровождение проекта →](docs/BUILD.md)
