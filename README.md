# Routing

[![Сборка и публикация](https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml/badge.svg)](https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml)

Автообновляемые наборы правил для выборочной маршрутизации в **sing-box**. Помогают направлять заблокированные и недоступные из России ресурсы через VPN, оставляя остальной трафик напрямую.

**[Домены](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains.srs)** · **[Сети приложений](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-services-ip.srs)** · **[Точные IP](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-registry-ip.srs)** · **[Direct-исключения](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/routing-direct-exceptions.srs)** · [Релизы и отчёты](https://github.com/Vanilla-SilQ-HD/Routing/releases/latest)

Прямые URL для поля **Source** в AWG Manager:

```text
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-domains.srs
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-services-ip.srs
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/blocked-registry-ip.srs
https://github.com/Vanilla-SilQ-HD/Routing/releases/latest/download/routing-direct-exceptions.srs
```

## Подключение

Пример для **sing-box 1.14+**. Это фрагмент существующего конфига: `vpn` и `direct` должны совпадать с тегами ваших подключений. URL постоянные и указывают на последний опубликованный релиз.

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
      { "rule_set": ["routing-direct-exceptions"], "action": "route", "outbound": "direct" },
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

Правила применяются сверху вниз, первое совпадение побеждает. Direct-исключения стоят выше VPN, всё непокрытое идёт через `direct`. Свои приоритетные правила размещайте перед этим фрагментом; другие правила VPN в конфиге могут изменить схему.

Если GitHub у вашего провайдера доступен, оставьте скачивание через `direct`: так первоначальная загрузка не зависит от уже работающего VPN. Если GitHub недоступен, замените `http_client.detour` на `vpn` у всех наборов. Кеш особенно важен при таком варианте. Проверьте холодный старт без кеша и последующие обновления.

## Настройка в AWG Manager

1. В **Маршрутизация → Sing-box** добавьте четыре Remote Rule Set с тегами и URL из примера, формат `binary`, интервал `6h`. Выберите `direct` для скачивания, если GitHub доступен.
2. Добавьте правило `routing-direct-exceptions` → **Напрямую**. Ниже добавьте правило с тремя наборами `routing`, `routing-services`, `routing-registry-ip` → ваше VPN-подключение. Не переносите пользовательские правила выше системных `sniff`, `hijack-dns` и локальных исключений.
3. Проверьте **Final outbound → direct**.
4. Для **TProxy** настройте DNS-сервер через VPN и правило DNS только для набора `routing`. DNS по умолчанию остаётся прямым. При подмене ответов используйте DNS через VPN или пресет «Анти-подмена» AWG Manager. Наборы IP в DNS-правила не добавляйте.
5. Для **FakeIP** выберите в DNS только доменный набор `routing`, чтобы уменьшить нагрузку. Клиенты должны использовать FakeIP DNS роутера; собственный DoH/DoT на устройстве может обойти эту схему.
6. В **Соединениях** проверьте фактический outbound и сработавшее правило для заблокированного и обычного ресурса. Проверьте IPv4 и IPv6 отдельно.

Подробнее: [удалённые наборы sing-box](https://sing-box.sagernet.org/configuration/rule-set/) и [документация AWG Manager](https://awgm.hoaxisr.ru/guide/singbox/router/).

## Что входит в наборы

### `blocked-domains.srs`

Доменная база объединяет:

- [Antifilter](https://antifilter.download/list/domains.lst).
- [Antifilter community](https://community.antifilter.download/list/domains.lst).
- [Re-filter](https://github.com/1andrevich/Re-filter-lists).
- [itdog allow-domains — Russia/inside](https://github.com/itdoginfo/allow-domains).
- [itdog — отдельный Google AI](https://github.com/itdoginfo/allow-domains/blob/main/Services/google_ai.lst), намеренно не входящий в Russia/inside.
- [hoaxisr/vernette — RKN](https://github.com/hoaxisr/rulesets).
- Отдельные зависимости [Bungie, Kinopub, Gemini и TikTok](https://github.com/hoaxisr/rulesets), найденные сравнением сервисных списков с общей базой.
- [hoaxisr/rulesets — unavailable-in-russia](https://github.com/hoaxisr/rulesets).

Antifilter full уже включает Antifilter community и Re-filter: отдельная загрузка нужна для свежих дополнений и учёта происхождения, а не для независимого подтверждения. Дубли и условия, покрытые существующим suffix, удаляются без потери покрытия. Целые доменные зоны и выбранные общие платформы фильтруются по [Public Suffix List](https://publicsuffix.org/) и [политике проекта](config/policy.json); отдельно перечисленные поддомены сохраняются.

Ручные дополнения находятся в [config/manual-vpn.json](config/manual-vpn.json). Каждое правило требует причину; public suffixes запрещены.

### `blocked-services-ip.srs`

Проверенные сети приложений, которые могут подключаться напрямую к IP. Сейчас это [официальный список Telegram](https://core.telegram.org/resources/cidr.txt) и IPv4/IPv6-маршруты пяти выделенных AS Telegram из RIPE RIS.

Общие сети облачных провайдеров, CDN и Meta, а также широкие составные списки Discord voice и Roblox автоматически не добавляются. Преобразование всех доменов в IP через DNS тоже не используется: один адрес может обслуживать множество независимых ресурсов. [Разбор IP-источников и охвата →](docs/IP-COVERAGE.md)

### `blocked-registry-ip.srs`

Только публичные точные адреса из уже подключённых блок-листов: IPv4 `/32` и IPv6 `/128`. Сети не расширяются до соседних диапазонов. Этот набор отделён от проверенных сервисных сетей, поскольку адрес из реестра может быть общим. Если такой адрес захватывает нужный прямой ресурс, отключите набор у себя или добавьте более приоритетное Direct-правило.

### `routing-direct-exceptions.srs`

Подтверждённые ложные и устаревшие срабатывания. Правила находятся в [config/direct-exceptions.json](config/direct-exceptions.json), имеют причину и дату пересмотра. Набор должен стоять выше общего VPN-правила. Личные исключения в репозиторий не добавляются.

## Обновления и проверки

GitHub Actions проверяет источники четыре раза в сутки: **03:35, 09:35, 15:35 и 21:35 по Москве**. GitHub может задерживать запуск. Новый релиз появляется при изменении набора или рецепта сборки; постоянные URL остаются прежними.

Перед публикацией выполняются unit-тесты, обязательные ожидания VPN/Direct, компиляция, обратное чтение всех SRS, `sing-box check` и контрольные суммы. `domain-changes.json` показывает добавленные/удалённые условия и отдельно фактически потерянное покрытие после минимизации. Если сборка или загрузка не удалась, предыдущий релиз остаётся доступен.

При сбое Telegram/RIPE допускается только полный ранее проверенный сервисный набор не старше 24 часов; частичный IP-набор не публикуется. Доменные источники резервного пропуска не имеют. Дату последней проверки смотрите в [Actions](https://github.com/Vanilla-SilQ-HD/Routing/actions/workflows/build.yml), а не только в дате релиза.

## Ограничения

- Абсолютно полного списка не существует: блокировки зависят от провайдера и времени, а источники могут содержать устаревшие или ошибочные записи.
- Доменные правила требуют имени назначения. Клиентский DoH/DoT, ECH и подключения по IP могут его скрыть; DNS и реальные маршруты нужно проверять на своих устройствах.
- Произвольные адреса собеседников в P2P-звонках и динамические голосовые серверы нельзя полностью описать безопасным статическим списком.
- На устройствах с небольшим объёмом RAM измерьте расход памяти: размер `.srs` не равен RSS sing-box.

Нашли ошибку или пропущенный ресурс — [откройте issue](https://github.com/Vanilla-SilQ-HD/Routing/issues), указав домен/IP или приложение, ожидаемый маршрут, сработавшее правило и версию набора.

[Сборка, измерение памяти и сопровождение проекта →](docs/BUILD.md)
