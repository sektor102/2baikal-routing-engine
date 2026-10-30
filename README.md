# 2Baikal Routing Engine

Единая политика DEFAULT DIRECT для **Mihomo на Windows** и **HAPP на iPhone**. Четыре исходных пользовательских файла сохранены побайтно в `inputs/`. Ветка остаётся **main** по решению владельца. Старый Shadowrocket-проект сохранён в `backup/shadowrocket-before-2baikal-2026-10-31`.

## Готовая сборка

Ссылки начинают работать только после успешной публикации:

- [HAPP JSON](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/happ-routing.json)
- [HAPP import link](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/happ-import-link.txt)
- [Mihomo YAML](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/mihomo-config.yaml)
- [Архив с локальными провайдерами](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/2baikal-routing.zip)
- [SHA256SUMS](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/SHA256SUMS)
- [Результаты проверки](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/validation.json)

Внутри конфигов URL закреплены за конкретным release tag. Для обновления всей политики нужно обновить сам конфиг. Интервал Mihomo 21600 секунд проверяет ту же закреплённую версию; смешивание версий исключено.

## Импорт и обновление

**Mihomo / Clash Verge.** Использовать YAML как шаблон маршрутизации в том же механизме клиента, который заполнял исходные `proxies: # LEAVE THIS LINE!` и группу `→ Remnawave`. В шаблоне нет серверов: для подключения клиент должен подставить свою подписку. Оба маркера сохранены. Базовый DNS/fake-ip совпадает с исходным. Вариант `mihomo-config-doh-optional.yaml` необязательный; сначала проверить на своём подключении. В нём локальные DNS-имена .lan/.local/.home.arpa получают REFUSED, пока явно не задан известный LAN DNS; это предотвращает отправку локальных имён публичным резолверам и цикл через system DNS.

**HAPP.** Скопировать содержимое `happ-import-link.txt` и импортировать средствами приложения. Используется документированная схема `happ://routing/add/{base64 JSON}`. Имя профиля сохранено; повторный импорт обновляет профиль, LastUpdated — строка Unix seconds. Выполнить Reconnect после изменения настроек. URL GitHub сам по себе не включает периодический импорт. В JSON-подписках ручной импорт может быть ограничен: профиль приходит вместе с подпиской. Проверить версию HAPP и тип подписки. [Официальная документация](https://www.happ.su/main/ru/dev-docs/routing).

UseChunkFiles, GlobalProxy=false, RouteOrder, DNS, DnsHosts, DomainStrategy и FakeDNS сохранены. GeoSite содержит только используемые категории. Расход памяти iOS не измерен — нужен тест на телефоне. Windows-процессы в HAPP отсутствуют.

## Сборка

Python 3.13, GNU make. Инструменты скачиваются из официальных releases с проверкой закреплённого SHA256, без установки в систему.

```sh
python -m pip install -r requirements.txt
make tools
make test                 # offline unit/integration/smoke с синтетическими fixtures
make fetch                # HTTPS, timeout/retry, SHA256, формат/категории
make audit
make build
make validate             # реальные Mihomo -t и Xray run -test
python scripts/report.py
python scripts/release.py prepare
```

Windows без make:

```powershell
python scripts/install_tools.py
python -m unittest discover -s tests -v
python -m engine fetch
python -m engine audit
python -m engine build --mihomo .cache/tools/mihomo.exe --repository sektor102/2baikal-routing-engine --previous .previous-release
python -m engine validate --mihomo .cache/tools/mihomo.exe --xray .cache/tools/xray.exe --require-binaries
```

После успешного fetch `python -m engine fetch --offline` проверяет кэш без сети. `make smoke` не требует скачанных баз/инструментов. Native core checks выполняются отдельно и обязательны для релиза.

## Изменить правило

Эталонные дополнения — `rules/policy.yaml`, секция `overrides`. Примеры синтаксиса:

```yaml
overrides:
  - 'DOMAIN-SUFFIX,example.org,PROXY'
  - 'DOMAIN,api.direct-example.org,DIRECT'
  - 'IP-CIDR,203.0.113.0/24,PROXY'
  - 'PROCESS-NAME,Example.exe,PROXY'
```

Примеры не добавлены в рабочую политику. Для переключения менять DIRECT/PROXY/REJECT, согласовав противоположные личные правила; конфликт одного приоритета останавливает сборку. Не удалять «дубли» между типами/назначениями. CIDR проверяются через ipaddress. CDN не резолвятся в вечные IP-правила.

В `friend-approved` добавить точную пару `TYPE,value` для opt-in. Все новые процессы, gstatic.com и keyword battleye требуют ревью. Статусы — в review.json. Персональные широкие процессы Edge/Codex сохранены; явные личные домены проверяются раньше процессов.

## Источники и приоритеты

`sources/manifest.yaml` задаёт URL, формат, приоритет, доверие и режим. `release.json` фиксирует фактические SHA256/ETag, размеры, категории, время проверки и source date, если оно доступно; неизвестная дата обозначена null. [Устройство движка](docs/design.md).

Mihomo: block → личные исключения → процессы → категории → MATCH,DIRECT. Домены/IP преобразуются официальным Mihomo в MRS. Процессы, keyword, regex остаются classical YAML. MRS для classical запрещён. [Форматы Mihomo](https://wiki.metacubex.one/en/config/rule-providers/).

HAPP сохраняет block-proxy-direct. Из производной proxy-категории вычитаются только целые записи, покрытые явным личным DIRECT, чтобы ru-blocked не перекрыл Apple. Более широкое небезопасное пересечение останавливает сборку. Удаления перечислены в conflicts.json. Полное содержимое twitter проверяется в реальной базе; Grok/xAI учитываются отдельно.

## CI, сбои и откат

Push в **main**, ручной запуск и cron `17 */6 * * *` UTC. GitHub может задержать scheduled run. Push в master тоже запускает проверки, если такая ветка появится; публикует только main. Generated files не коммитятся, циклических push нет.

При недоступности/порче upstream допускается только кэш с проверенными SHA256, форматом и категориями, не старше 7 суток. Без него сборка падает. Снимок друга не объявляется свежим. Draft загружается полностью и только затем становится latest; ошибка не заменяет рабочую сборку. Workflow сериализованы, изменение HEAD main в процессе запрещает устаревшую публикацию.

Без изменения выходного payload нет нового релиза и изменения LastUpdated. ETag/дата проверки или неиспользуемая категория сами по себе не создают новую версию. При оборванном upload предыдущий latest работает; проверить и удалить незавершённый draft вручную, повторить workflow.

Откат: выбрать предыдущий [Release](https://github.com/sektor102/2baikal-routing-engine/releases) и импортировать его конфиг. HAPP может не принять меньший LastUpdated: сохранить текущий экспорт, затем удалить/переимпортировать старый профиль средствами приложения, проверить активный профиль и Reconnect. Старый Shadowrocket-код доступен в резервной ветке.

Лицензии: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Equivalent Xray test не является запуском HAPP на iPhone. `-t` не доказывает отсутствие DNS-утечек или стабильность игровой связи: эти свойства проверяются на устройстве.
