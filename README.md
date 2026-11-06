# 2Baikal Routing Engine

Единая политика DEFAULT DIRECT для **Mihomo PC на Windows**, **Mihomo Router** и **HAPP на iPhone**. Четыре исходных пользовательских файла сохранены побайтно в `inputs/`. Ветка остаётся **main** по решению владельца. Старый Shadowrocket-проект сохранён в `backup/shadowrocket-before-2baikal-2026-10-31`.

## Готовая сборка

**[Открыть последний Release](https://github.com/sektor102/2baikal-routing-engine/releases/latest)**: в описании три раскрывающихся блока: Mihomo PC, Mihomo Router и строка `routing` для HAPP. Код можно скопировать кнопкой. Если будущий конфиг превысит размер описания GitHub, вместо обрезанного текста будет ссылка на полный файл именно этого релиза.

Ссылки начинают работать только после успешной публикации:

- [HAPP JSON](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/happ-routing.json)
- [HAPP import link](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/happ-import-link.txt)
- [Mihomo YAML](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/mihomo-config.yaml)
- [Mihomo Router YAML](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/mihomo-router-config.yaml)
- [Архив с локальными провайдерами](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/2baikal-routing.zip)
- [SHA256SUMS](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/SHA256SUMS)
- [Результаты проверки](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/validation.json)

Внутри конфигов URL закреплены за конкретным release tag. Для обновления всей политики нужно обновить сам конфиг. Интервал Mihomo 21600 секунд проверяет ту же закреплённую версию; смешивание версий исключено.

## Импорт и обновление

**Mihomo / Clash Verge.** В Remnawave открыть Подписка → Mihomo → шаблон для ПК (`Default` или свой `2Baikal`), вставить полный `mihomo-config.yaml` и сохранить. Оба маркера `proxies: # LEAVE THIS LINE!` сохранены: серверы подставляет **Remnawave**, а не Clash Verge. Убедиться, что шаблон назначен ответу Mihomo нужной подписки. В Clash Verge обновить обычную подписку Remnawave и выбрать рабочий узел в группе `→ Remnawave`. Сам публичный YAML не содержит серверов. Базовый DNS/fake-ip совпадает с исходным. Вариант `mihomo-config-doh-optional.yaml` необязательный; сначала проверить на своём подключении. В нём локальные DNS-имена .lan/.local/.home.arpa получают REFUSED, пока явно не задан известный LAN DNS; это предотвращает отправку локальных имён публичным резолверам и цикл через system DNS.

**HAPP.** Скопировать содержимое `happ-import-link.txt` и импортировать средствами приложения. Используется документированная схема `happ://routing/add/{base64 JSON}`. Имя профиля сохранено; повторный импорт обновляет профиль, LastUpdated — строка Unix seconds. Выполнить Reconnect после изменения настроек. URL GitHub сам по себе не включает периодический импорт. В JSON-подписках ручной импорт может быть ограничен: профиль приходит вместе с подпиской. Проверить версию HAPP и тип подписки. [Официальная документация](https://www.happ.su/main/ru/dev-docs/routing).

**HAPP через Remnawave.** Подписка → Настройки → Заголовки ответа → `routing`: вставить полную строку `happ://routing/add/…` из описания релиза или `happ-import-link.txt`, сохранить. В HAPP обновить подписку, включить профиль `2Baikal-Routing`, дождаться геофайлов и переподключиться. В поле вставляется содержимое файла, не его HTTPS-адрес.

**Mihomo Router.** `mihomo-router-config.yaml` собирается отдельно: домены, DOMAIN-SUFFIX, GeoSite, IPv4/IPv6 и CIDR сохранены; PROCESS-NAME и Windows-процессы исключены при сборке. `find-process-mode: off` отключает поиск процессов самим ядром. Базовый DNS/fake-ip сохранён. В Remnawave создать отдельный шаблон Mihomo `Router` и назначить его подписке роутера. Импортировать шаблон PC и фильтровать процессы на роутере не требуется. Общие доменные/IP-провайдеры PC и Router публикуются один раз.

**Автообновление.** GitHub проверяет upstream каждые 6 часов. После успешной публикации `scripts/sync_remnawave.py` может обновлять через API шаблоны PC, Router и заголовок HAPP. Для включения один раз настроить Secrets ниже. Без них шаг пропускается и работает ручной импорт. `profile-update-interval: 6` означает 6 часов; в Clash Verge можно задать 360 минут. Интервал провайдеров не переключает закреплённую версию релиза.

## Автосинхронизация Remnawave через GitHub Actions

В GitHub → Settings → Secrets and variables → Actions добавить четыре **repository secrets**:

| Secret | Значение |
| --- | --- |
| `REMNAWAVE_URL` | Прямой HTTPS-адрес панели без `/dashboard` и `/api` |
| `REMNAWAVE_API_TOKEN` | Отдельный API-ключ Remnawave |
| `REMNAWAVE_MIHOMO_TEMPLATE_UUID` | UUID шаблона Mihomo для PC из адреса редактора |
| `REMNAWAVE_ROUTER_TEMPLATE_UUID` | UUID отдельного шаблона Mihomo Router |

API-ключу нужны только GET/PATCH `/api/subscription-templates` (GET конкретного UUID) и GET/PATCH `/api/subscription-settings`. Настройка проверена по контрактам Remnawave 3.4.5: YAML передаётся в `encodedTemplateYaml` как Base64; `routing` меняется внутри `customResponseHeaders`. Существующие API-ключи не переиспользуются и не изменяются. Ключ не хранится в репозитории или артефактах.

Actions запускает синхронизацию только после проверок и публикации в main, включая повторный запуск без нового релиза. Перед записью сверяются SHA256 трёх профилей с опубликованными ассетами и текущий HEAD. Меняются только YAML двух выбранных шаблонов и `routing`; прочие заголовки, настройки HWID, пользователи, серверы и выбор шаблонов не меняются. Новый HAPP с меньшим LastUpdated либо другим именем не перезаписывает действующий профиль. Все записи подтверждаются чтением API; при сбое выполняется возврат прежних значений, если они не были изменены другим администратором. При невозможности подтвердить откат Actions завершается ошибкой для ручной проверки.

После настройки выполнить Actions → Verify and publish 2Baikal routing → Run workflow. Проверить шаг **Sync published PC, Router and HAPP profiles to Remnawave**. Затем обновить подписки клиентов; для HAPP нужен Reconnect. Роутеру надо назначить шаблон Router, ПК — шаблон PC. Автосинхронизация сама не меняет назначение шаблонов.

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

## Наборы по сервисам

Готовые наборы имеют имена вроде `apple-direct-personal-domain`, `instagram-proxy-personal-domain`, `youtube-proxy-geosite-domain`. Полный [указатель по сервисам](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/rulesets.md) показывает сервис, направление, слой приоритета, число записей и файлы. [ruleset-layout.json](https://github.com/sektor102/2baikal-routing-engine/releases/latest/download/ruleset-layout.json) содержит соответствие исходным правилам и сертификат сохранения порядка.

`overrides`, `personal`, `apps`, `approved`, `geosite` и `geoip` обозначают разные слои. Например, личное исключение Apple перед процессами и общая категория Apple после процессов остаются разными наборами. Геокатегории сохраняются отдельно с именем источника. Домены и IP не смешиваются в одном формате MRS.

Одиночные правила и фрагменты, которые нельзя безопасно объединить, записаны прямо в `rules:`. Отдельный провайдер на один домен не скачивается. Сборщик объединяет правила только внутри одного приоритета и не переставляет потенциально пересекающиеся правила с разными направлениями. Для IP/доменов, regex и неизвестных пересечений проверка консервативная. Отдельная проверка сверяет состав каждого выведенного набора с исходником и проверяет порядок всех потенциально пересекающихся противоположных действий; без её успеха релиз не публикуется.

Файл [rules/service-groups.yaml](rules/service-groups.yaml) задаёт только названия сервисов и соответствие доменам/процессам. Он не добавляет правила и не меняет DIRECT/PROXY. Для нового домена по-прежнему достаточно `overrides` ниже: известный сервис определяется автоматически, неизвестный домен остаётся понятной явной строкой. Для объединения нескольких корневых доменов одного нового сервиса можно дополнить каталог. Более конкретный домен в каталоге имеет приоритет при выборе имени сервиса.

## Изменить правило

1. Открыть [rules/policy.yaml](https://github.com/sektor102/2baikal-routing-engine/blob/main/rules/policy.yaml) на GitHub и нажать карандаш **Edit this file**.
2. Найти существующий список `overrides:` и добавить нужные строки под ним. Оставить прежние строки и отступ в два пробела перед `-`. Не добавлять второй ключ `overrides`.
3. Нажать **Commit changes**, сохранить в **main** и дождаться зелёного [Actions](https://github.com/sektor102/2baikal-routing-engine/actions).
4. При изменении правил появится новый Release. Если настроены четыре Secrets, Actions сам обновит PC, Router и HAPP в панели. Иначе перенести нужные блоки вручную. Затем обновить подписки в клиентах; HAPP переподключить.

Примеры строк для **добавления** в существующий список (заменить домены и процессы своими):

```yaml
  - 'DOMAIN-SUFFIX,example.com,DIRECT'  # сайт и все его поддомены напрямую
  - 'DOMAIN-SUFFIX,proxy-example.org,PROXY'  # сайт и поддомены через прокси
  - 'DOMAIN,api.example.net,DIRECT'    # только этот точный домен
  - 'PROCESS-NAME,MyApp.exe,DIRECT'    # процесс Windows напрямую
  - 'PROCESS-NAME,MyGame.exe,PROXY'    # процесс Windows через прокси
  - 'IP-CIDR,203.0.113.0/24,PROXY'
  - 'DOMAIN-SUFFIX,ads-example.org,REJECT'  # заблокировать
```

Домен пишется без `https://`, пути `/page`, порта и `*.`. `DOMAIN-SUFFIX,example.com` покрывает `example.com`, `www.example.com` и остальные поддомены. `DOMAIN,api.example.net` покрывает только указанное имя. Путь страницы средствами доменных правил не выбирается.

Точное имя процесса: Диспетчер задач Windows → **Подробности** → имя с `.exe`. Это правило только для Mihomo PC; в HAPP и Router оно не переносится. Для перехвата трафика приложений обычно нужен TUN. Явные доменные/IP-исключения проверяются раньше процессов, блокировки имеют приоритет.

Примеры не добавлены в рабочую политику. Для переключения менять DIRECT/PROXY/REJECT, согласовав противоположные личные правила; конфликт одного приоритета останавливает сборку. Если правило уже есть в `overrides`, исправить его направление, а не добавлять противоположную копию. Процесс из базовых правил с противоположным направлением и некоторые пересечения доменов DIRECT/PROXY требуют отдельного разрешения конфликта. Некоторые обязательные маршруты закреплены контрольными проверками: их намеренное изменение требует согласованного изменения проверок. При ошибке старый Release продолжает работать. Не удалять «дубли» между типами/назначениями. CIDR проверяются через ipaddress. CDN не резолвятся в вечные IP-правила.

В `friend-approved` добавить точную пару `TYPE,value` для opt-in. Все новые процессы, gstatic.com и keyword battleye требуют ревью. Статусы — в review.json. Персональные широкие процессы Edge/Codex сохранены; явные личные домены проверяются раньше процессов.

`unblock-domains` содержит точечные исключения к блокирующим GeoSite-категориям: сейчас только `graph.whatsapp.com` и `graph.whatsapp.net`, необходимые для функций WhatsApp/Meta AI. Для каждого имени обязательно соответствующее `DOMAIN-SUFFIX,...,PROXY` в `overrides`. Сборщик удаляет только полностью покрытые исключением записи из производной общей GeoSite-базы; поэтому результат одинаков для PC, Router и HAPP. Остальные блокировки сохраняются. Если источник начнёт блокировать более широкий родительский домен или пересекающийся regex/keyword, сборка остановится для проверки. Удалённые записи перечислены в `conflicts.json` → `geosite_block_exceptions`. Список Meta/Meta AI и недостающие домены Facebook, Messenger и Instagram добавлены в `overrides`, с проверками основных имён и поддоменов Graph.

## Источники и приоритеты

`sources/manifest.yaml` задаёт URL, формат, приоритет, доверие и режим. `release.json` фиксирует фактические SHA256/ETag, размеры, категории, время проверки и source date, если оно доступно; неизвестная дата обозначена null. [Устройство движка](docs/design.md).

Mihomo PC: block → личные исключения → процессы → категории → MATCH,DIRECT. Router сохраняет тот же порядок доменных/IP-правил с пропуском процессов. Домены/IP преобразуются официальным Mihomo в MRS. Процессы, keyword, regex остаются classical YAML. MRS для classical запрещён. [Форматы Mihomo](https://wiki.metacubex.one/en/config/rule-providers/).

HAPP сохраняет block-proxy-direct. Из производной proxy-категории вычитаются только целые записи, покрытые явным личным DIRECT, чтобы ru-blocked не перекрыл Apple. Более широкое небезопасное пересечение останавливает сборку. Удаления перечислены в conflicts.json. Полное содержимое twitter проверяется в реальной базе; Grok/xAI учитываются отдельно.

## CI, сбои и откат

Push в **main**, ручной запуск и cron `17 */6 * * *` UTC. GitHub может задержать scheduled run. Push в master тоже запускает проверки, если такая ветка появится; публикует только main. Generated files не коммитятся, циклических push нет.

При недоступности/порче upstream допускается только кэш с проверенными SHA256, форматом и категориями, не старше 7 суток. Без него сборка падает. Снимок друга не объявляется свежим. Draft загружается полностью и только затем становится latest; ошибка не заменяет рабочую сборку. Workflow сериализованы, изменение HEAD main в процессе запрещает устаревшую публикацию.

Без изменения выходного payload нет нового релиза и изменения LastUpdated. Описание существующего релиза может обновляться отдельно, без замены ассетов; перед этим полные тексты для вставки сверяются с SHA256 опубликованных файлов. ETag/дата проверки или неиспользуемая категория сами по себе не создают новую версию. При оборванном upload предыдущий latest работает; проверить и удалить незавершённый draft вручную, повторить workflow.

Откат: выбрать предыдущий [Release](https://github.com/sektor102/2baikal-routing-engine/releases) и импортировать его конфиг. HAPP может не принять меньший LastUpdated: сохранить текущий экспорт, затем удалить/переимпортировать старый профиль средствами приложения, проверить активный профиль и Reconnect. Старый Shadowrocket-код доступен в резервной ветке.

Лицензии: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Equivalent Xray test не является запуском HAPP на iPhone. `-t` не доказывает отсутствие DNS-утечек или стабильность игровой связи: эти свойства проверяются на устройстве.
