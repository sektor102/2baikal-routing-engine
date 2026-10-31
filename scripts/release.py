"""Publish immutable payloads and refresh copyable Remnawave release notes."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from engine.io import digest,read_json,write_json
from engine.model import Invalid
from engine.compiler import scan_secrets


def api(path,method='GET',body=None,raw=None):
    token=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    headers={'User-Agent':'2Baikal-Routing/0.1','Accept':'application/vnd.github+json',
             'X-GitHub-Api-Version':'2022-11-28'}
    if token: headers['Authorization']='Bearer '+token
    data=json.dumps(body).encode() if body is not None else raw
    if data is not None: headers['Content-Type']='application/json' if raw is None else 'application/octet-stream'
    url=path if path.startswith('https://') else 'https://api.github.com'+path
    if urllib.parse.urlsplit(url).hostname not in {'api.github.com','uploads.github.com'}:
        raise Invalid('Refusing authenticated request outside GitHub API/upload hosts')
    with urllib.request.urlopen(urllib.request.Request(url,data=data,headers=headers,method=method),timeout=90) as response:
        data=response.read(100_000_000)
        return json.loads(data) if 'json' in response.headers.get('Content-Type','') else data


def restore(repository):
    try: latest=api('/repos/'+repository+'/releases/latest')
    except urllib.error.HTTPError as exc:
        if exc.code!=404: raise
        print('No previous published release')
        return
    asset=next((a for a in latest['assets'] if a['name']=='release.json'),None)
    if asset is None:
        raise Invalid('Latest release lacks engine release.json; cannot use as verified baseline')
    # Public repository assets contain no token in the download URL.
    with urllib.request.urlopen(asset['browser_download_url'],timeout=30) as response: raw=response.read(5_000_001)
    if len(raw)>5_000_000: raise Invalid('Previous metadata too large')
    previous=json.loads(raw)
    if previous.get('version')!=latest['tag_name']: raise Invalid('Previous version/tag mismatch')
    write_json(ROOT/'.previous-release/release.json',previous)
    print('Previous release:',previous['version'])


def prepare():
    dist=ROOT/'dist'
    metadata=read_json(dist/'release.json')
    validation=read_json(ROOT/'reports/validation.json')
    if validation.get('artifact_tree_sha256')!=digest(dist/'SHA256SUMS'):
        raise Invalid('Validation does not belong to this artifact tree')
    if validation.get('golden_failures') or validation.get('schema')!='passed':
        raise Invalid('Routing/schema validation missing')
    if any(validation.get('service_equivalence',{}).get(client,{}).get('status')!='passed'
           for client in ['pc','router']):
        raise Invalid('Service regrouping equivalence proof missing')
    if not isinstance(validation.get('mihomo'),list) or not isinstance(validation.get('xray'),dict):
        raise Invalid('Both native binary checks required')
    expected={'mihomo/config.yaml','mihomo/config-doh-optional.yaml','mihomo-router/config.yaml'}
    if {row.get('profile') for row in validation['mihomo']}!=expected:
        raise Invalid('Native Mihomo checks required for PC, optional DoH and Router')
    for row in validation['mihomo']:
        if row['returncode']: raise Invalid('Mihomo validation failed')
    if validation['xray']['returncode']: raise Invalid('Xray validation failed')
    declared=set()
    for line in (dist/'SHA256SUMS').read_text().splitlines():
        sha,relative=line.split('  ',1)
        path=dist/relative
        if not path.resolve().is_relative_to(dist.resolve()) or digest(path)!=sha:
            raise Invalid('Artifact modified after validation: '+relative)
        declared.add(relative)
    actual={f.relative_to(dist).as_posix() for f in dist.rglob('*') if f.is_file()}-{'SHA256SUMS'}
    if actual!=declared: raise Invalid('Unexpected or missing artifact files')
    scan_secrets(dist)
    dest=ROOT/'release-assets'
    if dest.exists(): shutil.rmtree(dest)
    dest.mkdir()
    names={'happ/routing.json':'happ-routing.json','happ/import-link.txt':'happ-import-link.txt',
           'mihomo/config.yaml':'mihomo-config.yaml','mihomo/config-doh-optional.yaml':'mihomo-config-doh-optional.yaml',
           'mihomo-router/config.yaml':'mihomo-router-config.yaml'}
    for file in sorted(dist.rglob('*')):
        if not file.is_file() or file.name=='SHA256SUMS': continue
        rel=file.relative_to(dist).as_posix()
        name=names.get(rel,file.name)
        if (dest/name).exists():
            if digest(dest/name)!=digest(file): raise Invalid('Release asset filename collision: '+name)
            continue  # PC and Router share byte-identical domain/IP providers.
        shutil.copyfile(file,dest/name)
    shutil.copyfile(ROOT/'reports/validation.json',dest/'validation.json')
    for name in ['coverage-diff.json','changelog.md','twitter.json','category-overlaps.json','provider-diff.json','personal-route-collisions.json']:
        if (ROOT/'reports'/name).exists(): shutil.copyfile(ROOT/'reports'/name,dest/name)
    for name in ['LICENSE','THIRD_PARTY_NOTICES.md']:
        if (ROOT/name).exists(): shutil.copyfile(ROOT/name,dest/name)
    with zipfile.ZipFile(dest/'2baikal-routing.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(dist.rglob('*')):
            if file.is_file(): archive.write(file,file.relative_to(dist).as_posix())
    sums=''.join(f'{digest(file)}  {file.name}\n' for file in sorted(dest.iterdir()))
    (dest/'SHA256SUMS').write_text(sums,encoding='utf-8',newline='\n')
    print('Prepared',len(list(dest.iterdir())),'validated release assets')
    return metadata,dest


def code_block(text,language=''):
    # Keep even embedded Markdown fences inside the copyable configuration.
    import re
    fence='`'*max(3,max((len(run)+1 for run in re.findall(r'`+',text)),default=0))
    return fence+language+'\n'+text+('' if text.endswith('\n') else '\n')+fence


def release_notes(meta,dest):
    base=f"https://github.com/{meta['repository']}/releases/download/{meta['version']}"
    policy=f"https://github.com/{meta['repository']}/edit/main/rules/policy.yaml"
    files={name:(dest/name).read_text(encoding='utf-8')
           for name in ['mihomo-config.yaml','mihomo-router-config.yaml','happ-import-link.txt']}

    def render(embedded):
        def content(name,language):
            if name in embedded: return code_block(files[name],language)
            return 'Полный текст слишком большой для описания. [Открыть файл]('+base+'/'+name+') и скопировать его содержимое целиком.'
        return f'''## Подключение к Remnawave

Три готовых блока ниже: раскройте нужный и скопируйте содержимое кнопкой в правом верхнем углу кода.

**Файлы для подключения:** [Mihomo PC]({base}/mihomo-config.yaml) · [Mihomo Router]({base}/mihomo-router-config.yaml) · [HAPP routing]({base}/happ-import-link.txt)

<details>
<summary><b>Mihomo PC — шаблон для Clash Verge на Windows</b></summary>

1. Remnawave → Подписка → Mihomo → ваш шаблон для ПК (**Default** или **2Baikal**).
2. Замените содержимое редактора полным YAML ниже и сохраните. Сохраните оба маркера `# LEAVE THIS LINE!`: серверы подставляет Remnawave.
3. Назначьте этот шаблон ответу Mihomo своей подписки, если ещё не назначен. В Clash Verge обновите обычную подписку Remnawave и выберите рабочий сервер в группе `→ Remnawave`.

{content('mihomo-config.yaml','yaml')}

</details>

<details>
<summary><b>Mihomo Router — домены, поддомены и IP/CIDR, без процессов</b></summary>

1. Remnawave → Подписка → Mihomo → отдельный шаблон **Router**.
2. Вставьте полный YAML ниже и сохраните. Маркеры `# LEAVE THIS LINE!` нужны для подстановки серверов панелью.
3. Назначьте Router подписке своего роутера и обновите её. Домены, DOMAIN-SUFFIX, категории GeoSite и IP/CIDR сохранены. PROCESS-NAME отсутствует; поиск процессов отключён (`find-process-mode: off`). Отфильтровывать Windows-процессы на роутере не требуется.

{content('mihomo-router-config.yaml','yaml')}

</details>

<details>
<summary><b>HAPP — готовое значение заголовка routing</b></summary>

1. Remnawave → Подписка → Настройки → Заголовки ответа.
2. Замените значение заголовка `routing` строкой ниже целиком и сохраните. Нужна сама строка `happ://routing/add/…`, а не HTTPS-адрес файла.
3. В HAPP обновите подписку, включите профиль **2Baikal-Routing**, дождитесь загрузки геофайлов и выполните Reconnect. В JSON-подписке профиль доставляется вместе с подпиской.

{content('happ-import-link.txt','text')}

</details>

<details>
<summary>Как добавить сайт, домен или процесс</summary>

Откройте [rules/policy.yaml → редактировать]({policy}) и добавьте строки в существующий список `overrides`. Существующие строки оставьте.

```yaml
  - 'DOMAIN-SUFFIX,example.com,DIRECT'  # сайт и все поддомены напрямую
  - 'DOMAIN,api.example.org,PROXY'     # только этот домен через прокси
  - 'PROCESS-NAME,MyApp.exe,DIRECT'    # процесс Windows напрямую
  - 'PROCESS-NAME,MyGame.exe,PROXY'    # процесс Windows через прокси
```

Это примеры: замените домены и имена процессов своими. Пишите домен без `https://`, пути и порта. Имя процесса берите в Диспетчере задач Windows → Подробности. Правила процессов работают только в Mihomo на ПК; для перехвата трафика приложений обычно нужен TUN.

Сохраните коммит в **main** и дождитесь зелёного Actions. При изменении правил появится новый Release. Настроенный синхронизатор Actions перенесёт PC, Router и HAPP в Remnawave; без настройки перенесите нужные блоки вручную. Затем обновите подписки клиентов.

Если сборка сообщает о конфликте, новая политика не публикуется. Блокировки имеют приоритет; некоторые пересечения DIRECT/PROXY требуют согласования из-за порядка групп HAPP.

</details>

<details>
<summary>Обновления, проверки и дополнительные ассеты</summary>

GitHub проверяет источники каждые 6 часов и публикует только изменившуюся проверенную политику. URL внутри профилей закреплены за этим релизом. `scripts/sync_remnawave.py` обновляет через API два шаблона Mihomo и заголовок HAPP, когда настроены Secrets; настройка описана в README. `profile-update-interval: 6` задаёт клиентам 6 часов, а в Clash Verge вручную задаётся 360 минут.

Остальные ассеты — базы, провайдеры правил, отчёты и резервные форматы. Конфиги загружают базы и провайдеры по ссылкам. PC и Router переиспользуют одинаковые доменные/IP-провайдеры без удвоения ассетов. Для вставки в панель достаточно нужных блоков выше.

[Полный архив]({base}/2baikal-routing.zip) · [SHA256SUMS]({base}/SHA256SUMS) · [Проверки]({base}/validation.json) · [Изменения]({base}/changelog.md)

[Наборы по сервисам]({base}/rulesets.md) · [Проверка сохранения приоритетов]({base}/ruleset-layout.json)

Исходных личных правил: {meta['counts']['personal']}. Перед публикацией проверены схемы, контрольные маршруты и конфиги штатными Mihomo/Xray. Проверка HAPP на самом iPhone остаётся ручной.

</details>
'''
    embedded=set(files)
    body=render(embedded)
    # Leave room below GitHub's body limits as the policy grows. Never truncate
    # a configuration: fall back to an exact-version download link instead.
    for name in ['mihomo-router-config.yaml','mihomo-config.yaml','happ-import-link.txt']:
        if len(body.encode('utf-8'))<=120_000: break
        embedded.remove(name)
        body=render(embedded)
    return body


def refresh_notes(repository,meta,dest,existing,body):
    # A spoiler must show the bytes actually served by this published release.
    for name in ['mihomo-config.yaml','mihomo-router-config.yaml','happ-import-link.txt']:
        assets=[a for a in existing['assets'] if a['name']==name]
        if len(assets)!=1 or assets[0].get('digest')!='sha256:'+digest(dest/name):
            raise Invalid('Published configuration differs from release notes: '+name)
    if existing.get('body')!=body:
        api('/repos/'+repository+'/releases/'+str(existing['id']),'PATCH',{'body':body})
        print('Updated Remnawave spoilers; release assets and LastUpdated unchanged')
    else:
        print('Remnawave release notes unchanged')


def publish(repository,commit):
    meta,dest=prepare()
    if not meta.get('publishable') or meta.get('repository')!=repository:
        raise Invalid('Unhosted or wrong-repository candidate')
    head=api('/repos/'+repository+'/git/ref/heads/main')['object']['sha']
    if head!=commit: raise Invalid('main moved during build; refusing stale publication')
    result=read_json(ROOT/'reports/build-result.json')
    tag=meta['version']
    body=release_notes(meta,dest)
    try:
        existing=api('/repos/'+repository+'/releases/tags/'+tag)
    except urllib.error.HTTPError as exc:
        if exc.code!=404: raise
        existing=None
    if existing and not existing['draft']:
        refresh_notes(repository,meta,dest,existing,body)
        if not result['changed']: print('Payload unchanged; no release, no LastUpdated change')
        print('Immutable version already published:',existing['html_url'])
        return
    if existing:
        # Do not overwrite partially uploaded drafts automatically. A maintainer
        # can inspect/remove the draft and retry; the previous latest stays valid.
        raise Invalid('Incomplete draft exists; inspect it before retry')
    if not result['changed']: raise Invalid('Unchanged payload has no published release')
    release=api('/repos/'+repository+'/releases','POST',
                {'tag_name':tag,'target_commitish':commit,'name':'2Baikal '+tag,
                 'body':body,'draft':True,'prerelease':False})
    upload=release['upload_url'].split('{',1)[0]
    for file in sorted(dest.iterdir()):
        asset=api(upload+'?name='+urllib.parse.quote(file.name),'POST',raw=file.read_bytes())
        if asset.get('size')!=file.stat().st_size: raise Invalid('Upload size mismatch')
        if asset.get('digest') and asset['digest']!='sha256:'+digest(file): raise Invalid('Upload checksum mismatch')
    published=api('/repos/'+repository+'/releases/'+str(release['id']),'PATCH',{'draft':False,'make_latest':'true'})
    print('Published:',published['html_url'])


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('operation',choices=['restore','prepare','publish'])
    parser.add_argument('--repository',default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--commit',default=os.environ.get('SOURCE_SHA'))
    args=parser.parse_args()
    if args.operation=='restore': restore(args.repository)
    elif args.operation=='prepare': prepare()
    else:
        if not args.commit: raise Invalid('Explicit source commit required')
        publish(args.repository,args.commit)
