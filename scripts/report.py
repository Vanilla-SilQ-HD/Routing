"""Self-contained interactive HTML report for a Routing build."""
from __future__ import annotations

import json


DATASETS = (
    ("blocked-domains", "Домены", "Маршрутизация и DNS"),
    ("blocked-services-ip", "Сети приложений", "Проверенные сети Telegram"),
    ("blocked-registry-ip", "Точные IP", "Только /32 и /128 из блок-листов"),
    ("routing-direct-exceptions", "Direct-исключения", "Приоритетные правила Direct"),
)


def make_report(manifest, exclusions, probes):
    repository = manifest["environment"].get("repository", "Vanilla-SilQ-HD/Routing")
    owner, project = repository.split("/", 1)
    release_base = f"https://github.com/{repository}/releases/latest/download/"
    output = manifest["output"]
    services = manifest["service_networks"]
    registry = manifest["registry_ip"]
    direct = manifest["direct_exceptions"]
    changes = manifest["domain_diff"]
    data = {
        "meta": {
            "repository": repository,
            "builtAt": manifest["built_at"],
            "commit": manifest["environment"].get("github_commit"),
            "pagesUrl": f"https://{owner.lower()}.github.io/{project}/",
            "releaseUrl": f"https://github.com/{repository}/releases/latest",
            "runUrl": f"https://github.com/{repository}/actions",
        },
        "summary": {
            "domains": output["total_conditions"],
            "exact": output["exact"],
            "suffix": output["suffix"],
            "srsBytes": output["srs_bytes"],
            "sources": len(manifest["sources"]),
            "servicePrefixes": services["output"]["total_prefixes"],
            "registryPrefixes": registry["output"]["total_prefixes"],
            "directRules": direct["output"]["total_conditions"],
            "added": changes["added"],
            "removed": changes["removed"],
            "effectiveAdded": changes["effective_added"],
            "effectiveRemoved": changes["effective_removed"],
        },
        "downloads": [
            {
                "name": name,
                "title": title,
                "description": description,
                "url": release_base + name + ".srs",
                "shaUrl": release_base + name + ".srs.sha256",
                "sha256": output["files"][name + ".srs"],
                "bytes": (output["srs_bytes"] if name == "blocked-domains" else
                          services["output"]["srs_bytes"] if name == "blocked-services-ip" else
                          registry["output"]["srs_bytes"] if name == "blocked-registry-ip" else
                          direct["output"]["srs_bytes"]),
            }
            for name, title, description in DATASETS
        ],
        "sources": [
            {
                "id": source["id"],
                "url": source["url"],
                "conditions": source["unique_conditions"],
                "ips": source["ip_addresses"],
                "invalid": source["invalid"],
                "filtered": source["filtered_conditions"],
                "sha256": source["sha256"],
            }
            for source in manifest["sources"]
        ],
        "probes": probes,
        "changes": manifest.get("domain_changes", changes),
        "exclusions": exclusions,
        "services": {
            "baseline": services["validation"]["baseline"],
            "sources": [
                {
                    "service": source["service"],
                    "url": source["url"],
                    "ipv4": source["ipv4_prefixes"],
                    "ipv6": source["ipv6_prefixes"],
                }
                for source in services["sources"]
            ],
        },
        "registry": registry["output"],
        "validation": {
            "domainBaseline": manifest["validation"]["baseline"],
            "serviceBaseline": services["validation"]["baseline"],
            "registryBaseline": registry["validation"]["baseline"],
            "compiler": manifest["compiler"],
            "scope": manifest["scope"],
        },
    }
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    template = r'''<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Routing Dashboard</title>
<style>
:root{--bg:#08111f;--panel:#101c2e;--panel2:#15243a;--line:#293c56;--text:#e7f0fc;--muted:#93a9c4;--vpn:#45d7a5;--direct:#70b7ff;--danger:#ff8b98;--shadow:0 12px 36px #02071055}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 90% 0,#12305255,transparent 35%),var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}a{color:var(--direct);text-decoration:none}a:hover{text-decoration:underline}button,input,select{font:inherit}button{cursor:pointer}.wrap{max-width:1440px;margin:auto;padding:28px}.top{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.brand{display:flex;gap:16px;align-items:center}.mark{display:grid;place-items:center;width:50px;height:50px;border-radius:14px;background:linear-gradient(135deg,var(--direct),var(--vpn));color:#07111f;font-weight:800;font-size:20px}.brand h1{margin:0;font-size:28px;letter-spacing:2px}.brand p{margin:3px 0 0;color:var(--muted)}.meta{text-align:right;color:var(--muted);font-size:13px}.meta a{margin-left:14px}.grid{display:grid;gap:14px}.cards{grid-template-columns:repeat(6,minmax(0,1fr));margin:24px 0}.card,.panel{background:linear-gradient(145deg,#122037,var(--panel));border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}.card{padding:16px}.card .value{font-size:25px;font-weight:700;letter-spacing:-.5px}.card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.8px}.card .hint{color:var(--muted);font-size:12px;margin-top:4px}.vpn{color:var(--vpn)}.direct{color:var(--direct)}.danger{color:var(--danger)}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0 14px}.tabs button{border:1px solid var(--line);background:var(--panel);color:var(--muted);border-radius:9px;padding:9px 14px}.tabs button.active{background:#204a70;color:#fff;border-color:#4b83b5}.panel{display:none;padding:20px}.panel.active{display:block}.panel h2{margin:0 0 5px;font-size:20px}.panel .description{color:var(--muted);margin:0 0 16px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.toolbar input,.toolbar select{background:#0b1728;border:1px solid var(--line);color:var(--text);border-radius:8px;padding:9px 11px;min-width:180px}.toolbar input{flex:1;max-width:480px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px}table{width:100%;border-collapse:collapse;white-space:nowrap}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{background:#172740;color:#b7c9de;font-size:12px;text-transform:uppercase;letter-spacing:.5px}tr:last-child td{border-bottom:0}tbody tr:hover{background:#17253a}td.domain,td.sha{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;white-space:normal;max-width:460px}.sha{font-size:11px;color:var(--muted)}.badge{display:inline-block;padding:3px 8px;border-radius:6px;font-size:12px;font-weight:600}.badge.vpn{background:#123b32}.badge.direct{background:#153656}.badge.neutral{background:#26364b;color:#c0cfdf}.badge.danger{background:#4b2530}.columns{display:grid;grid-template-columns:1fr 1fr;gap:14px}.downloads{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.download{padding:16px;border:1px solid var(--line);border-radius:12px;background:#0d192a}.download h3{margin:0 0 5px}.download p{color:var(--muted);margin:0 0 12px}.download .links{display:flex;gap:14px;flex-wrap:wrap}.download .hash{margin-top:10px;font:11px ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted);overflow-wrap:anywhere}.notice{border-left:3px solid var(--direct);padding:12px 14px;background:#10233a;border-radius:6px;color:#bfd1e7;margin:14px 0}.checks{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.check{padding:12px;border:1px solid var(--line);border-radius:9px;background:#0e1a2a}.check:before{content:"✓";color:var(--vpn);font-weight:700;margin-right:9px}.empty{padding:28px;text-align:center;color:var(--muted)}.count{color:var(--muted);font-size:13px;margin:8px 0}.small{font-size:12px;color:var(--muted)}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#c1d7ef}.footer{margin:24px 0 4px;text-align:center;color:var(--muted);font-size:12px}@media(max-width:1100px){.cards{grid-template-columns:repeat(3,1fr)}}@media(max-width:700px){.wrap{padding:16px}.top{display:block}.meta{text-align:left;margin-top:12px}.meta a{margin:0 12px 0 0}.cards{grid-template-columns:repeat(2,1fr)}.columns,.downloads,.checks{grid-template-columns:1fr}.panel{padding:14px}.card .value{font-size:21px}}
</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div class="brand"><div class="mark">R</div><div><h1>ROUTING</h1><p>Интерактивный отчёт выборочной маршрутизации</p></div></div>
  <div class="meta"><div id="built"></div><div id="commit"></div><div style="margin-top:7px"><a id="release" target="_blank" rel="noopener">Релиз</a><a id="actions" target="_blank" rel="noopener">Actions</a><a id="repository" target="_blank" rel="noopener">Репозиторий</a></div></div>
</header>
<section id="cards" class="grid cards"></section>
<nav class="tabs" aria-label="Разделы отчёта">
  <button data-tab="overview" class="active">Обзор</button>
  <button data-tab="probes">VPN / Direct</button>
  <button data-tab="sources">Источники</button>
  <button data-tab="changes">Изменения</button>
  <button data-tab="networks">IP и сети</button>
  <button data-tab="validation">Проверки</button>
</nav>
<section id="overview" class="panel active">
  <h2>Скачать наборы</h2><p class="description">Постоянные URL ведут на последний опубликованный релиз. Для DNS используйте только доменный набор.</p>
  <div id="downloads" class="downloads"></div>
  <div class="notice">Порядок в AWG Manager: <code>routing-direct-exceptions</code> → Direct, затем <code>routing</code>, <code>routing-services</code>, <code>routing-registry-ip</code> → VPN. Final outbound: <b>direct</b>.</div>
</section>
<section id="probes" class="panel">
  <h2>Контрольные маршруты</h2><p class="description">Обязательные ожидания останавливают сборку при несовпадении. Поиск работает по домену, правилу и источнику.</p>
  <div class="toolbar"><input id="probe-search" type="search" placeholder="Домен, правило или источник…"><select id="probe-filter"><option value="">VPN и Direct</option><option value="VPN">Только VPN</option><option value="Direct">Только Direct</option></select></div>
  <div id="probe-count" class="count"></div><div class="table-wrap"><table><thead><tr><th>Домен</th><th>База</th><th>Итог</th><th>Ожидание</th><th>Совпавшее правило</th><th>Источники</th></tr></thead><tbody id="probe-rows"></tbody></table></div>
</section>
<section id="sources" class="panel">
  <h2>Источники доменов</h2><p class="description">Пересечения помогают дополнять базу, но не считаются независимыми подтверждениями.</p>
  <div class="table-wrap"><table><thead><tr><th>Источник</th><th>Доменных условий</th><th>Точных IP</th><th>Неверных</th><th>Отфильтровано</th><th>SHA-256</th></tr></thead><tbody id="source-rows"></tbody></table></div>
  <h2 style="margin-top:24px">Исключённые широкие условия</h2><p class="description">PSL и общая инфраструктура не попадают в общий VPN-набор.</p><div id="exclusion-count" class="count"></div>
  <div class="toolbar"><input id="exclusion-search" type="search" placeholder="Домен или причина…"></div><div class="table-wrap"><table><thead><tr><th>Условие</th><th>Тип</th><th>Причина</th><th>Источники</th></tr></thead><tbody id="exclusion-rows"></tbody></table></div>
</section>
<section id="changes" class="panel">
  <h2>Семантический diff</h2><p class="description">Effective — изменение фактического покрытия после поглощения дочерних правил новыми suffix-правилами.</p>
  <div id="change-cards" class="grid cards"></div>
  <div class="columns"><div><h3>Добавленные условия</h3><div class="toolbar"><input id="added-search" type="search" placeholder="Фильтр добавленных…"></div><div class="table-wrap"><table><tbody id="added-rows"></tbody></table></div></div><div><h3>Удалённые условия</h3><div class="toolbar"><input id="removed-search" type="search" placeholder="Фильтр удалённых…"></div><div class="table-wrap"><table><tbody id="removed-rows"></tbody></table></div></div></div>
  <h3 style="margin-top:22px">Фактически потерянное покрытие</h3><div class="table-wrap"><table><tbody id="lost-rows"></tbody></table></div>
</section>
<section id="networks" class="panel">
  <h2>Сервисные сети</h2><p id="service-baseline" class="description"></p><div class="table-wrap"><table><thead><tr><th>Сервис</th><th>IPv4</th><th>IPv6</th><th>Источник</th></tr></thead><tbody id="service-rows"></tbody></table></div>
  <h2 style="margin-top:24px">Точные registry-IP</h2><p class="description">Отдельный набор: общий адрес из блок-листа не считается доказательно выделенной сетью сервиса.</p><div id="registry-list" class="columns"></div>
  <h2 style="margin-top:24px">Direct-исключения</h2><div id="direct-rules" class="notice"></div>
</section>
<section id="validation" class="panel">
  <h2>Результаты проверок</h2><p class="description">Все четыре SRS проходят одинаковый путь валидации перед публикацией.</p>
  <div class="checks"><div class="check">Unit-тесты и обязательные probes</div><div class="check">Compile / decompile всех SRS</div><div class="check">sing-box check</div><div class="check">SHA-256 и повторное скачивание</div><div class="check">Semantic diff без скрытой потери покрытия</div><div class="check">Только /32 и /128 в registry-IP</div></div>
  <div id="baselines" style="margin-top:18px" class="table-wrap"></div>
  <h3 style="margin-top:22px">Область сборки</h3><div id="scope"></div>
</section>
<footer class="footer">Routing Dashboard · данные сформированы сборщиком · внешние скрипты и трекеры не используются</footer>
</div>
<script>window.ROUTING_DATA=__PAYLOAD__;</script>
<script>
const D=window.ROUTING_DATA,S=D.summary;
const $=id=>document.getElementById(id);
const fmt=n=>Number(n).toLocaleString('ru-RU');
const bytes=n=>n<1024?n+' Б':n<1048576?(n/1024).toFixed(1)+' КБ':(n/1048576).toFixed(2)+' МБ';
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const badge=v=>`<span class="badge ${v==='VPN'?'vpn':v==='Direct'?'direct':'neutral'}">${esc(v||'—')}</span>`;
const empty=(text,colspan=1)=>`<tr><td colspan="${colspan}" class="empty">${esc(text)}</td></tr>`;
$('built').textContent='Сборка: '+new Date(D.meta.builtAt).toLocaleString('ru-RU',{timeZone:'UTC'})+' UTC';
$('commit').textContent=D.meta.commit?'Commit: '+D.meta.commit:'Локальная сборка';
$('release').href=D.meta.releaseUrl;$('actions').href=D.meta.runUrl;$('repository').href='https://github.com/'+D.meta.repository;
const cards=[['Доменных условий',fmt(S.domains),fmt(S.exact)+' exact · '+fmt(S.suffix)+' suffix'],['Источников',fmt(S.sources),'автообновление 4 раза в сутки'],['Сети приложений',fmt(S.servicePrefixes),'проверенные сети Telegram'],['Точные IP',fmt(S.registryPrefixes),'отдельный registry-набор'],['Direct-исключения',fmt(S.directRules),'приоритет над VPN'],['Размер доменного SRS',bytes(S.srsBytes),'двоичный rule-set']];
$('cards').innerHTML=cards.map(([l,v,h])=>`<div class="card"><div class="label">${l}</div><div class="value">${v}</div><div class="hint">${h}</div></div>`).join('');
$('downloads').innerHTML=D.downloads.map(x=>`<article class="download"><h3>${esc(x.title)}</h3><p>${esc(x.description)} · ${bytes(x.bytes)}</p><div class="links"><a href="${x.url}">Скачать SRS</a><a href="${x.shaUrl}">SHA-256</a></div><div class="hash">${esc(x.sha256)}</div></article>`).join('');
function probes(){const q=$('probe-search').value.toLowerCase(),f=$('probe-filter').value;const rows=D.probes.filter(p=>(!f||p.final_decision===f)&&(!q||[p.domain,p.matched_rule,(p.sources||[]).join(' ')].join(' ').toLowerCase().includes(q)));$('probe-count').textContent=`Показано ${fmt(rows.length)} из ${fmt(D.probes.length)}`;$('probe-rows').innerHTML=rows.length?rows.map(p=>`<tr><td class="domain">${esc(p.domain)}</td><td>${badge(p.base_decision)}</td><td>${badge(p.final_decision)}</td><td>${badge(p.expected)}</td><td class="domain">${esc(p.matched_rule||'—')}</td><td>${esc((p.sources||[]).join(', ')||'—')}</td></tr>`).join(''):empty('Ничего не найдено',6)}
$('probe-search').addEventListener('input',probes);$('probe-filter').addEventListener('change',probes);probes();
$('source-rows').innerHTML=D.sources.map(s=>`<tr><td class="domain"><a href="${s.url}">${esc(s.id)}</a></td><td>${fmt(s.conditions)}</td><td>${fmt(s.ips)}</td><td>${fmt(s.invalid)}</td><td>${fmt(s.filtered)}</td><td class="sha">${esc(s.sha256)}</td></tr>`).join('');
function exclusions(){const q=$('exclusion-search').value.toLowerCase();const rows=D.exclusions.filter(x=>!q||[x.domain,x.reason,(x.sources||[]).join(' ')].join(' ').toLowerCase().includes(q));$('exclusion-count').textContent=`Показано ${fmt(rows.length)} из ${fmt(D.exclusions.length)}`;$('exclusion-rows').innerHTML=rows.length?rows.map(x=>`<tr><td class="domain">${esc(x.domain)}</td><td><code>${esc(x.kind)}</code></td><td>${esc(x.reason)}</td><td>${esc((x.sources||[]).join(', '))}</td></tr>`).join(''):empty('Ничего не найдено',4)}
$('exclusion-search').addEventListener('input',exclusions);exclusions();
const C=D.changes;
$('change-cards').innerHTML=[['Добавлено',fmt(C.total_added??S.added),'vpn'],['Удалено',fmt(C.total_removed??S.removed),'direct'],['Новое покрытие',fmt(C.effective_added??S.effectiveAdded),'vpn'],['Потеряно покрытие',fmt(C.effective_removed??S.effectiveRemoved),(C.effective_removed??S.effectiveRemoved)?'danger':'vpn']].map(([l,v,c])=>`<div class="card"><div class="label">${l}</div><div class="value ${c}">${v}</div></div>`).join('');
function listRows(items,input,output,emptyText){const q=$(input).value.toLowerCase(),rows=(items||[]).filter(x=>x.toLowerCase().includes(q));$(output).innerHTML=rows.length?rows.map(x=>`<tr><td class="domain">${esc(x)}</td></tr>`).join(''):empty(emptyText)}
function changeLists(){const groups=C.by_kind||{},added=Object.values(groups).flatMap(x=>x.added_sample||[]),removed=Object.values(groups).flatMap(x=>x.removed_sample||[]);listRows(added,'added-search','added-rows','Добавлений нет');listRows(removed,'removed-search','removed-rows','Удалений нет');$('lost-rows').innerHTML=(C.effective_removed_sample||[]).length?C.effective_removed_sample.map(x=>`<tr><td class="domain danger">${esc(x)}</td></tr>`).join(''):empty('Потерянного покрытия нет')}
$('added-search').addEventListener('input',changeLists);$('removed-search').addEventListener('input',changeLists);changeLists();
$('service-baseline').textContent='Baseline: '+D.services.baseline+'. Общие облачные сети не включаются.';
$('service-rows').innerHTML=D.services.sources.map(s=>`<tr><td>${esc(s.service)}</td><td>${fmt(s.ipv4)}</td><td>${fmt(s.ipv6)}</td><td class="domain"><a href="${s.url}">${esc(s.url)}</a></td></tr>`).join('');
$('registry-list').innerHTML=D.registry.prefixes.length?D.registry.prefixes.map(x=>`<code class="download">${esc(x)}</code>`).join(''):'<div class="empty">Нет адресов</div>';
$('direct-rules').textContent='Условий: '+fmt(S.directRules)+'. Пустой набор безопасен и не имеет совпадений.';
$('baselines').innerHTML=`<table><tbody><tr><td>Доменный baseline</td><td><code>${esc(D.validation.domainBaseline)}</code></td></tr><tr><td>Сервисный baseline</td><td><code>${esc(D.validation.serviceBaseline)}</code></td></tr><tr><td>Registry baseline</td><td><code>${esc(D.validation.registryBaseline)}</code></td></tr><tr><td>Компилятор</td><td><code>${esc(D.validation.compiler.version)}</code></td></tr><tr><td>sing-box check</td><td><span class="badge vpn">${esc(D.validation.compiler.sing_box_check)}</span></td></tr></tbody></table>`;
$('scope').innerHTML=Object.entries(D.validation.scope).map(([k,v])=>`<div class="download"><code>${esc(k)}</code>: <b>${esc(v)}</b></div>`).join('');
document.querySelectorAll('.tabs button').forEach(button=>button.addEventListener('click',()=>{document.querySelectorAll('.tabs button,.panel').forEach(x=>x.classList.remove('active'));button.classList.add('active');$(button.dataset.tab).classList.add('active');history.replaceState(null,'','#'+button.dataset.tab)}));
const initial=location.hash.slice(1);if($(initial)&&document.querySelector(`[data-tab="${initial}"]`))document.querySelector(`[data-tab="${initial}"]`).click();
</script>
</body>
</html>'''
    return template.replace("__PAYLOAD__", payload)
