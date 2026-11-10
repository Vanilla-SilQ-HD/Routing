"""Small external availability probe. Never changes routing rules."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = "Routing-Monitor/1 (public availability checks)"


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def request_json(url, *, payload=None, timeout=30):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, headers={
        "User-Agent": USER_AGENT, "Accept": "application/json",
        "Content-Type": "application/json" if data else "application/x-www-form-urlencoded",
    }, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read(4 * 1024 * 1024 + 1))
    except urllib.error.HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", errors="replace")
        raise RuntimeError(f"Globalping HTTP {exc.code}: {detail}") from exc


def create_measurement(config, target):
    provider = config["provider"]
    return request_json(provider["url"], payload={
        "limit": provider["probes_per_target"],
        "locations": [{"country": provider["country"]}],
        "target": target,
        "type": "http",
        "measurementOptions": {
            "request": {"method": "HEAD", "path": "/", "headers": {}},
            "protocol": "HTTPS",
            "ipVersion": 4,
        },
    })


def wait_for_measurement(config, measurement_id):
    started = time.monotonic()
    url = config["provider"]["url"] + "/" + measurement_id
    while time.monotonic() - started < config["provider"]["timeout_seconds"]:
        measurement = request_json(url)
        if measurement.get("status") in {"finished", "failed", "aborted"}:
            return measurement
        time.sleep(2)
    raise TimeoutError(f"Globalping measurement timed out: {measurement_id}")


def classify_result(result):
    nested = result.get("result", {})
    status_code = result.get("statusCode", nested.get("statusCode"))
    status = result.get("status", nested.get("status", "unknown"))
    if isinstance(status_code, int) and 200 <= status_code < 400:
        return "works_direct"
    if status_code in {401, 403, 451}:
        return "blocked_or_geo"
    if status_code == 429 or status in {"failed", "aborted"}:
        return "unknown"
    return "down_or_error"


def load_previous(url):
    try:
        return request_json(url)
    except (OSError, ValueError, RuntimeError, urllib.error.URLError):
        return {"history": []}


def run_probe(config, target):
    try:
        created = create_measurement(config, target)
        measurement = wait_for_measurement(config, created["id"])
        results = measurement.get("results", [])
        if not results:
            return {"target": target, "status": "unknown", "http_status": None, "error": "empty result"}
        result = results[0]
        nested = result.get("result", {})
        return {
            "target": target,
            "status": classify_result(result),
            "http_status": result.get("statusCode", nested.get("statusCode")),
            "error": result.get("error", nested.get("error")),
            "raw_output": str(nested.get("rawOutput", result.get("rawOutput", "")))[:500],
        }
    except (OSError, ValueError, KeyError, TimeoutError, urllib.error.URLError) as exc:
        return {"target": target, "status": "unknown", "http_status": None, "error": str(exc)[:300]}


def html_report(data):
    latest = data["history"][-1]["results"] if data["history"] else []
    rows = "".join(
        f"<tr><td>{item['target']}</td><td><span class='status {item['status']}'>{item['status']}</span></td>"
        f"<td>{item.get('http_status') or '—'}</td><td>{item.get('error') or '—'}</td></tr>"
        for item in latest
    ) or "<tr><td colspan='4'>Измерений пока нет</td></tr>"
    points = "".join(
        f"<tr><td>{run['generated_at']}</td><td>{', '.join(sorted({item['status'] for item in run['results']}))}</td></tr>"
        for run in reversed(data["history"][-14:])
    )
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Routing · Мониторинг</title>
<style>body{{max-width:1200px;margin:32px auto;padding:0 20px;background:#08111f;color:#e7f0fc;font:15px/1.55 system-ui}}h1{{letter-spacing:2px}}p{{color:#93a9c4}}table{{width:100%;border-collapse:collapse;background:#101c2e;margin:20px 0}}td,th{{padding:11px;border:1px solid #293c56;text-align:left;vertical-align:top}}th{{background:#172740}}a{{color:#70b7ff}}.status{{font-weight:700}}.works_direct{{color:#45d7a5}}.blocked_or_geo{{color:#ffca75}}.down_or_error{{color:#ff8b98}}.unknown{{color:#93a9c4}}.notice{{padding:14px;border-left:3px solid #70b7ff;background:#10233a}}</style></head><body>
<h1>ROUTING · Мониторинг</h1><p>Внешняя проверка небольшой контрольной выборки через Globalping. Результаты не меняют маршруты автоматически и не доказывают наличие блокировки у конкретного провайдера.</p>
<div class="notice">Проверка через ваш VPN не выполняется: для неё нужна отдельная точка выхода. Статусы показывают только внешние HTTP-ответы.</div>
<h2>Последняя выборка</h2><table><thead><tr><th>Домен</th><th>Статус</th><th>HTTP</th><th>Примечание</th></tr></thead><tbody>{rows}</tbody></table>
<h2>История запусков</h2><table><thead><tr><th>Время UTC</th><th>Статусы</th></tr></thead><tbody>{points}</tbody></table>
<p><a href="monitoring.json">Машинный monitoring.json</a> · <a href="index.html">Routing Dashboard</a></p>
</body></html>"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(ROOT / "config/monitoring.json"))
    parser.add_argument("--pages-url", default="https://vanilla-silq-hd.github.io/Routing/monitoring.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--html", required=True)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    previous = load_previous(args.pages_url)
    history = previous.get("history", [])[-29:]
    if not args.offline and os.environ.get("RUN_MONITOR", "true").lower() == "true":
        results = [run_probe(config, target) for target in config["targets"]]
        history.append({"generated_at": utc_now(), "results": results})
    data = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "provider": config["provider"]["name"],
        "vpn_measurement": "not_performed",
        "automatic_route_changes": False,
        "history": history,
    }
    Path(args.output).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    Path(args.html).write_text(html_report(data), encoding="utf-8")
    print(json.dumps({"measurements": len(history), "latest": history[-1]["results"] if history else []}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
