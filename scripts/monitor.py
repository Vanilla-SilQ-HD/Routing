"""Small external availability probe. Never changes routing rules."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import logging
import os
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, cast

try:
    from .logging_utils import configure_logging
except ImportError:
    from logging_utils import configure_logging  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = "Routing-Monitor/1 (public availability checks)"
logger = logging.getLogger(__name__)


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def request_json(url: str, *, payload: dict[str, Any] | None = None, timeout: float = 30) -> Any:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("Monitoring API URL must use HTTPS")
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {
        "User-Agent": USER_AGENT, "Accept": "application/json",
        "Content-Type": "application/json" if data else "application/x-www-form-urlencoded",
    }
    # Optional token raises the Globalping rate limit when provided via secrets.
    token = os.environ.get("GLOBALPING_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    try:
        with urllib.request.build_opener().open(request, timeout=timeout) as response:
            return json.loads(response.read(4 * 1024 * 1024 + 1))
    except urllib.error.HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", errors="replace")
        raise RuntimeError(f"Globalping HTTP {exc.code}: {detail}") from exc


def create_measurement(config: dict[str, Any], target: str) -> Any:
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


def wait_for_measurement(config: dict[str, Any], measurement_id: str) -> Any:
    started = time.monotonic()
    url = config["provider"]["url"] + "/" + measurement_id
    while time.monotonic() - started < config["provider"]["timeout_seconds"]:
        measurement = request_json(url)
        if measurement.get("status") in {"finished", "failed", "aborted"}:
            return measurement
        time.sleep(2)
    raise TimeoutError(f"Globalping measurement timed out: {measurement_id}")


def classify_result(result: dict[str, Any]) -> str:
    nested = result.get("result", {})
    status_code = result.get("statusCode", nested.get("statusCode"))
    status = result.get("status", nested.get("status", "unknown"))
    headers = result.get("headers", nested.get("headers", {}))
    location = headers.get("location", headers.get("Location", ""))
    raw_output = str(nested.get("rawOutput", result.get("rawOutput", ""))).lower()
    if "unavailable-in-region" in str(location).lower() or (
            "location:" in raw_output and "unavailable-in-region" in raw_output):
        return "blocked_or_geo"
    if isinstance(status_code, int) and 200 <= status_code < 400:
        return "works_direct"
    if status_code in {401, 403, 451}:
        return "blocked_or_geo"
    if status_code == 429 or status in {"failed", "aborted"}:
        return "unknown"
    return "down_or_error"


def load_previous(url: str) -> dict[str, Any]:
    """Load prior monitoring history.

    A 404 simply means the first run (empty history is fine). Any other failure
    (network error, 5xx, invalid JSON) must not silently wipe the stored history:
    we mark it as unrestored so the caller can avoid overwriting good data.
    """
    try:
        return cast(dict[str, Any], request_json(url))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"history": [], "history_restored": True}
        logger.warning("Could not load previous monitoring history (HTTP %s); keeping it unrestored", exc.code)
        return {"history": [], "history_restored": False}
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
        logger.warning("Could not load previous monitoring history (%s); keeping it unrestored", exc)
        return {"history": [], "history_restored": False}


def load_compact_domains(url: str) -> list[str]:
    """Load the published Compact domain list for sample rotation. Best-effort:
    any failure simply disables rotation for this run."""
    try:
        if urllib.parse.urlsplit(url).scheme != "https":
            raise ValueError("Compact source URL must use HTTPS")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.build_opener().open(request, timeout=30) as response:
            text = response.read(64 * 1024 * 1024).decode("utf-8", errors="replace")
    except (OSError, ValueError, urllib.error.URLError) as exc:
        logger.warning("Could not load Compact domains for rotation: %s", exc)
        return []
    domains = []
    for line in text.splitlines():
        line = line.strip()
        for prefix in ("full:", "domain:"):
            if line.startswith(prefix):
                domains.append(line[len(prefix):])
                break
    return domains


def select_rotation_targets(domains: list[str], sample_size: int, seed: str) -> list[str]:
    """Deterministically pick a daily-rotating sample so different runs probe
    different Compact domains without any randomness in the published artifact."""
    if not domains:
        return []
    ordered = sorted(domains)
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    rng = random.Random(int.from_bytes(digest, "big"))
    return sorted(rng.sample(ordered, min(sample_size, len(ordered))))


def update_stale_candidates(previous: dict[str, Any], results: list[dict[str, Any]], threshold: int) -> list[dict[str, Any]]:
    """Track domains that answer works_direct from RU probes for several runs in a
    row. These are only *candidates* for review: routes are never changed here."""
    streaks: dict[str, int] = dict(previous.get("stale_streaks", {}))
    current = {item["target"] for item in results}
    for target in list(streaks):
        if target not in current:
            del streaks[target]
    for item in results:
        target = item["target"]
        if item.get("status") == "works_direct":
            streaks[target] = streaks.get(target, 0) + 1
        else:
            streaks.pop(target, None)
    candidates = [{"domain": target, "consecutive_works_direct": count}
                  for target, count in sorted(streaks.items()) if count >= threshold]
    previous["stale_streaks"] = streaks
    return candidates


def summarize_results(target: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    observations = []
    for result in results:
        nested = result.get("result", {})
        probe = result.get("probe", {})
        observations.append({
            "status": classify_result(result),
            "http_status": result.get("statusCode", nested.get("statusCode")),
            "error": result.get("error", nested.get("error")),
            "raw_output": str(nested.get("rawOutput", result.get("rawOutput", "")))[:500],
            "asn": probe.get("asn"),
            "network": probe.get("network"),
        })
    statuses = [item["status"] for item in observations]
    errors = [str(item["error"])[:300] for item in observations if item["error"]]
    if len(set(statuses)) > 1:
        errors.insert(0, "inconsistent probe results")
    return {
        "target": target,
        "status": statuses[0] if len(set(statuses)) == 1 else "unknown",
        "http_status": next((item["http_status"] for item in observations if item["http_status"] is not None), None),
        "error": "; ".join(dict.fromkeys(errors)) or None,
        "raw_output": observations[0]["raw_output"],
        "probe_statuses": statuses,
        "observations": observations,
        "networks": sorted({str(item["network"]) for item in observations if item.get("network")}),
        "asns": sorted({item["asn"] for item in observations if item.get("asn") is not None}),
    }


def run_probe(config: dict[str, Any], target: str) -> dict[str, Any]:
    try:
        created = create_measurement(config, target)
        measurement = wait_for_measurement(config, created["id"])
        results = measurement.get("results", [])
        if not results:
            return {"target": target, "status": "unknown", "http_status": None, "error": "empty result",
                    "probe_statuses": [], "observations": []}
        return summarize_results(target, results)
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError, urllib.error.URLError) as exc:
        return {"target": target, "status": "unknown", "http_status": None, "error": str(exc)[:300],
                "probe_statuses": [], "observations": []}


def html_report(data: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value), quote=True)

    latest = data["history"][-1]["results"] if data["history"] else []
    rows = "".join(
        f"<tr><td>{esc(item['target'])}</td><td><span class='status {esc(item['status'])}'>{esc(item['status'])}</span></td>"
        f"<td>{esc(item.get('http_status') or '—')}</td>"
        f"<td>{esc(', '.join(item.get('probe_statuses', [])) or '—')}</td>"
        f"<td>{esc(', '.join(item.get('networks', [])) or '—')}</td>"
        f"<td>{esc(item.get('error') or '—')}</td></tr>"
        for item in latest
    ) or "<tr><td colspan='6'>Измерений пока нет</td></tr>"
    points = "".join(
        f"<tr><td>{esc(run['generated_at'])}</td>"
        f"<td>{esc(', '.join(sorted({item['status'] for item in run['results']})))}</td></tr>"
        for run in reversed(data["history"][-14:])
    )
    stale = data.get("stale_candidates", [])
    stale_rows = "".join(
        f"<tr><td>{esc(item['domain'])}</td><td>{esc(item['consecutive_works_direct'])}</td></tr>"
        for item in stale
    ) or "<tr><td colspan='2'>Кандидатов на пересмотр нет</td></tr>"
    stale_section = (
        "<h2>Кандидаты на пересмотр (устаревшие записи)</h2>"
        "<p>Домены, которые несколько запусков подряд отвечают <b>works_direct</b> из RU. "
        "Это лишь повод для ручной проверки — маршруты автоматически не меняются.</p>"
        f"<table><thead><tr><th>Домен</th><th>Запусков works_direct подряд</th></tr></thead><tbody>{stale_rows}</tbody></table>"
        "<p><a href='stale-candidates.json'>Машинный stale-candidates.json</a></p>"
    ) if stale else ""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Routing · Мониторинг</title>
<style>body{{max-width:1200px;margin:32px auto;padding:0 20px;background:#08111f;color:#e7f0fc;font:15px/1.55 system-ui}}h1{{letter-spacing:2px}}p{{color:#93a9c4}}table{{width:100%;border-collapse:collapse;background:#101c2e;margin:20px 0}}td,th{{padding:11px;border:1px solid #293c56;text-align:left;vertical-align:top}}th{{background:#172740}}a{{color:#70b7ff}}.status{{font-weight:700}}.works_direct{{color:#45d7a5}}.blocked_or_geo{{color:#ffca75}}.down_or_error{{color:#ff8b98}}.unknown{{color:#93a9c4}}.notice{{padding:14px;border-left:3px solid #70b7ff;background:#10233a}}</style></head><body>
<h1>ROUTING · Мониторинг</h1><p>Внешняя проверка небольшой контрольной выборки через Globalping. Результаты не меняют маршруты автоматически и не доказывают наличие блокировки у конкретного провайдера.</p>
<div class="notice">Проверка через ваш VPN не выполняется: для неё нужна отдельная точка выхода. Статусы показывают только внешние HTTP-ответы.</div>
<h2>Последняя выборка</h2><table><thead><tr><th>Домен</th><th>Статус</th><th>HTTP</th><th>Точки</th><th>Сеть</th><th>Примечание</th></tr></thead><tbody>{rows}</tbody></table>
{stale_section}
<h2>История запусков</h2><table><thead><tr><th>Время UTC</th><th>Статусы</th></tr></thead><tbody>{points}</tbody></table>
<p><a href="monitoring.json">Машинный monitoring.json</a> · <a href="index.html">Routing Dashboard</a></p>
</body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--config", default=str(ROOT / "config/monitoring.json"))
    parser.add_argument("--pages-url", default="https://vanilla-silq-hd.github.io/Routing/monitoring.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--html", required=True)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    configure_logging(args.debug)
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    previous = load_previous(args.pages_url)
    history_restored = previous.get("history_restored", True)
    history = previous.get("history", [])[-29:]
    stale_candidates: list[dict[str, Any]] = previous.get("stale_candidates", [])
    if not args.offline and os.environ.get("RUN_MONITOR", "true").lower() == "true":
        # Fixed VPN targets, control Direct targets, plus a daily-rotating Compact sample.
        targets = list(config["targets"])
        direct_targets = list(config.get("direct_targets", []))
        rotation = config.get("rotation")
        rotated: list[str] = []
        if rotation:
            domains = load_compact_domains(rotation["source_url"])
            rotated = select_rotation_targets(domains, rotation["sample_size"], dt.datetime.now(dt.UTC).date().isoformat())
        results = [run_probe(config, target) for target in targets + rotated]
        direct_results = [dict(run_probe(config, target), expected="Direct") for target in direct_targets]
        results.extend(direct_results)
        if rotation:
            stale_candidates = update_stale_candidates(previous, results, rotation["stale_threshold"])
        history.append({"generated_at": utc_now(), "results": results, "rotated_sample": rotated})
    data = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "provider": config["provider"]["name"],
        "vpn_measurement": "not_performed",
        "automatic_route_changes": False,
        "history_restored": history_restored,
        "stale_candidates": stale_candidates,
        "history": history,
    }
    Path(args.output).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    Path(args.html).write_text(html_report(data), encoding="utf-8")
    stale_path = Path(args.output).with_name("stale-candidates.json")
    stale_path.write_text(json.dumps({"schema_version": 1, "generated_at": data["generated_at"],
                                      "note": "Домены, которые несколько запусков подряд отвечают works_direct из RU. "
                                              "Кандидаты на ручной пересмотр; маршруты автоматически не меняются.",
                                      "candidates": stale_candidates}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    logger.info(json.dumps({"measurements": len(history), "latest": history[-1]["results"] if history else []}, ensure_ascii=False))


if __name__ == "__main__":
    main()
