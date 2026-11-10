"""Create a reviewed-rule candidate from an unrouted-resource issue."""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import urllib.request

from build import normalize_domain, write_json


def sections(body):
    matches = list(re.finditer(r"(?im)^###\s+(.+?)\s*$", body))
    result = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        result[match.group(1).strip().lower()] = body[match.end():end].strip()
    return result


def expected_route(issue):
    fields = sections(issue.get("body", ""))
    expected = fields.get("ожидаемый маршрут", fields.get("expected", "")).strip().lower()
    actual = fields.get("фактический маршрут", fields.get("actual", "")).strip().lower()
    expected = expected or "vpn"
    if expected not in {"vpn", "direct"} or actual and actual not in {"vpn", "direct"}:
        raise ValueError("Expected and actual routes must be VPN or Direct")
    if actual and expected == actual:
        raise ValueError("Expected and actual routes must differ")
    return expected


def candidate_from_issue(issue):
    expected_route(issue)
    fields = sections(issue.get("body", ""))
    lines = fields.get("resource", "").splitlines()
    if not lines or not lines[0].strip():
        raise ValueError("Issue resource is empty")
    resource = lines[0].strip()
    if re.fullmatch(r"[0-9a-fA-F:.]+/[0-9]+", resource):
        network = ipaddress.ip_network(resource, strict=True)
        if not network.is_global or network.prefixlen != network.max_prefixlen:
            raise ValueError("Only public exact /32 or /128 addresses are accepted")
        kind, domain = "ip_cidr", str(network)
    else:
        kind, domain = "domain_suffix", normalize_domain(resource)
    review_after = (dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=30)).isoformat()
    reason = f"Issue #{issue['number']}: {issue.get('title', 'unrouted resource')}. {issue['html_url']}"
    return {"kind": kind, "domain": domain, "reason": reason, "review_after": review_after}


def markdown(candidate, issue):
    target = "direct-exceptions" if expected_route(issue) == "direct" else "manual-vpn"
    return (f"Кандидат для `config/{target}.json`. Проверьте ресурс перед публикацией.\n\n"
            f"```json\n{json.dumps(candidate, ensure_ascii=False, indent=2)}\n```\n\n"
            f"Источник: {issue['html_url']}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", default=os.environ.get("GITHUB_EVENT_PATH"))
    parser.add_argument("--output", default="candidate.json")
    parser.add_argument("--markdown", default="candidate.md")
    parser.add_argument("--comment", action="store_true")
    args = parser.parse_args()
    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    issue = event["issue"]
    candidate = candidate_from_issue(issue)
    write_json(args.output, candidate)
    comment = markdown(candidate, issue)
    Path(args.markdown).write_text(comment, encoding="utf-8")
    if args.comment:
        repository = os.environ["GITHUB_REPOSITORY"]
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/issues/{issue['number']}/comments",
            data=json.dumps({"body": comment}, ensure_ascii=False).encode("utf-8"),
            headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
                     "Accept": "application/vnd.github+json", "User-Agent": "Routing-Issue-Bot"},
            method="POST")
        with urllib.request.urlopen(request, timeout=30):
            pass
    print(json.dumps(candidate, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
