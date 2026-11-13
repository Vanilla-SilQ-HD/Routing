"""Download one pinned official compiler; never install a service or run a router."""
import hashlib
import io
import json
import logging
import os
import platform
import tarfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

try:
    from .logging_utils import configure_logging
except ImportError:
    from logging_utils import configure_logging  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging()
    lock = json.loads((ROOT / "config/tools-lock.json").read_text(encoding="utf-8"))
    system = platform.system().lower()
    if platform.machine().lower() not in {"amd64", "x86_64"}:
        raise SystemExit("Only the audited amd64 compiler archives are configured.")
    asset = lock["assets"][f"{system}-amd64"]
    if urllib.parse.urlsplit(asset["url"]).scheme != "https":
        raise SystemExit("Compiler URL must use HTTPS")
    request = urllib.request.Request(asset["url"], headers={"User-Agent": "selective-vpn-rules/1"})
    with urllib.request.build_opener().open(request, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise SystemExit("Refusing non-HTTPS archive redirect")
        data = response.read(128 * 1024 * 1024 + 1)
    if len(data) > 128 * 1024 * 1024:
        raise SystemExit("Compiler archive exceeds the size limit")
    if hashlib.sha256(data).hexdigest() != asset["sha256"]:
        raise SystemExit("Compiler archive SHA-256 mismatch")
    if system == "windows":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            executable = archive.read(asset["member"])
        output = ROOT / ".tools/sing-box.exe"
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = archive.getmember(asset["member"])
            if not member.isfile():
                raise SystemExit("Compiler member is not a regular file")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise SystemExit("Compiler member cannot be read")
            executable = extracted.read()
        output = ROOT / ".tools/sing-box"
    output.parent.mkdir(exist_ok=True)
    temporary = output.with_suffix(".tmp")
    temporary.write_bytes(executable)
    os.replace(temporary, output)
    if system != "windows":
        output.chmod(0o755)
    logger.info("Verified sing-box %s: %s", lock["sing_box_version"], output)


if __name__ == "__main__":
    main()
