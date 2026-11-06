"""Download one pinned official compiler; never install a service or run a router."""
import hashlib
import io
import json
import os
import platform
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    lock = json.loads((ROOT / "config/tools-lock.json").read_text(encoding="utf-8"))
    system = platform.system().lower()
    if platform.machine().lower() not in {"amd64", "x86_64"}:
        raise SystemExit("Only the audited amd64 compiler archives are configured.")
    asset = lock["assets"][f"{system}-amd64"]
    request = urllib.request.Request(asset["url"], headers={"User-Agent": "selective-vpn-rules/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise SystemExit("Refusing non-HTTPS archive redirect")
        data = response.read(128 * 1024 * 1024 + 1)
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
            executable = archive.extractfile(member).read()
        output = ROOT / ".tools/sing-box"
    output.parent.mkdir(exist_ok=True)
    temporary = output.with_suffix(".tmp")
    temporary.write_bytes(executable)
    os.replace(temporary, output)
    if system != "windows":
        output.chmod(0o755)
    print(f"Verified sing-box {lock['sing_box_version']}: {output}")


if __name__ == "__main__":
    main()
