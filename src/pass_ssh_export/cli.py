"""Export public keys and a shared ssh config from Proton Pass.

Private keys never leave Proton Pass: only the ``public_key`` field of each SSH key
item is fetched, so ``IdentityFile ~/.ssh/<name>.pub`` can select a key while the
Proton Pass SSH agent does the signing.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from collections.abc import Iterable, Sequence
from pathlib import Path

from . import __version__

KEY_TYPE_RE = re.compile(r"^(ssh-|ecdsa-|sk-)[A-Za-z0-9@.-]+$")
INCLUDE_RE = re.compile(r"^[ \t]*Include[ \t=].*config\.d/", re.IGNORECASE | re.MULTILINE)
IS_WINDOWS = os.name == "nt"


class Error(Exception):
    """A fatal, user-presentable error."""


class NotInstalled(Error):
    """pass-cli is missing."""


def run_pass(args: Sequence[str]) -> str:
    exe = shutil.which("pass-cli")
    if exe is None:
        raise NotInstalled("pass-cli not found in PATH (install: https://proton.me/pass/download)")
    try:
        proc = subprocess.run(
            [exe, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except OSError as e:
        raise Error(f"cannot run pass-cli: {e}") from e
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
        raise Error(f"pass-cli {' '.join(args[:2])} failed: {detail}")
    return proc.stdout


def pass_json(args: Sequence[str]):
    out = run_pass([*args, "--output", "json"])
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise Error(f"pass-cli returned invalid JSON for {' '.join(args[:2])}: {e}") from e


def slugify(title: str) -> str:
    """'SSH: ASUS-A15' -> 'ssh-asus-a15'; always a safe single path component."""
    text = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-z0-9._-]+", "-", text.lower()).strip("-.")
    return text or "key"


def unique_name(base: str, used: set) -> str:
    name, i = base, 2
    while name in used:
        name, i = f"{base}-{i}", i + 1
    used.add(name)
    return name


def parse_public_key(raw: str, title: str) -> str | None:
    """Return 'type data comment' (comment = item title) or None if not a public key."""
    parts = raw.replace("\r", "").strip().split()
    if len(parts) < 2 or not KEY_TYPE_RE.match(parts[0]):
        return None
    comment = " ".join(title.split())
    return f"{parts[0]} {parts[1]} {comment}".rstrip()


def key_identity(line: str) -> list[str]:
    return line.split()[:2]


def write_file(path: Path, content: str, mode: int) -> None:
    """Atomic write (temp file + rename) with LF endings and the given mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        if not IS_WINDOWS:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def ensure_dir(path: Path, dry_run: bool) -> None:
    if dry_run:
        return
    path.mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        os.chmod(path, 0o700)


def iter_items(share_ids: Iterable[str], item_type: str) -> Iterable[dict]:
    for share_id in share_ids:
        data = pass_json(
            [
                "item",
                "list",
                f"--share-id={share_id}",
                "--filter-type",
                item_type,
                "--filter-state",
                "active",
            ]
        )
        for item in data.get("items", []):
            item.setdefault("share_id", share_id)
            yield item


def export_keys(out_dir: Path, share_ids: list[str], force: bool, dry_run: bool) -> int:
    """Write one .pub per SSH key item. Returns the number of failures."""
    written = unchanged = skipped = failed = 0
    used: set = set()
    items = sorted(iter_items(share_ids, "ssh-key"), key=lambda i: (i["title"], i["id"]))
    for item in items:
        title = item["title"]
        name = unique_name(slugify(title), used)
        file = out_dir / f"{name}.pub"
        try:
            # IDs go as --opt=value because they can start with "-".
            raw = run_pass(
                [
                    "item",
                    "view",
                    f"--share-id={item['share_id']}",
                    f"--item-id={item['id']}",
                    "--field",
                    "public_key",
                ]
            )
        except Error as e:
            print(f"error {title}: {e}", file=sys.stderr)
            failed += 1
            continue
        content = parse_public_key(raw, title)
        if content is None:
            print(f"skip  {title} (no public key)", file=sys.stderr)
            skipped += 1
            continue
        existing = read_text(file)
        if existing is not None and key_identity(existing) == key_identity(content):
            print(f"ok    {file}")
            unchanged += 1
            continue
        if existing is not None and not force:
            print(f"skip  {file} exists with a different key (use --force to overwrite)",
                  file=sys.stderr)
            skipped += 1
            continue
        if dry_run:
            print(f"would write {file}")
        else:
            write_file(file, content + "\n", 0o644)
            print(f"wrote {file}")
        written += 1
    verb = "would be written" if dry_run else "written"
    print(f"keys: {written} {verb}, {unchanged} unchanged, {skipped} skipped, {failed} failed")
    return failed


def fetch_config_note(share_ids: list[str], title: str) -> str | None:
    matches = [i for i in iter_items(share_ids, "note") if i["title"] == title]
    if not matches:
        return None
    if len(matches) > 1:
        print(f'config: several notes titled "{title}", using the first', file=sys.stderr)
    item = matches[0]
    data = pass_json(
        ["item", "view", f"--share-id={item['share_id']}", f"--item-id={item['id']}"]
    )
    note = (data.get("item", {}).get("content", {}) or {}).get("note") or ""
    return note.replace("\r", "")


def include_line(out_dir: Path) -> str:
    """Include directive for config.d/*.conf; '~' when inside HOME, forward slashes always."""
    glob = (out_dir / "config.d" / "*.conf").as_posix()
    home = Path.home().as_posix()
    if glob == home or glob.startswith(home + "/"):
        glob = "~" + glob[len(home):]
    if " " in glob:
        glob = f'"{glob}"'
    return f"Include {glob}"


def sync_config(out_dir: Path, share_ids: list[str], title: str, dry_run: bool) -> None:
    note = fetch_config_note(share_ids, title)
    if note is None:
        print(f'config: no note titled "{title}" in Proton Pass, skipping')
        return
    shared = out_dir / "config.d" / "protonpass.conf"
    content = (
        f'# Managed by pass-ssh-export from the Proton Pass note "{title}".\n'
        "# Edit the note, not this file: it is overwritten on every run.\n\n"
        f"{note.rstrip()}\n"
    )
    if read_text(shared) == content:
        print(f"ok    {shared}")
    elif dry_run:
        print(f"would write {shared}")
    else:
        ensure_dir(shared.parent, dry_run)
        write_file(shared, content, 0o600)
        print(f"wrote {shared}")

    # ssh keeps the first value per option, so the Include goes last: local settings win.
    # "Match all" closes any preceding Host block so the Include is unconditional.
    local = out_dir / "config"
    current = read_text(local) or ""
    if INCLUDE_RE.search(current):
        return
    if dry_run:
        print(f"would add Include to {local}")
        return
    sep = "" if not current or current.endswith("\n") else "\n"
    block = (
        "\n# Shared config pulled from Proton Pass by pass-ssh-export.\n"
        "# Keep this at the end: settings above it take precedence.\n"
        f"Match all\n{include_line(out_dir)}\n"
    )
    write_file(local, current + sep + block, 0o600)
    print(f"added Include to {local}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pass-ssh-export",
        description="Export public keys of Proton Pass SSH key items to <dir>/<name>.pub and "
        "optionally pull a shared ssh config from a Proton Pass note.",
    )
    p.add_argument("-d", "--dir", type=Path, default=Path.home() / ".ssh",
                   help="output directory (default: ~/.ssh)")
    p.add_argument("-c", "--config-title", default="ssh-config",
                   help="title of the note holding the shared config (default: ssh-config)")
    p.add_argument("-C", "--no-config", action="store_true", help="don't pull the config note")
    p.add_argument("-K", "--no-keys", action="store_true", help="don't export the public keys")
    p.add_argument("-f", "--force", action="store_true",
                   help="overwrite existing .pub files whose key differs")
    p.add_argument("-n", "--dry-run", action="store_true", help="show what would be written")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_keys and args.no_config:
        parser.error("--no-keys and --no-config leave nothing to do")
    out_dir: Path = args.dir.expanduser()
    try:
        try:
            run_pass(["info"])
        except NotInstalled:
            raise
        except Error as e:
            raise Error("not logged in to Proton Pass, run: pass-cli login") from e
        share_ids = [v["share_id"] for v in pass_json(["vault", "list"]).get("vaults", [])]
        ensure_dir(out_dir, args.dry_run)
        failed = 0
        if not args.no_keys:
            failed = export_keys(out_dir, share_ids, args.force, args.dry_run)
        if not args.no_config:
            sync_config(out_dir, share_ids, args.config_title, args.dry_run)
        return 1 if failed else 0
    except Error as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
