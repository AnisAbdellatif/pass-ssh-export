import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pass_ssh_export import cli

PUB_A = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA"
PUB_B = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBB"


def fake_pass(keys, note=None):
    """keys: {item_id: (title, pubkey)}"""

    def run(args):
        args = list(args)
        if args == ["info"]:
            return ""
        if args[:2] == ["vault", "list"]:
            return json.dumps({"vaults": [{"share_id": "S1"}]})
        if args[:2] == ["item", "list"]:
            kind = args[args.index("--filter-type") + 1]
            if kind == "ssh-key":
                items = [{"id": i, "title": t} for i, (t, _) in keys.items()]
            else:
                items = [{"id": "N", "title": "ssh-config"}] if note is not None else []
            return json.dumps({"items": items})
        if args[:2] == ["item", "view"]:
            if "--field" in args:
                item_id = next(a.split("=", 1)[1] for a in args if a.startswith("--item-id="))
                return keys[item_id][1] + "\n"
            return json.dumps({"item": {"content": {"note": note}}})
        raise AssertionError(args)

    return run


class SlugTests(unittest.TestCase):
    def test_slugify(self):
        self.assertEqual(cli.slugify("SSH: ASUS-A15FA507XK"), "ssh-asus-a15fa507xk")
        self.assertEqual(cli.slugify("../../etc/passwd"), "etc-passwd")
        self.assertEqual(cli.slugify("Clé 日本"), "cle")
        self.assertEqual(cli.slugify("日本"), "key")

    def test_unique(self):
        used = set()
        self.assertEqual([cli.unique_name("a", used) for _ in range(3)], ["a", "a-2", "a-3"])

    def test_parse_public_key(self):
        self.assertEqual(cli.parse_public_key(PUB_A + " old-comment\r\n", "My  Key"),
                         PUB_A + " My Key")
        self.assertIsNone(cli.parse_public_key("", "t"))
        self.assertIsNone(cli.parse_public_key("garbage", "t"))
        self.assertIsNone(cli.parse_public_key("notakey AAAA", "t"))


class MainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "ssh dir"
        self.addCleanup(self.tmp.cleanup)

    def run_main(self, keys, note=None, *extra):
        with mock.patch.object(cli, "run_pass", fake_pass(keys, note)):
            return cli.main(["-d", str(self.dir), *extra])

    def test_export_and_idempotent(self):
        keys = {"k1": ("SSH: One", PUB_A), "k2": ("SSH: One", PUB_B)}
        self.assertEqual(self.run_main(keys), 0)
        self.assertEqual((self.dir / "ssh-one.pub").read_text(), PUB_A + " SSH: One\n")
        self.assertEqual((self.dir / "ssh-one-2.pub").read_text(), PUB_B + " SSH: One\n")
        self.assertFalse((self.dir / "config").exists())
        before = (self.dir / "ssh-one.pub").stat().st_mtime_ns
        self.assertEqual(self.run_main(keys), 0)
        self.assertEqual((self.dir / "ssh-one.pub").stat().st_mtime_ns, before)

    def test_different_key_needs_force(self):
        self.run_main({"k1": ("a", PUB_A)})
        self.run_main({"k1": ("a", PUB_B)})
        self.assertIn("AAAAIAAA", (self.dir / "a.pub").read_text())
        self.run_main({"k1": ("a", PUB_B)}, None, "--force")
        self.assertIn("AAAAIBBB", (self.dir / "a.pub").read_text())

    def test_dry_run_writes_nothing(self):
        self.run_main({"k1": ("a", PUB_A)}, "Host x\n  User y\n", "-n")
        self.assertFalse(self.dir.exists())

    def test_config_note_and_include(self):
        self.dir.mkdir()
        (self.dir / "config").write_text("Host local\n  User me")
        self.assertEqual(self.run_main({}, "Host x\r\n  User y\r\n"), 0)
        shared = (self.dir / "config.d" / "protonpass.conf").read_text()
        self.assertTrue(shared.endswith("Host x\n  User y\n"))
        cfg = (self.dir / "config").read_text()
        self.assertTrue(cfg.startswith("Host local\n  User me\n"))
        self.assertIn('Match all\nInclude "', cfg)  # path contains a space -> quoted
        self.run_main({}, "Host x\r\n  User y\r\n")
        self.assertEqual((self.dir / "config").read_text(), cfg)  # Include added once

    def test_no_config_flag(self):
        self.run_main({}, "Host x\n", "-C")
        self.assertFalse((self.dir / "config.d").exists())

    def test_not_logged_in(self):
        def boom(args):
            raise cli.Error("nope")

        with mock.patch.object(cli, "run_pass", boom):
            self.assertEqual(cli.main(["-d", str(self.dir)]), 1)


class IncludeLineTests(unittest.TestCase):
    def test_home_relative(self):
        line = cli.include_line(Path.home() / ".ssh")
        self.assertEqual(line, "Include ~/.ssh/config.d/*.conf")


if __name__ == "__main__":
    unittest.main()
