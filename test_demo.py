from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from notug_protocol.demo import run_demo


class DemoIntegrationTests(unittest.TestCase):
    def test_demo_neutralizes_global_hooks_and_init_templates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="notug-demo-hostile-config-") as raw:
            root = Path(raw)
            home = root / "home"
            template_hooks = root / "template" / "hooks"
            global_hooks = root / "global-hooks"
            home.mkdir()
            template_hooks.mkdir(parents=True)
            global_hooks.mkdir()
            marker = root / "hook-ran.txt"
            hook = f'#!/bin/sh\necho ran > "{marker.as_posix()}"\nexit 97\n'
            for path in (template_hooks / "pre-commit", global_hooks / "pre-commit"):
                path.write_text(hook, encoding="utf-8", newline="\n")
                path.chmod(0o755)
            (home / ".gitconfig").write_text(
                "[init]\n"
                f"\ttemplateDir = {template_hooks.parent.as_posix()}\n"
                "[core]\n"
                f"\thooksPath = {global_hooks.as_posix()}\n",
                encoding="utf-8",
                newline="\n",
            )

            with mock.patch.dict(
                os.environ,
                {
                    "HOME": str(home),
                    "USERPROFILE": str(home),
                    "XDG_CONFIG_HOME": str(home / "xdg"),
                    "GIT_TEMPLATE_DIR": str(template_hooks.parent),
                },
            ):
                result = run_demo(io.StringIO())

            self.assertTrue(result["ok"])
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
