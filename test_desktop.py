from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from notug_protocol.desktop.activity import JsonlNormalizer, normalize_jsonl_line
from notug_protocol.desktop.codex import CodexInstallation, build_codex_command
from notug_protocol.desktop.geometry import (
    RHOMBIC_TRIACONTAHEDRON,
    edge_lengths,
    manifold_edge_counts,
)
from notug_protocol.desktop.packaged_selftest import _JsonlProbe
from notug_protocol.desktop.state import OrbState, appearance_for, highest_priority


class DesktopLogicTests(unittest.TestCase):
    def test_orb_states_have_accessible_non_colour_cues_and_stable_precedence(self) -> None:
        for state in OrbState:
            appearance = appearance_for(state)
            self.assertTrue(appearance.color.startswith("#"))
            self.assertTrue(appearance.glyph)
            self.assertTrue(appearance.label)
        self.assertEqual(
            highest_priority({OrbState.WORKING, OrbState.REVIEW, OrbState.READY}),
            OrbState.REVIEW,
        )
        self.assertEqual(highest_priority({OrbState.ERROR, OrbState.REVIEW}), OrbState.ERROR)

    def test_jsonl_normalizer_handles_chunks_and_malformed_output_without_raw_storage(self) -> None:
        normalizer = JsonlNormalizer()
        self.assertEqual(normalizer.feed('{"type":"item.started","item":{"name":"shell'), ())
        events = normalizer.feed(' command"}}\n{"type":"turn.completed"}\n')
        event = events[0]
        self.assertEqual(event.raw_type, "item.started")
        self.assertEqual(event.text, "shell command")
        self.assertEqual(events[1].raw_type, "turn.completed")
        malformed = normalize_jsonl_line("not-json")
        self.assertEqual(malformed.kind, "warning")
        self.assertIn("malformed", malformed.text)

    def test_jsonl_human_text_is_sanitized_after_structured_parsing(self) -> None:
        event = normalize_jsonl_line(
            '{"type":"item.completed","item":{"text":"safe\\ntext\u202e"}}'
        )

        self.assertEqual(event.text, r"safe\u000atext\u202e")

    def test_fixed_codex_command_uses_stdin_and_leaves_worktree_binding_to_core(self) -> None:
        installation = CodexInstallation(
            argv=("node.exe", r"C:\tools\@openai\codex\bin\codex.js"),
            display_path=r"C:\tools\@openai\codex\bin\codex.js",
            version="codex-cli 1.0.0",
            source="test",
        )
        command = build_codex_command(installation)
        self.assertEqual(
            command,
            (
                "node.exe",
                r"C:\tools\@openai\codex\bin\codex.js",
                "--ask-for-approval",
                "never",
                "exec",
                "--ephemeral",
                "--sandbox",
                "workspace-write",
                "--json",
                "--color",
                "never",
                "-",
            ),
        )
        self.assertNotIn("-C", command)
        self.assertNotIn("prompt", repr(command).casefold())

    def test_packaged_probe_requires_one_relative_command_and_exact_cwd_output(self) -> None:
        with TemporaryDirectory(prefix="leucoform-packaged-probe-") as temporary:
            worktree = Path(temporary).resolve()
            probe = _JsonlProbe(worktree)
            event = {
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "command": "powershell.exe -Command Get-Location",
                    "aggregated_output": f"{worktree}\r\n",
                    "exit_code": 0,
                },
            }
            probe.feed(json.dumps(event) + "\n")
            probe.finish()

        self.assertFalse(probe.malformed)
        self.assertEqual(probe.command_count, 1)
        self.assertTrue(probe.cwd_verified)
        self.assertTrue(probe.relative_command_verified)

    def test_packaged_probe_rejects_absolute_workspace_command(self) -> None:
        with TemporaryDirectory(prefix="leucoform-packaged-probe-") as temporary:
            worktree = Path(temporary).resolve()
            probe = _JsonlProbe(worktree)
            event = {
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "command": f"powershell.exe -Command Set-Location '{worktree}'",
                    "aggregated_output": f"{worktree}\r\n",
                    "exit_code": 0,
                },
            }
            probe.feed(json.dumps(event) + "\n")

        self.assertTrue(probe.cwd_verified)
        self.assertFalse(probe.relative_command_verified)

    def test_companion_geometry_is_a_closed_rhombic_triacontahedron(self) -> None:
        solid = RHOMBIC_TRIACONTAHEDRON
        self.assertEqual(len(solid.vertices), 32)
        self.assertEqual(len(solid.faces), 30)
        self.assertTrue(all(len(face) == 4 for face in solid.faces))
        edge_counts = manifold_edge_counts(solid)
        self.assertEqual(len(edge_counts), 60)
        self.assertEqual(set(edge_counts.values()), {2})
        lengths = edge_lengths(solid)
        self.assertAlmostEqual(min(lengths), max(lengths), places=12)


if __name__ == "__main__":
    unittest.main()
