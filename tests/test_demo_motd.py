"""MOTD must print as text, never execute, and fail visibly if misconfigured."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('demo_shell', ROOT / 'tools/virp-shell.py')
shell = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shell)


class DemoMotd(unittest.TestCase):
    def invoke(self, text=None, missing=False):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'WELCOME.txt'
            if not missing:
                path.write_text(text or '', encoding='utf-8')
            intro = []
            err = io.StringIO()
            with patch.dict(os.environ, {'VIRP_SHELL_MOTD': str(path)}), \
                 patch.object(shell.os, 'geteuid', return_value=988), \
                 patch.object(shell.VirpShell, 'cmdloop', lambda s: intro.append(s.intro)), \
                 contextlib.redirect_stderr(err):
                rc = shell.main([])
            return rc, intro, err.getvalue()

    def test_welcome_is_literal_text(self):
        text = (ROOT / 'docs/demo/WELCOME.txt').read_text() + '\n$(touch never)'
        rc, intro, _ = self.invoke(text)
        self.assertEqual(rc, 0)
        self.assertIn(text.rstrip(), intro[0])

    def test_missing_file_refuses_instead_of_silently_omitting_instructions(self):
        rc, intro, err = self.invoke(missing=True)
        self.assertEqual(rc, 2)
        self.assertEqual(intro, [])
        self.assertIn('cannot load VIRP_SHELL_MOTD', err)

    def test_terminal_escape_and_oversize_refused(self):
        for text in ['\x1b[2Jhidden', 'x' * 16385]:
            with self.subTest(text=text[:20]):
                rc, intro, _ = self.invoke(text)
                self.assertEqual(rc, 2)
                self.assertEqual(intro, [])


if __name__ == '__main__':
    unittest.main()
