import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import gen_docs


class RenderTests(unittest.TestCase):
    def test_block_covers_every_published_artifact(self):
        block = gen_docs.render_block()
        self.assertTrue(block.startswith(gen_docs.BEGIN))
        self.assertTrue(block.endswith(gen_docs.END))
        for _, artifact in gen_docs.ARTIFACTS:
            self.assertIn(f"### `{artifact}`", block)

    def test_fields_are_rendered_with_types(self):
        block = gen_docs.render_block()
        self.assertIn("| `schema_version` |", block)
        self.assertIn("| `output.files.<key>` |", block)

    def test_type_label_variants(self):
        self.assertEqual(gen_docs.type_label({"const": "x"}), 'const `"x"`')
        self.assertEqual(gen_docs.type_label({"enum": ["a", "b"]}), "enum `a` / `b`")
        self.assertEqual(gen_docs.type_label({"type": ["string", "null"]}), "string / null")
        self.assertEqual(gen_docs.type_label({"type": "array", "items": {"type": "string"}}), "array<string>")
        self.assertEqual(
            gen_docs.type_label({"type": "object", "additionalProperties": {"type": "integer"}}),
            "object<string, integer>",
        )
        self.assertEqual(gen_docs.type_label({}), "any")

    def test_cell_escapes_pipes(self):
        self.assertEqual(gen_docs.cell("a | b"), "a \\| b")


class ReplaceBlockTests(unittest.TestCase):
    def test_replaces_only_generated_region(self):
        document = f"intro\n{gen_docs.BEGIN}\nstale\n{gen_docs.END}\noutro\n"
        updated = gen_docs.replace_block(document, "FRESH")
        self.assertEqual(updated, "intro\nFRESH\noutro\n")

    def test_missing_markers_raise(self):
        with self.assertRaises(ValueError):
            gen_docs.replace_block("no markers here", "FRESH")


class CheckModeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        schemas = root / "schemas"
        schemas.mkdir()
        (schemas / "manifest_schema.json").write_text(
            '{"description": "d", "properties": {"schema_version": {"type": "integer", "description": "v"}}}',
            encoding="utf-8",
        )
        self.document = root / "DATA_FORMATS.md"
        self.patches = [
            patch.object(gen_docs, "SCHEMA_DIR", schemas),
            patch.object(gen_docs, "DOC_PATH", self.document),
            patch.object(gen_docs, "ARTIFACTS", (("manifest_schema.json", "manifest.json"),)),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_check_passes_on_fresh_document(self):
        self.document.write_text(gen_docs.render_block() + "\n", encoding="utf-8")
        with patch.object(sys, "argv", ["gen_docs.py", "--check"]):
            gen_docs.main()

    def test_check_fails_on_stale_document(self):
        self.document.write_text(f"{gen_docs.BEGIN}\nstale\n{gen_docs.END}\n", encoding="utf-8")
        with patch.object(sys, "argv", ["gen_docs.py", "--check"]), self.assertRaises(SystemExit):
            gen_docs.main()

    def test_write_updates_document(self):
        self.document.write_text(f"{gen_docs.BEGIN}\nstale\n{gen_docs.END}\n", encoding="utf-8")
        with patch.object(sys, "argv", ["gen_docs.py"]):
            gen_docs.main()
        self.assertIn("| `schema_version` | integer | v |", self.document.read_text(encoding="utf-8"))


class RepositoryDocsTests(unittest.TestCase):
    def test_committed_reference_is_up_to_date(self):
        document = gen_docs.DOC_PATH.read_text(encoding="utf-8")
        self.assertEqual(gen_docs.replace_block(document, gen_docs.render_block()), document)


if __name__ == "__main__":
    unittest.main()
