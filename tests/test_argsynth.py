import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentlure.mcp import synthesize_arguments, synthesize_value


class ArgSynthTests(unittest.TestCase):
    def test_scalar_types(self):
        self.assertEqual(synthesize_value({"type": "string"}), "hello")
        self.assertEqual(synthesize_value({"type": "integer"}), 1)
        self.assertEqual(synthesize_value({"type": "number"}), 1)
        self.assertEqual(synthesize_value({"type": "boolean"}), True)
        self.assertEqual(synthesize_value({"type": "array"}), [])

    def test_enum_first_value(self):
        self.assertEqual(synthesize_value({"enum": ["a", "b"]}), "a")

    def test_object_from_properties(self):
        schema = {"type": "object",
                  "properties": {"name": {"type": "string"},
                                 "count": {"type": "integer"}}}
        self.assertEqual(synthesize_value(schema), {"name": "hello", "count": 1})

    def test_arguments_cover_all_properties(self):
        schema = {"type": "object",
                  "properties": {"to": {"type": "string"},
                                 "subject": {"type": "string"},
                                 "body": {"type": "string"}},
                  "required": ["to", "subject", "body"]}
        args = synthesize_arguments(schema)
        self.assertEqual(set(args), {"to", "subject", "body"})
        self.assertTrue(all(v == "hello" for v in args.values()))

    def test_arguments_empty_schema(self):
        self.assertEqual(synthesize_arguments(None), {})
        self.assertEqual(synthesize_arguments({}), {})
        self.assertEqual(synthesize_arguments({"type": "object"}), {})


if __name__ == "__main__":
    unittest.main()
