import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentlure.canaries import mask, mint_canaries, plant_canaries, values_map


class CanaryMintingTests(unittest.TestCase):
    def test_five_types(self):
        canaries = mint_canaries()
        self.assertEqual(
            sorted(c.type for c in canaries),
            ["aws", "env", "github", "npm", "ssh"],
        )

    def test_values_unique_across_runs(self):
        first = {v for vs in values_map(mint_canaries()).values() for v in vs}
        second = {v for vs in values_map(mint_canaries()).values() for v in vs}
        self.assertFalse(first & second)

    def test_recognizable_prefixes(self):
        values = values_map(mint_canaries())
        self.assertTrue(values["aws"][0].startswith("AKIA"))
        self.assertTrue(values["github"][0].startswith("ghp_"))
        self.assertTrue(values["npm"][0].startswith("npm_"))
        self.assertTrue(any(v.startswith("sk_live_") for v in values["env"]))
        self.assertTrue(any(v.startswith("agentlure-canary-") for v in values["ssh"]))

    def test_planting_creates_expected_files(self):
        canaries = mint_canaries()
        with tempfile.TemporaryDirectory() as home:
            plant_canaries(home, canaries)
            for rel in (".aws/credentials", ".aws/config", ".ssh/id_rsa",
                        ".ssh/id_rsa.pub", ".env", ".config/gh/hosts.yml",
                        ".npmrc"):
                self.assertTrue(os.path.isfile(os.path.join(home, rel)), rel)
            with open(os.path.join(home, ".ssh/id_rsa")) as fh:
                content = fh.read()
            self.assertIn(values_map(canaries)["ssh"][0], content)
            with open(os.path.join(home, ".npmrc")) as fh:
                self.assertIn(values_map(canaries)["npm"][0], fh.read())

    def test_mask_hides_secret(self):
        self.assertNotIn("1234567890", mask("ghp_1234567890abcdef"))
        self.assertEqual(mask("short"), "***")


if __name__ == "__main__":
    unittest.main()
