import base64
import binascii
import os
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentlure.encodings import search_blob

VALUES = {"github": ["ghp_TESTTOKEN0123456789abcdef"], "aws": ["AKIATEST0123456789"]}


def encodings_found(data, values=VALUES):
    return {(h["canary_type"], h["encoding"]) for h in search_blob(data, values)}


class PayloadSearchTests(unittest.TestCase):
    def test_raw(self):
        hits = encodings_found(b"token is ghp_TESTTOKEN0123456789abcdef ok")
        self.assertIn(("github", "raw"), hits)

    def test_base64_of_value(self):
        blob = base64.b64encode(b"ghp_TESTTOKEN0123456789abcdef")
        self.assertIn(("github", "base64"), encodings_found(b"data=" + blob))

    def test_base64_of_whole_file_containing_value(self):
        document = b"# config\nTOKEN=ghp_TESTTOKEN0123456789abcdef\nOTHER=1\n"
        blob = base64.b64encode(document)
        self.assertIn(("github", "base64"), encodings_found(blob))

    def test_base64_file_inside_urlencoded_query(self):
        document = b"AWS=AKIATEST0123456789\n"
        query = urllib.parse.urlencode(
            {"d": base64.b64encode(document).decode()}).encode()
        self.assertIn(("aws", "base64"), encodings_found(query))

    def test_hex_of_value(self):
        blob = binascii.hexlify(b"AKIATEST0123456789")
        self.assertIn(("aws", "hex"), encodings_found(b"x=" + blob))

    def test_urlencoded_value(self):
        blob = urllib.parse.quote("ghp_TESTTOKEN0123456789abcdef", safe="").encode()
        # '/' '+' '=' style characters get encoded; plain token stays itself
        # so also test with a value that actually changes under quoting:
        values = {"env": ["pa ss+word/with=special"]}
        quoted = urllib.parse.quote("pa ss+word/with=special", safe="").encode()
        hits = {(h["canary_type"], h["encoding"])
                for h in search_blob(b"q=" + quoted, values)}
        self.assertTrue(any(e in ("urlencoded", "raw") for _t, e in hits))
        self.assertIn(("github", "raw"), encodings_found(b"t=" + blob))

    def test_clean_payload_no_hits(self):
        self.assertEqual(encodings_found(b"hello world, nothing here"), set())
        self.assertEqual(encodings_found(b""), set())

    def test_no_duplicate_raw_urlencoded_for_plain_token(self):
        hits = search_blob(b"ghp_TESTTOKEN0123456789abcdef", VALUES)
        github_hits = [h for h in hits if h["canary_type"] == "github"]
        self.assertEqual(len(github_hits), 1)
        self.assertEqual(github_hits[0]["encoding"], "raw")


if __name__ == "__main__":
    unittest.main()
