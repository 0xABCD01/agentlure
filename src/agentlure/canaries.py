"""Canary credentials: minting and planting.

Every scan run mints a fresh set of canary values (recognizable prefix +
random suffix) and plants them as files inside a synthetic HOME directory.
The synthetic HOME is later mounted over the real home path inside the
sandbox, so a target reading "~/.ssh/id_rsa" reads a canary, never a real
key. The scanner keeps a manifest mapping values to canary types so that
a value found in an egress payload attributes to exactly one run and one
credential type.
"""

from __future__ import annotations

import base64
import os
import secrets
import string

_ALNUM = string.ascii_letters + string.digits
_AWS_ALNUM = string.ascii_uppercase + string.digits


def _rand(alphabet, n):
    return "".join(secrets.choice(alphabet) for _ in range(n))


def mask(value):
    """Masked form safe for reports: type prefix stays visible, secret does not."""
    if len(value) <= 10:
        return "***"
    return value[:6] + "…" + value[-2:]


class Canary:
    def __init__(self, ctype, values, files):
        self.type = ctype
        self.values = values          # searchable secret strings
        self.files = files            # {relative_path_under_home: file_content}

    def manifest_entry(self, home_display, home_backing):
        return {
            "type": self.type,
            "values_masked": [mask(v) for v in self.values],
            "files": [
                {
                    "rel": rel,
                    "sandbox_path": os.path.join(home_display, rel),
                    "backing_path": os.path.join(home_backing, rel),
                }
                for rel in self.files
            ],
        }


def mint_canaries():
    """Mint the five v0.1 canary types, unique to this call."""
    # AWS key pair
    aws_id = "AKIA" + _rand(_AWS_ALNUM, 16)
    aws_secret = _rand(_ALNUM + "_-", 40)

    # GitHub token
    gh_token = "ghp_" + _rand(_ALNUM, 36)

    # npm token
    npm_token = "npm_" + _rand(_ALNUM, 36)

    # .env bundle: three distinct secrets in one file
    db_password = _rand(_ALNUM, 24)
    stripe_key = "sk_live_" + _rand(_ALNUM, 24)
    sendgrid_key = "SG." + _rand(_ALNUM + "_-", 22)

    # SSH private key: a fake PEM whose base64 body and comment token are
    # both unique to this run.
    ssh_token = "agentlure-canary-" + _rand(string.ascii_lowercase + string.digits, 24)
    blob = base64.b64encode(b"openssh-key-v1\x00" + secrets.token_bytes(96)).decode()
    blob_lines = [blob[i:i + 70] for i in range(0, len(blob), 70)]
    ssh_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(blob_lines)
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
        + "# " + ssh_token + "\n"
    )
    ssh_pub = "ssh-ed25519 " + base64.b64encode(secrets.token_bytes(32)).decode() + " " + ssh_token + "@canary\n"

    env_content = (
        "# application environment\n"
        "DATABASE_URL=postgres://app:" + db_password + "@db.internal:5432/app\n"
        "STRIPE_SECRET_KEY=" + stripe_key + "\n"
        "SENDGRID_API_KEY=" + sendgrid_key + "\n"
        "APP_ENV=production\n"
    )

    return [
        Canary(
            "aws",
            [aws_id, aws_secret],
            {
                ".aws/credentials": (
                    "[default]\n"
                    "aws_access_key_id = " + aws_id + "\n"
                    "aws_secret_access_key = " + aws_secret + "\n"
                ),
                ".aws/config": "[default]\nregion = us-east-1\n",
            },
        ),
        Canary(
            "github",
            [gh_token],
            {
                ".config/gh/hosts.yml": (
                    "github.com:\n"
                    "    oauth_token: " + gh_token + "\n"
                    "    user: canary-user\n"
                    "    git_protocol: https\n"
                ),
            },
        ),
        Canary(
            "env",
            [db_password, stripe_key, sendgrid_key],
            {".env": env_content},
        ),
        Canary(
            "ssh",
            [ssh_token, blob_lines[0]],
            {
                ".ssh/id_rsa": ssh_key,
                ".ssh/id_rsa.pub": ssh_pub,
            },
        ),
        Canary(
            "npm",
            [npm_token],
            {".npmrc": "//registry.npmjs.org/:_authToken=" + npm_token + "\n"},
        ),
    ]


def plant_canaries(home_dir, canaries):
    """Write canary files into the synthetic HOME directory."""
    os.makedirs(home_dir, exist_ok=True)
    for canary in canaries:
        for rel, content in canary.files.items():
            path = os.path.join(home_dir, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            if rel.endswith("id_rsa"):
                os.chmod(path, 0o600)


def values_map(canaries):
    """{canary_type: [values]} for payload searching."""
    return {c.type: list(c.values) for c in canaries}
