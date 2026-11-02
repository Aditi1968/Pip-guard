"""Write realistic-format, invalid credential files into the sandbox image (FR-4.3).

Runs at `docker build` time so no credential-shaped strings ever live in git: GitHub push
protection would flag them, and a public repo must not look like it leaks keys. Values are
random per build; the "fake" marker lives only in sandbox/manifest.json.
"""

import base64
import json
import secrets
import string
import sys
from pathlib import Path

ALNUM = string.ascii_letters + string.digits


def rnd(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def ssh_key() -> str:
    body = base64.b64encode(b"openssh-key-v1\0" + secrets.token_bytes(380)).decode()
    lines = [body[i : i + 70] for i in range(0, len(body), 70)]
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )


def seed(home: Path) -> list[Path]:
    files = {
        ".aws/credentials": (
            "[default]\n"
            f"aws_access_key_id = AKIA{rnd(string.ascii_uppercase + string.digits, 16)}\n"
            f"aws_secret_access_key = {rnd(ALNUM + '/+', 40)}\n"
            "region = us-east-1\n"
        ),
        ".ssh/id_rsa": ssh_key(),
        ".netrc": f"machine api.github.com\n  login deploy-bot\n  password ghp_{rnd(ALNUM, 36)}\n",
        "project/.env": (
            f"DATABASE_URL=postgres://app:{rnd(ALNUM, 24)}@db.internal:5432/app\n"
            f"STRIPE_SECRET_KEY=sk_live_{rnd(ALNUM, 24)}\n"
            "DEBUG=false\n"
        ),
    }
    written = []
    for rel, text in files.items():
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        p.chmod(0o600)
        written.append(p)
    return written


if __name__ == "__main__":
    home = Path(sys.argv[1])
    manifest = json.loads(Path(sys.argv[2]).read_text())
    written = {p.as_posix() for p in seed(home)}
    if written != set(manifest["files"]):
        sys.exit(f"seeded files {sorted(written)} do not match manifest {manifest['files']}")
