"""Encrypted storage. This part is optional in the current design, since
the tool is really about generation, but I am keeping it because it works
and because building it taught me the full crypto chain: password to
scrypt to key to Fernet. If I ever want the saved passwords encrypted at
rest, this is already the answer.
"""

import base64
import json
import secrets
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def new_entry(label, username, password):
    # An entry is a dict: indexed by name, not position. The vault as a
    # whole is a dict of these dicts, so lookups chain together like
    # vault["github"]["password"].
    return {"label": label, "username": username, "password": password}


def _derive_key(master_password, salt):
    """The leading underscore is the Python convention for an internal
    helper that is not part of the public menu.

    The key is stored nowhere. It gets recomputed from the master password
    every time we need it. scrypt is deliberately slow and memory hungry.
    For one unlock you will never notice. For an attacker trying a billion
    guesses it is a wall. A plain hash would derive keys about a million
    times faster, which is a pure gift to the attacker.
    """
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    raw = kdf.derive(master_password.encode())        # str to bytes border crossing
    return base64.urlsafe_b64encode(raw)              # Fernet wants base64 keys


def save_vault(entries, master_password, path):
    # Fresh random salt on every save. The salt is a uniquifier, not a
    # secret, which is why it can sit in the file in the clear.
    salt = secrets.token_bytes(16)
    key = _derive_key(master_password, salt)
    token = Fernet(key).encrypt(json.dumps(entries).encode())
    envelope = {
        "salt": base64.b64encode(salt).decode(),   # JSON cannot hold raw bytes
        "data": token.decode(),
    }
    Path(path).write_text(json.dumps(envelope, indent=2))


def load_vault(master_password, path):
    """This is save_vault run backwards. Every encode has a matching
    decode, b64encode has b64decode, and dumps has loads.

    A wrong password raises InvalidToken instead of returning garbage.
    Fernet verifies an HMAC signature before it even attempts decryption,
    which is what authenticated encryption means. The round trip is also
    the determinism proof: load re-derives the key from scratch, and that
    only works because the same password plus the same salt always
    produces the same key.
    """
    envelope = json.loads(Path(path).read_text())
    salt = base64.b64decode(envelope["salt"])
    key = _derive_key(master_password, salt)
    plaintext = Fernet(key).decrypt(envelope["data"].encode())
    return json.loads(plaintext.decode())