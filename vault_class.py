import sqlite3
import json
import base64
import difflib
import secrets
import string
import math

from crypto import encrypt, decrypt, generate_salt, derive_key


class Vault:
    VAULT_CHECK = "VAULT_OK"

    def __init__(self, db_name="vault.db"):
        self.db_name = db_name
        self.key = None
        self.salt = None

    # ───────── Vault lifecycle ─────────

    def exists(self):
        with sqlite3.connect(self.db_name) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='vault_meta'"
            )
            return cur.fetchone() is not None

    def unlock_or_create(self, master_password):
        if not self.exists():
            self.salt = generate_salt()
            self.key = derive_key(master_password, self.salt)
            self._init_db()
        else:
            with sqlite3.connect(self.db_name) as conn:
                cur = conn.cursor()
                cur.execute("SELECT salt FROM vault_meta LIMIT 1")
                self.salt = cur.fetchone()[0]

            self.key = derive_key(master_password, self.salt)
            if not self._verify_master():
                raise ValueError("Wrong master password")

    def lock(self):
        self.key = None

    # ───────── Internal helpers ─────────

    def _init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            cur = conn.cursor()

            cur.execute("""
            CREATE TABLE IF NOT EXISTS vault_meta (
                id INTEGER PRIMARY KEY,
                salt BLOB NOT NULL,
                nonce BLOB NOT NULL,
                check_value BLOB NOT NULL
            )
            """)

            cur.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                nonce BLOB NOT NULL,
                password BLOB NOT NULL
            )
            """)

            nonce, check = encrypt(self.key, self.VAULT_CHECK)
            cur.execute(
                "INSERT INTO vault_meta (salt, nonce, check_value) VALUES (?, ?, ?)",
                (self.salt, nonce, check),
            )
            conn.commit()

    def _verify_master(self):
        with sqlite3.connect(self.db_name) as conn:
            cur = conn.cursor()
            cur.execute("SELECT nonce, check_value FROM vault_meta LIMIT 1")
            nonce, check = cur.fetchone()

        try:
            return decrypt(self.key, nonce, check) == self.VAULT_CHECK
        except Exception:
            return False

    # ───────── CRUD operations ─────────

    def add_entry(self, site, username, password):
        nonce, cipher = encrypt(self.key, password)
        with sqlite3.connect(self.db_name) as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO entries (site, username, nonce, password) VALUES (?, ?, ?, ?)",
                (site, username, nonce, cipher),
            )
            conn.commit()

    def get_entries_by_site(self, site):
        with sqlite3.connect(self.db_name) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, username, nonce, password FROM entries WHERE site = ?",
                (site,),
            )
            rows = cur.fetchall()

        result = []
        for entry_id, user, nonce, cipher in rows:
            result.append((entry_id, user, decrypt(self.key, nonce, cipher)))
        return result

    def edit_entry(self, entry_id, new_username=None, new_password=None):
        with sqlite3.connect(self.db_name) as conn:
            cur = conn.cursor()

            if new_password is not None:
                nonce, cipher = encrypt(self.key, new_password)
                cur.execute(
                    """
                    UPDATE entries
                    SET username = COALESCE(?, username),
                        nonce = ?,
                        password = ?
                    WHERE id = ?
                    """,
                    (new_username, nonce, cipher, entry_id),
                )
            else:
                cur.execute(
                    "UPDATE entries SET username = COALESCE(?, username) WHERE id = ?",
                    (new_username, entry_id),
                )

            conn.commit()

    def delete_entry(self, entry_id):
        with sqlite3.connect(self.db_name) as conn:
            conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            conn.commit()

    def list_sites(self):
        with sqlite3.connect(self.db_name) as conn:
            cur = conn.cursor()
            cur.execute("SELECT DISTINCT site FROM entries")
            return [r[0] for r in cur.fetchall()]

    # ───────── Search ─────────

    def search_sites(self, query, limit=5, cutoff=0.3):
        sites = self.list_sites()
        matches = difflib.get_close_matches(query, sites, n=limit, cutoff=cutoff)
        for s in sites:
            if query.lower() in s.lower() and s not in matches:
                matches.append(s)
        return matches[:limit]

    # ───────── Password tools ─────────

    def generate_password(self, length=20):
        alphabet = (
            string.ascii_uppercase +
            string.ascii_lowercase +
            string.digits +
            "!@#$%^&*()-_=+[]{};:,.<>?"
        )
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        return pwd, self.calculate_entropy(len(alphabet), length)

    def calculate_entropy(self, charset_size, length):
        return round(length * math.log2(charset_size), 2)

    # ───────── Export / Import ─────────

    def export(self, filename):
        with sqlite3.connect(self.db_name) as conn:
            cur = conn.cursor()
            cur.execute("SELECT site, username, nonce, password FROM entries")
            rows = cur.fetchall()

        data = [
            {
                "site": s,
                "username": u,
                "nonce": base64.b64encode(n).decode(),
                "password": base64.b64encode(p).decode(),
            }
            for s, u, n, p in rows
        ]

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def import_data(self, filename):
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        with sqlite3.connect(self.db_name) as conn:
            cur = conn.cursor()
            for e in data:
                cur.execute(
                    "INSERT INTO entries (site, username, nonce, password) VALUES (?, ?, ?, ?)",
                    (
                        e["site"],
                        e["username"],
                        base64.b64decode(e["nonce"]),
                        base64.b64decode(e["password"]),
                    ),
                )
            conn.commit()

    # ───────── Master password rotation ─────────

    def change_master_password(self, new_master):
        new_salt = generate_salt()
        new_key = derive_key(new_master, new_salt)

        with sqlite3.connect(self.db_name) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, nonce, password FROM entries")
            rows = cur.fetchall()

            for eid, old_nonce, old_cipher in rows:
                plain = decrypt(self.key, old_nonce, old_cipher)
                n, c = encrypt(new_key, plain)
                cur.execute(
                    "UPDATE entries SET nonce = ?, password = ? WHERE id = ?",
                    (n, c, eid),
                )

            nonce, check = encrypt(new_key, self.VAULT_CHECK)
            cur.execute(
                "UPDATE vault_meta SET salt = ?, nonce = ?, check_value = ? WHERE id = 1",
                (new_salt, nonce, check),
            )
            conn.commit()

        self.salt = new_salt
        self.key = new_key
