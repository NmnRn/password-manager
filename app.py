import base64
import hashlib
import hmac
import math
import os
import secrets
import sqlite3
import sys
import threading
import time
from pathlib import Path
from tkinter import messagebox, ttk

import customtkinter as ctk
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
from argon2.low_level import Type
from cryptography.fernet import Fernet, InvalidToken

APP_DIR_NAME = "KeyPass"


def _resolve_data_dir() -> Path:
    # In PyInstaller onefile mode, __file__ points to a temporary extraction directory.
    # Keep database in a stable user-writable location.
    if getattr(sys, "frozen", False):
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / APP_DIR_NAME
        return Path.home() / "AppData" / "Local" / APP_DIR_NAME
    return Path(__file__).resolve().parent


DATA_DIR = _resolve_data_dir()
DB_PATH = DATA_DIR / "database.db"
# Legacy PBKDF2 support for old rows:
PASSWORD_KDF_ITERATIONS = 1_000_000
PASSWORD_ARGON2_TIME_COST = 3
PASSWORD_ARGON2_MEMORY_COST_KIB = 65536
PASSWORD_ARGON2_PARALLELISM = max(1, min(4, os.cpu_count() or 1))
HASH_KEY_KDF_ITERATIONS = 210_000
HASH_KEY_CHECK_VALUE = b"user-key-check:v1"
AUTH_MIN_DELAY_SECONDS = 4.5
AUTH_BURN_CHUNK_ITERATIONS = 140_000
AUTH_MAX_FAILED_ATTEMPTS = 5
AUTH_LOCKOUT_BASE_SECONDS = 30
AUTH_LOCKOUT_MAX_SECONDS = 900
SESSION_TIMEOUT_SECONDS = 900
SESSION_CHECK_INTERVAL_MS = 1000

# UI palette (dark theme)
ACCENT = "#1f6aa5"
ACCENT_HOVER = "#17527f"
BG_APP = "#0f141c"
BG_PANEL = "#172332"
BG_CARD = "#1c2b3b"
BG_SURFACE = "#101a26"
BG_SOFT = "#26384c"
TEXT_PRIMARY = "#ebf3fb"
TEXT_SECONDARY = "#9bb0c5"
TEXT_MUTED = "#7f95aa"
BTN_NEUTRAL = "#2b3f54"
BTN_NEUTRAL_HOVER = "#35516c"


def get_conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _get_table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row["name"]) for row in rows}


def _ensure_column(conn: sqlite3.Connection, table_name: str, column_sql: str) -> None:
    column_name = column_sql.split()[0]
    existing_columns = _get_table_columns(conn, table_name)
    if column_name not in existing_columns:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


def init_db() -> None:
    conn = get_conn()
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                key_salt TEXT,
                key_check TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lock_until REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                website TEXT,
                username TEXT,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )

        _ensure_column(conn, "users", "key_salt TEXT")
        _ensure_column(conn, "users", "key_check TEXT")
        _ensure_column(conn, "users", "failed_attempts INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "users", "lock_until REAL")
        _ensure_column(conn, "passwords", "user_id INTEGER")

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON passwords(user_id)"
        )
        conn.commit()
    finally:
        conn.close()


def user_count() -> int:
    conn = get_conn()
    try:
        row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return int(row["count"])
    finally:
        conn.close()


def _get_password_hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=PASSWORD_ARGON2_TIME_COST,
        memory_cost=PASSWORD_ARGON2_MEMORY_COST_KIB,
        parallelism=max(1, PASSWORD_ARGON2_PARALLELISM),
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password cannot be empty.")
    return _get_password_hasher().hash(password)


def verify_password(stored_password: str, candidate: str) -> bool:
    if stored_password.startswith("$argon2"):
        try:
            return _get_password_hasher().verify(stored_password, candidate)
        except (VerifyMismatchError, VerificationError, InvalidHash):
            return False

    # Backward compatibility for PBKDF2 and legacy plain-text rows.
    if not stored_password.startswith("pbkdf2_sha256$"):
        return hmac.compare_digest(stored_password, candidate)

    try:
        _, iter_text, salt_hex, digest_hex = stored_password.split("$", 3)
        iterations = int(iter_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False

    current = hashlib.pbkdf2_hmac(
        "sha256", candidate.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(current, expected)


def _password_needs_rehash(stored_password: str) -> bool:
    if not stored_password.startswith("$argon2"):
        return False
    try:
        return _get_password_hasher().check_needs_rehash(stored_password)
    except (VerificationError, InvalidHash):
        return False


def _upgrade_password_hash_if_needed(user_id: int, stored_password: str, password: str) -> None:
    if not _password_needs_rehash(stored_password):
        return
    new_hash = hash_password(password)
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (new_hash, user_id),
        )
        conn.commit()
    finally:
        conn.close()


def _derive_user_fernet_key(password: str, hash_key: str, salt_bytes: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")
    if not hash_key:
        raise ValueError("Hash key cannot be empty.")
    combined_secret = f"{password}\x1f{hash_key}".encode("utf-8")
    raw_key = hashlib.pbkdf2_hmac(
        "sha256",
        combined_secret,
        salt_bytes,
        HASH_KEY_KDF_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(raw_key)


def _derive_user_fernet_key_legacy(hash_key: str, salt_bytes: bytes) -> bytes:
    # Backward compatibility for users created before password+hash-key KDF migration.
    if not hash_key:
        raise ValueError("Hash key cannot be empty.")
    raw_key = hashlib.pbkdf2_hmac(
        "sha256",
        hash_key.encode("utf-8"),
        salt_bytes,
        HASH_KEY_KDF_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(raw_key)


def generate_hash_key() -> str:
    # User-facing recovery key; if lost, encrypted entries cannot be decrypted.
    return secrets.token_urlsafe(24)


def _build_user_cipher(password: str, hash_key: str, salt_hex: str) -> Fernet:
    salt_bytes = bytes.fromhex(salt_hex)
    return Fernet(_derive_user_fernet_key(password, hash_key, salt_bytes))


def _build_user_cipher_legacy(hash_key: str, salt_hex: str) -> Fernet:
    salt_bytes = bytes.fromhex(salt_hex)
    return Fernet(_derive_user_fernet_key_legacy(hash_key, salt_bytes))


def _initialize_user_hash_key(user_id: int, password: str, hash_key: str) -> Fernet:
    salt_bytes = os.urandom(16)
    salt_hex = salt_bytes.hex()
    cipher = Fernet(_derive_user_fernet_key(password, hash_key, salt_bytes))
    check_token = cipher.encrypt(HASH_KEY_CHECK_VALUE).decode("utf-8")

    conn = get_conn()
    try:
        conn.execute(
            "UPDATE users SET key_salt = ?, key_check = ? WHERE id = ?",
            (salt_hex, check_token, user_id),
        )
        conn.commit()
    finally:
        conn.close()

    return cipher


def _migrate_legacy_user_cipher(
    user_id: int,
    salt_hex: str,
    legacy_cipher: Fernet,
    new_cipher: Fernet,
) -> None:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, password FROM passwords WHERE user_id = ?",
            (user_id,),
        ).fetchall()

        for row in rows:
            encrypted_or_plain = str(row["password"] or "")
            plain_text = decrypt_secret(legacy_cipher, encrypted_or_plain)
            re_encrypted = encrypt_secret(new_cipher, plain_text)
            conn.execute(
                "UPDATE passwords SET password = ? WHERE id = ?",
                (re_encrypted, int(row["id"])),
            )

        check_token = new_cipher.encrypt(HASH_KEY_CHECK_VALUE).decode("utf-8")
        conn.execute(
            "UPDATE users SET key_salt = ?, key_check = ? WHERE id = ?",
            (salt_hex, check_token, user_id),
        )
        conn.commit()
    finally:
        conn.close()


def _resolve_user_cipher(user_row: sqlite3.Row, password: str, hash_key: str) -> Fernet:
    if not hash_key:
        raise ValueError("Hash key is required.")

    user_id = int(user_row["id"])
    key_salt = user_row["key_salt"]
    key_check = user_row["key_check"]

    if not key_salt or not key_check:
        return _initialize_user_hash_key(user_id, password, hash_key)

    try:
        cipher = _build_user_cipher(password, hash_key, str(key_salt))
        check_plain = cipher.decrypt(str(key_check).encode("utf-8"))
        if check_plain != HASH_KEY_CHECK_VALUE:
            raise ValueError("Invalid hash key.")
        return cipher
    except (InvalidToken, ValueError, TypeError):
        # Legacy fallback: old users might still be on hash_key-only KDF.
        try:
            legacy_cipher = _build_user_cipher_legacy(hash_key, str(key_salt))
            legacy_plain = legacy_cipher.decrypt(str(key_check).encode("utf-8"))
            if legacy_plain != HASH_KEY_CHECK_VALUE:
                raise ValueError("Invalid hash key.")

            new_cipher = _build_user_cipher(password, hash_key, str(key_salt))
            _migrate_legacy_user_cipher(
                user_id=user_id,
                salt_hex=str(key_salt),
                legacy_cipher=legacy_cipher,
                new_cipher=new_cipher,
            )
            return new_cipher
        except (InvalidToken, ValueError, TypeError):
            raise ValueError("Invalid hash key.")


def encrypt_secret(cipher: Fernet, plaintext: str) -> str:
    return cipher.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(cipher: Fernet, token: str) -> str:
    try:
        plain = cipher.decrypt(token.encode("utf-8"))
        return plain.decode("utf-8")
    except (InvalidToken, ValueError, TypeError):
        # Legacy plaintext records continue to work.
        return token


def create_user(email: str, password: str) -> str:
    hash_key = generate_hash_key()

    salt_bytes = os.urandom(16)
    salt_hex = salt_bytes.hex()
    cipher = Fernet(_derive_user_fernet_key(password, hash_key, salt_bytes))
    check_token = cipher.encrypt(HASH_KEY_CHECK_VALUE).decode("utf-8")

    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO users (email, password, key_salt, key_check)
            VALUES (?, ?, ?, ?)
            """,
            (email, hash_password(password), salt_hex, check_token),
        )
        conn.commit()
    finally:
        conn.close()
    return hash_key


def _is_account_locked(lock_until: float | int | str | None) -> bool:
    if lock_until is None:
        return False
    try:
        return float(lock_until) > time.time()
    except (TypeError, ValueError):
        return False


def _remaining_lock_seconds(lock_until: float | int | str | None) -> int:
    if lock_until is None:
        return 0
    try:
        remaining = float(lock_until) - time.time()
    except (TypeError, ValueError):
        return 0
    return max(0, math.ceil(remaining))


def _register_auth_failure(user_id: int) -> float | None:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT failed_attempts FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        current_attempts = int(row["failed_attempts"]) if row else 0
        failed_attempts = current_attempts + 1
        lock_until: float | None = None
        if failed_attempts >= AUTH_MAX_FAILED_ATTEMPTS:
            multiplier = 2 ** (failed_attempts - AUTH_MAX_FAILED_ATTEMPTS)
            lock_seconds = min(
                AUTH_LOCKOUT_MAX_SECONDS,
                AUTH_LOCKOUT_BASE_SECONDS * multiplier,
            )
            lock_until = time.time() + float(lock_seconds)
        conn.execute(
            "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE id = ?",
            (failed_attempts, lock_until, user_id),
        )
        conn.commit()
        return lock_until
    finally:
        conn.close()


def _reset_auth_failures(user_id: int) -> None:
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = ?",
            (user_id,),
        )
        conn.commit()
    finally:
        conn.close()


def _burn_cpu_for_auth(started_at: float, seed_material: bytes) -> None:
    digest = hashlib.sha256(seed_material).digest()
    salt = b"key-pass-auth-burn-v1"
    while time.monotonic() - started_at < AUTH_MIN_DELAY_SECONDS:
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            digest,
            salt,
            AUTH_BURN_CHUNK_ITERATIONS,
            dklen=32,
        )
    _ = digest


def authenticate_user(email: str, password: str, hash_key: str) -> tuple[bool, str, dict | None]:
    started_at = time.monotonic()
    burn_seed = f"{email}|{password}|{hash_key}".encode("utf-8", "ignore")
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT id, email, password, key_salt, key_check, failed_attempts, lock_until
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        _burn_cpu_for_auth(started_at, burn_seed)
        return False, "Invalid email or password.", None

    if _is_account_locked(row["lock_until"]):
        _burn_cpu_for_auth(started_at, burn_seed)
        remaining = _remaining_lock_seconds(row["lock_until"])
        return False, f"Account is locked. Try again in {remaining}s.", None

    if not verify_password(str(row["password"]), password):
        lock_until = _register_auth_failure(int(row["id"]))
        _burn_cpu_for_auth(started_at, burn_seed)
        if lock_until is not None:
            remaining = _remaining_lock_seconds(lock_until)
            return False, f"Too many failed attempts. Try again in {remaining}s.", None
        return False, "Invalid email or password.", None

    try:
        cipher = _resolve_user_cipher(row, password, hash_key)
    except ValueError as exc:
        lock_until = _register_auth_failure(int(row["id"]))
        _burn_cpu_for_auth(started_at, burn_seed)
        if lock_until is not None:
            remaining = _remaining_lock_seconds(lock_until)
            return False, f"Too many failed attempts. Try again in {remaining}s.", None
        return False, str(exc), None

    _upgrade_password_hash_if_needed(
        user_id=int(row["id"]),
        stored_password=str(row["password"]),
        password=password,
    )
    _reset_auth_failures(int(row["id"]))

    context = {
        "user_id": int(row["id"]),
        "email": str(row["email"]),
        "cipher": cipher,
    }
    _burn_cpu_for_auth(started_at, burn_seed)
    return True, "", context


def list_password_entries(user_id: int, cipher: Fernet) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT website, username, password, created_at
            FROM passwords
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,),
        ).fetchall()
        result: list[dict] = []
        for row in rows:
            result.append(
                {
                    "website": row["website"],
                    "username": row["username"],
                    "password": decrypt_secret(cipher, str(row["password"] or "")),
                    "created_at": row["created_at"],
                }
            )
        return result
    finally:
        conn.close()


def add_password_entry(
    user_id: int,
    cipher: Fernet,
    website: str,
    username: str,
    password: str,
) -> None:
    encrypted_password = encrypt_secret(cipher, password)
    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO passwords (user_id, website, username, password)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, website or None, username or None, encrypted_password),
        )
        conn.commit()
    finally:
        conn.close()


class AddPasswordWindow(ctk.CTkToplevel):
    def __init__(self, master, user_id: int, cipher: Fernet, on_saved):
        super().__init__(master)
        self.user_id = user_id
        self.cipher = cipher
        self.on_saved = on_saved
        self.title("Add Password")
        self.geometry("480x310")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        card = ctk.CTkFrame(self, corner_radius=16, fg_color=BG_CARD)
        card.pack(fill="both", expand=True, padx=16, pady=16)

        ctk.CTkLabel(
            card,
            text="Add New Password",
            font=ctk.CTkFont(family="Georgia", size=26, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=18, pady=(16, 4))

        ctk.CTkLabel(
            card,
            text="Website and username are optional, password is required.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", padx=18, pady=(0, 14))

        self.website_entry = ctk.CTkEntry(card, placeholder_text="Website (example.com)")
        self.website_entry.pack(fill="x", padx=18, pady=6)

        self.username_entry = ctk.CTkEntry(card, placeholder_text="Username")
        self.username_entry.pack(fill="x", padx=18, pady=6)

        self.password_entry = ctk.CTkEntry(card, placeholder_text="Password", show="*")
        self.password_entry.pack(fill="x", padx=18, pady=6)

        for widget in (self.website_entry, self.username_entry, self.password_entry):
            widget.bind("<Return>", lambda _event: self.handle_save())

        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.pack(fill="x", padx=18, pady=(14, 18))

        ctk.CTkButton(
            actions,
            text="Save",
            command=self.handle_save,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
        ).pack(side="left")

        ctk.CTkButton(
            actions,
            text="Cancel",
            command=self.destroy,
            fg_color=BTN_NEUTRAL,
            text_color=TEXT_PRIMARY,
            hover_color=BTN_NEUTRAL_HOVER,
        ).pack(side="left", padx=10)

    def handle_save(self) -> None:
        website = self.website_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not password:
            messagebox.showwarning("Missing Information", "Password field is required.")
            return

        try:
            add_password_entry(
                user_id=self.user_id,
                cipher=self.cipher,
                website=website,
                username=username,
                password=password,
            )
        except sqlite3.Error as exc:
            messagebox.showerror("Error", f"Could not save entry: {exc}")
            return

        messagebox.showinfo("Success", "Password entry added.")
        self.on_saved()
        self.destroy()


class DashboardFrame(ctk.CTkFrame):
    def __init__(self, master, user_id: int, email: str, cipher: Fernet, on_logout):
        super().__init__(master, fg_color="transparent")
        self.user_id = user_id
        self.email = email
        self.cipher = cipher
        self.on_logout = on_logout
        self.add_window = None
        self.password_lookup: dict[str, str] = {}

        top = ctk.CTkFrame(self, corner_radius=18, fg_color="#0c1f31")
        top.pack(fill="x", padx=20, pady=(20, 10))

        ctk.CTkLabel(
            top,
            text="Vault Dashboard",
            font=ctk.CTkFont(family="Georgia", size=30, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=20, pady=(18, 2))
        ctk.CTkLabel(
            top,
            text=f"Welcome, {email}",
            font=ctk.CTkFont(size=13),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", padx=20, pady=(0, 18))

        info_row = ctk.CTkFrame(self, fg_color="transparent")
        info_row.pack(fill="x", padx=20, pady=(0, 8))
        self.total_label = ctk.CTkLabel(
            info_row,
            text="Total: 0",
            fg_color=BG_SOFT,
            text_color=TEXT_PRIMARY,
            corner_radius=12,
            padx=12,
            pady=6,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self.total_label.pack(side="left")
        self.last_label = ctk.CTkLabel(
            info_row,
            text="Last entry: -",
            fg_color=BG_SOFT,
            text_color=TEXT_PRIMARY,
            corner_radius=12,
            padx=12,
            pady=6,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self.last_label.pack(side="left", padx=10)

        table_card = ctk.CTkFrame(self, corner_radius=16, fg_color=BG_PANEL)
        table_card.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        ctk.CTkLabel(
            table_card,
            text="Password Entries",
            font=ctk.CTkFont(family="Georgia", size=24, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(14, 8))

        table_wrap = ctk.CTkFrame(table_card, corner_radius=12, fg_color=BG_SURFACE)
        table_wrap.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        table_wrap.grid_columnconfigure(0, weight=1)
        table_wrap.grid_rowconfigure(0, weight=1)

        self._configure_tree_style()
        self.tree = ttk.Treeview(
            table_wrap,
            columns=("website", "username", "password", "created_at"),
            show="headings",
            height=12,
            style="Vault.Treeview",
        )
        self.tree.heading("website", text="Website")
        self.tree.heading("username", text="Username")
        self.tree.heading("password", text="Password")
        self.tree.heading("created_at", text="Created At")
        self.tree.column("website", width=200, anchor="w")
        self.tree.column("username", width=200, anchor="w")
        self.tree.column("password", width=180, anchor="center")
        self.tree.column("created_at", width=240, anchor="w")

        v_scrollbar = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=(8, 0))
        v_scrollbar.grid(row=0, column=1, sticky="ns", pady=(8, 0), padx=(0, 8))
        h_scrollbar.grid(row=1, column=0, sticky="ew", padx=(8, 0), pady=(0, 8))
        self._bind_table_scroll()

        self.status_label = ctk.CTkLabel(
            table_card,
            text="",
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(size=12),
        )
        self.status_label.pack(anchor="w", padx=16, pady=(0, 12))

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(fill="x", padx=20, pady=(0, 20))
        ctk.CTkButton(
            actions,
            text="New Password",
            command=self.open_add_password_page,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
        ).pack(side="left")
        ctk.CTkButton(
            actions,
            text="Refresh",
            command=self.refresh_passwords,
            fg_color=BTN_NEUTRAL,
            text_color=TEXT_PRIMARY,
            hover_color=BTN_NEUTRAL_HOVER,
        ).pack(side="left", padx=10)
        ctk.CTkButton(
            actions,
            text="Show Selected",
            command=self.show_selected_password,
            fg_color=BTN_NEUTRAL,
            text_color=TEXT_PRIMARY,
            hover_color=BTN_NEUTRAL_HOVER,
        ).pack(side="left")
        ctk.CTkButton(
            actions,
            text="Sign Out",
            command=self.on_logout,
            fg_color=BTN_NEUTRAL,
            text_color=TEXT_PRIMARY,
            hover_color=BTN_NEUTRAL_HOVER,
        ).pack(side="right")

        self.refresh_passwords()

    def _configure_tree_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure(
            "Vault.Treeview",
            background=BG_SURFACE,
            fieldbackground=BG_SURFACE,
            foreground=TEXT_PRIMARY,
            rowheight=30,
            bordercolor=BG_SOFT,
            lightcolor=BG_SOFT,
            darkcolor=BG_SOFT,
        )
        style.configure(
            "Vault.Treeview.Heading",
            background=BG_CARD,
            foreground=TEXT_PRIMARY,
            font=("Trebuchet MS", 10, "bold"),
            relief="flat",
        )
        style.map(
            "Vault.Treeview",
            background=[("selected", "#2a628f")],
            foreground=[("selected", "#ffffff")],
        )

    def _bind_table_scroll(self) -> None:
        self.tree.bind("<MouseWheel>", self._on_tree_mousewheel)
        self.tree.bind("<Shift-MouseWheel>", self._on_tree_shift_mousewheel)
        # Linux wheel events
        self.tree.bind("<Button-4>", lambda _event: self.tree.yview_scroll(-1, "units"))
        self.tree.bind("<Button-5>", lambda _event: self.tree.yview_scroll(1, "units"))

    def _on_tree_mousewheel(self, event) -> str:
        direction = -1 if event.delta > 0 else 1
        self.tree.yview_scroll(direction, "units")
        return "break"

    def _on_tree_shift_mousewheel(self, event) -> str:
        direction = -1 if event.delta > 0 else 1
        self.tree.xview_scroll(direction, "units")
        return "break"

    def refresh_passwords(self) -> None:
        rows = list_password_entries(user_id=self.user_id, cipher=self.cipher)
        self.password_lookup.clear()
        for item_id in self.tree.get_children():
            self.tree.delete(item_id)

        for idx, row in enumerate(rows, start=1):
            row_id = str(idx)
            raw_password = str(row["password"] or "")
            self.tree.insert(
                "",
                "end",
                iid=row_id,
                values=(
                    str(row["website"] or ""),
                    str(row["username"] or ""),
                    self.mask_password(raw_password),
                    str(row["created_at"] or ""),
                ),
            )
            self.password_lookup[row_id] = raw_password

        if rows:
            self.status_label.configure(text=f"{len(rows)} entries listed.")
            self.total_label.configure(text=f"Total: {len(rows)}")
            self.last_label.configure(text=f"Last entry: {rows[0]['created_at']}")
        else:
            self.status_label.configure(text="No entries for this user.")
            self.total_label.configure(text="Total: 0")
            self.last_label.configure(text="Last entry: -")

    def open_add_password_page(self) -> None:
        if self.add_window is not None and self.add_window.winfo_exists():
            self.add_window.focus()
            return
        self.add_window = AddPasswordWindow(
            self,
            user_id=self.user_id,
            cipher=self.cipher,
            on_saved=self.refresh_passwords,
        )

    def show_selected_password(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a row first.")
            return

        row_id = selected[0]
        values = self.tree.item(row_id, "values")
        website = values[0] if len(values) > 0 else "-"
        username = values[1] if len(values) > 1 else "-"
        raw_password = self.password_lookup.get(row_id, "")
        messagebox.showinfo(
            "Password Details",
            f"Website: {website}\nUsername: {username}\nPassword: {raw_password}",
        )

    @staticmethod
    def mask_password(password: str) -> str:
        if not password:
            return ""
        return "*" * min(len(password), 12)


class AuthFrame(ctk.CTkFrame):
    def __init__(self, master, on_auth_success):
        super().__init__(master, fg_color="transparent")
        self.on_auth_success = on_auth_success
        self._auth_in_progress = False

        self.grid_columnconfigure(0, weight=5)
        self.grid_columnconfigure(1, weight=6)
        self.grid_rowconfigure(0, weight=1)

        self.hero = ctk.CTkFrame(self, fg_color="#0c1f31", corner_radius=20)
        self.hero.grid(row=0, column=0, sticky="nsew", padx=(20, 10), pady=20)
        self._build_hero()

        self.panel = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=20)
        self.panel.grid(row=0, column=1, sticky="nsew", padx=(10, 20), pady=20)

        self.page_container = ctk.CTkFrame(self.panel, fg_color="transparent")
        self.page_container.pack(fill="both", expand=True, padx=20, pady=20)

        self.login_page = self._build_login_page()
        self.register_page = self._build_register_page()

        if user_count() == 0:
            self.show_register(first_setup=True)
        else:
            self.show_login()

    def _build_hero(self) -> None:
        ctk.CTkLabel(
            self.hero,
            text="KEY PASS",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#d5ebfb",
        ).pack(anchor="w", padx=24, pady=(28, 8))

        ctk.CTkLabel(
            self.hero,
            text="Manage your passwords\nin one place",
            font=ctk.CTkFont(family="Georgia", size=38, weight="bold"),
            text_color="#ffffff",
            justify="left",
        ).pack(anchor="w", padx=24, pady=(0, 8))

        ctk.CTkLabel(
            self.hero,
            text=(
                "Each user has a unique hash key.\n"
                "If the hash key is lost, encrypted passwords cannot be recovered."
            ),
            font=ctk.CTkFont(size=13),
            text_color="#d7eafa",
            justify="left",
        ).pack(anchor="w", padx=24, pady=(0, 24))

    def _build_login_page(self) -> ctk.CTkFrame:
        page = ctk.CTkFrame(self.page_container, fg_color="transparent")

        ctk.CTkLabel(
            page,
            text="Sign In",
            font=ctk.CTkFont(family="Georgia", size=28, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", pady=(4, 6))
        ctk.CTkLabel(
            page,
            text="Continue with email, password, and hash key.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", pady=(0, 16))

        self.login_email_entry = ctk.CTkEntry(
            page,
            placeholder_text="Email",
            height=40,
        )
        self.login_email_entry.pack(fill="x", pady=6)

        self.login_password_entry = ctk.CTkEntry(
            page,
            placeholder_text="Password",
            show="*",
            height=40,
        )
        self.login_password_entry.pack(fill="x", pady=6)

        self.login_hash_key_entry = ctk.CTkEntry(
            page,
            placeholder_text="Hash Key",
            show="*",
            height=40,
        )
        self.login_hash_key_entry.pack(fill="x", pady=6)

        for widget in (
            self.login_email_entry,
            self.login_password_entry,
            self.login_hash_key_entry,
        ):
            widget.bind("<Return>", lambda _event: self.handle_login())

        buttons = ctk.CTkFrame(page, fg_color="transparent")
        buttons.pack(fill="x", pady=(12, 0))
        self.login_btn = ctk.CTkButton(
            buttons,
            text="Sign In",
            command=self.handle_login,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
        )
        self.login_btn.pack(side="left")
        ctk.CTkButton(
            buttons,
            text="Sign Up",
            command=lambda: self.show_register(first_setup=False),
            fg_color=BTN_NEUTRAL,
            text_color=TEXT_PRIMARY,
            hover_color=BTN_NEUTRAL_HOVER,
        ).pack(side="left", padx=10)

        self.login_status_label = ctk.CTkLabel(
            page,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        )
        self.login_status_label.pack(anchor="w", pady=(8, 0))
        return page

    def _build_register_page(self) -> ctk.CTkFrame:
        page = ctk.CTkFrame(self.page_container, fg_color="transparent")

        ctk.CTkLabel(
            page,
            text="Create Account",
            font=ctk.CTkFont(family="Georgia", size=28, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", pady=(4, 6))
        ctk.CTkLabel(
            page,
            text="The hash key is generated by the system and shown only once.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", pady=(0, 16))

        self.reg_email_entry = ctk.CTkEntry(
            page,
            placeholder_text="Email",
            height=40,
        )
        self.reg_email_entry.pack(fill="x", pady=6)

        self.reg_password_entry = ctk.CTkEntry(
            page,
            placeholder_text="Password",
            show="*",
            height=40,
        )
        self.reg_password_entry.pack(fill="x", pady=6)

        self.reg_confirm_entry = ctk.CTkEntry(
            page,
            placeholder_text="Confirm Password",
            show="*",
            height=40,
        )
        self.reg_confirm_entry.pack(fill="x", pady=6)

        for widget in (self.reg_email_entry, self.reg_password_entry, self.reg_confirm_entry):
            widget.bind("<Return>", lambda _event: self.handle_register())

        buttons = ctk.CTkFrame(page, fg_color="transparent")
        buttons.pack(fill="x", pady=(12, 0))
        ctk.CTkButton(
            buttons,
            text="Create Account",
            command=self.handle_register,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
        ).pack(side="left")
        self.back_btn = ctk.CTkButton(
            buttons,
            text="Back to Sign In",
            command=self.show_login,
            fg_color=BTN_NEUTRAL,
            text_color=TEXT_PRIMARY,
            hover_color=BTN_NEUTRAL_HOVER,
        )
        self.back_btn.pack(side="left", padx=10)
        return page

    def show_login(self) -> None:
        self.register_page.pack_forget()
        self.login_page.pack(fill="both", expand=True)

    def show_register(self, first_setup: bool) -> None:
        self.login_page.pack_forget()
        self.register_page.pack(fill="both", expand=True)
        if first_setup:
            self.back_btn.configure(state="disabled")
        else:
            self.back_btn.configure(state="normal")

    def handle_register(self) -> None:
        email = self.reg_email_entry.get().strip().lower()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()

        if not email or not password:
            messagebox.showwarning("Missing Information", "Email and password are required.")
            return
        if password != confirm:
            messagebox.showwarning("Error", "Passwords do not match.")
            return

        try:
            generated_hash_key = create_user(email, password)
        except sqlite3.IntegrityError:
            messagebox.showwarning("Error", "This email is already registered.")
            return

        self.reg_email_entry.delete(0, "end")
        self.reg_password_entry.delete(0, "end")
        self.reg_confirm_entry.delete(0, "end")
        self.login_email_entry.delete(0, "end")
        self.login_email_entry.insert(0, email)
        self._show_hash_key_dialog(generated_hash_key)
        self.show_login()

    def _show_hash_key_dialog(self, hash_key: str) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Hash Key")
        dialog.geometry("560x240")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()

        container = ctk.CTkFrame(dialog, corner_radius=16, fg_color=BG_CARD)
        container.pack(fill="both", expand=True, padx=16, pady=16)

        ctk.CTkLabel(
            container,
            text="Hash Key (shown once)",
            font=ctk.CTkFont(family="Georgia", size=24, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(14, 6))

        ctk.CTkLabel(
            container,
            text="Click Copy and store it in a safe place.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", padx=16, pady=(0, 8))

        key_entry = ctk.CTkEntry(container, height=40)
        key_entry.pack(fill="x", padx=16, pady=6)
        key_entry.insert(0, hash_key)

        def copy_key() -> None:
            dialog.clipboard_clear()
            dialog.clipboard_append(hash_key)
            copy_btn.configure(text="Copied")

        buttons = ctk.CTkFrame(container, fg_color="transparent")
        buttons.pack(fill="x", padx=16, pady=(10, 12))

        copy_btn = ctk.CTkButton(
            buttons,
            text="Copy",
            command=copy_key,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
        )
        copy_btn.pack(side="left")

        ctk.CTkButton(
            buttons,
            text="Done",
            command=dialog.destroy,
            fg_color=BTN_NEUTRAL,
            text_color=TEXT_PRIMARY,
            hover_color=BTN_NEUTRAL_HOVER,
        ).pack(side="left", padx=10)

        self.wait_window(dialog)

    def handle_login(self) -> None:
        if self._auth_in_progress:
            return

        email = self.login_email_entry.get().strip().lower()
        password = self.login_password_entry.get()
        hash_key = self.login_hash_key_entry.get()

        if not email or not password or not hash_key:
            messagebox.showwarning("Missing Information", "Email, password, and hash key are required.")
            return

        self._set_login_busy(True, "Verifying... Please wait.")
        thread = threading.Thread(
            target=self._auth_worker,
            args=(email, password, hash_key),
            daemon=True,
        )
        thread.start()

    def _auth_worker(self, email: str, password: str, hash_key: str) -> None:
        try:
            ok, error_message, context = authenticate_user(email, password, hash_key)
        except Exception as exc:  # noqa: BLE001
            ok, error_message, context = False, f"Unexpected error: {exc}", None
        self.after(0, lambda: self._on_auth_result(ok, error_message, context))

    def _on_auth_result(self, ok: bool, error_message: str, context: dict | None) -> None:
        self._set_login_busy(False, "")
        if not ok or context is None:
            messagebox.showerror("Error", error_message)
            return

        self.login_password_entry.delete(0, "end")
        self.login_hash_key_entry.delete(0, "end")
        self.on_auth_success(
            int(context["user_id"]),
            str(context["email"]),
            context["cipher"],
        )

    def _set_login_busy(self, is_busy: bool, status_text: str) -> None:
        self._auth_in_progress = is_busy
        entry_state = "disabled" if is_busy else "normal"
        btn_state = "disabled" if is_busy else "normal"
        self.login_email_entry.configure(state=entry_state)
        self.login_password_entry.configure(state=entry_state)
        self.login_hash_key_entry.configure(state=entry_state)
        self.login_btn.configure(state=btn_state)
        self.login_status_label.configure(text=status_text)


class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Key Pass")
        self.geometry("1180x760")
        self.minsize(980, 640)
        self.configure(fg_color=BG_APP)
        self.current_view = None
        self.session_active = False
        self.last_activity_at = 0.0
        self._install_activity_bindings()
        self._schedule_session_watchdog()
        self.show_auth()

    def _install_activity_bindings(self) -> None:
        for sequence in (
            "<Any-KeyPress>",
            "<Any-ButtonPress>",
            "<MouseWheel>",
            "<Button-4>",
            "<Button-5>",
        ):
            self.bind_all(sequence, self._mark_activity, add="+")

    def _mark_activity(self, _event=None) -> None:
        if self.session_active:
            self.last_activity_at = time.monotonic()

    def _schedule_session_watchdog(self) -> None:
        self.after(SESSION_CHECK_INTERVAL_MS, self._check_session_timeout)

    def _check_session_timeout(self) -> None:
        try:
            if self.session_active:
                elapsed = time.monotonic() - self.last_activity_at
                if elapsed >= SESSION_TIMEOUT_SECONDS and isinstance(self.current_view, DashboardFrame):
                    self.session_active = False
                    messagebox.showinfo(
                        "Session Expired",
                        "You were signed out due to inactivity.",
                    )
                    self.show_auth()
        finally:
            self._schedule_session_watchdog()

    def show_auth(self) -> None:
        if self.current_view is not None:
            self.current_view.destroy()
        self.session_active = False
        self.current_view = AuthFrame(self, on_auth_success=self.show_dashboard)
        self.current_view.pack(fill="both", expand=True)

    def show_dashboard(self, user_id: int, email: str, cipher: Fernet) -> None:
        if self.current_view is not None:
            self.current_view.destroy()
        self.current_view = DashboardFrame(
            self,
            user_id=user_id,
            email=email,
            cipher=cipher,
            on_logout=self.show_auth,
        )
        self.current_view.pack(fill="both", expand=True)
        self.session_active = True
        self.last_activity_at = time.monotonic()


def main() -> None:
    init_db()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = PasswordManagerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
