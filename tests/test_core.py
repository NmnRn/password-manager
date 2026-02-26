import unittest
from pathlib import Path

import app


class CoreFlowTests(unittest.TestCase):
    def setUp(self):
        self.original_db_path = app.DB_PATH
        self.original_auth_delay = app.AUTH_MIN_DELAY_SECONDS
        self.original_pw_iter = app.PASSWORD_KDF_ITERATIONS
        self.original_pw_argon2_time = app.PASSWORD_ARGON2_TIME_COST
        self.original_pw_argon2_memory = app.PASSWORD_ARGON2_MEMORY_COST_KIB
        self.original_pw_argon2_parallelism = app.PASSWORD_ARGON2_PARALLELISM
        self.original_hash_iter = app.HASH_KEY_KDF_ITERATIONS
        self.original_max_failed_attempts = app.AUTH_MAX_FAILED_ATTEMPTS
        self.original_lockout_base_seconds = app.AUTH_LOCKOUT_BASE_SECONDS
        self.original_lockout_max_seconds = app.AUTH_LOCKOUT_MAX_SECONDS

        self.test_db_path = Path(".test_runtime.db")
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.test_db_path}{suffix}")
            if candidate.exists():
                candidate.unlink()

        app.DB_PATH = self.test_db_path
        app.AUTH_MIN_DELAY_SECONDS = 0.01
        app.PASSWORD_KDF_ITERATIONS = 2_000
        app.PASSWORD_ARGON2_TIME_COST = 1
        app.PASSWORD_ARGON2_MEMORY_COST_KIB = 8192
        app.PASSWORD_ARGON2_PARALLELISM = 1
        app.HASH_KEY_KDF_ITERATIONS = 2_000
        app.AUTH_MAX_FAILED_ATTEMPTS = 3
        app.AUTH_LOCKOUT_BASE_SECONDS = 1
        app.AUTH_LOCKOUT_MAX_SECONDS = 8
        app.init_db()

    def tearDown(self):
        app.DB_PATH = self.original_db_path
        app.AUTH_MIN_DELAY_SECONDS = self.original_auth_delay
        app.PASSWORD_KDF_ITERATIONS = self.original_pw_iter
        app.PASSWORD_ARGON2_TIME_COST = self.original_pw_argon2_time
        app.PASSWORD_ARGON2_MEMORY_COST_KIB = self.original_pw_argon2_memory
        app.PASSWORD_ARGON2_PARALLELISM = self.original_pw_argon2_parallelism
        app.HASH_KEY_KDF_ITERATIONS = self.original_hash_iter
        app.AUTH_MAX_FAILED_ATTEMPTS = self.original_max_failed_attempts
        app.AUTH_LOCKOUT_BASE_SECONDS = self.original_lockout_base_seconds
        app.AUTH_LOCKOUT_MAX_SECONDS = self.original_lockout_max_seconds
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.test_db_path}{suffix}")
            if candidate.exists():
                candidate.unlink()

    def test_auth_success_and_fail(self):
        email = "user1@test.local"
        password = "p@ss-1"
        hash_key = app.create_user(email, password)

        conn = app.get_conn()
        try:
            row = conn.execute("SELECT password FROM users WHERE email = ?", (email,)).fetchone()
            self.assertTrue(str(row["password"]).startswith("$argon2id$"))
        finally:
            conn.close()

        ok, err, ctx = app.authenticate_user(email, password, hash_key)
        self.assertTrue(ok)
        self.assertEqual(err, "")
        self.assertIsNotNone(ctx)

        ok_wrong_key, _, _ = app.authenticate_user(email, password, "wrong")
        self.assertFalse(ok_wrong_key)

        ok_wrong_pw, _, _ = app.authenticate_user(email, "wrong", hash_key)
        self.assertFalse(ok_wrong_pw)

    def test_user_isolation(self):
        hash1 = app.create_user("u1@test.local", "pw1")
        hash2 = app.create_user("u2@test.local", "pw2")

        _, _, ctx1 = app.authenticate_user("u1@test.local", "pw1", hash1)
        _, _, ctx2 = app.authenticate_user("u2@test.local", "pw2", hash2)
        self.assertIsNotNone(ctx1)
        self.assertIsNotNone(ctx2)

        app.add_password_entry(ctx1["user_id"], ctx1["cipher"], "site-a", "u1", "secret-a")
        app.add_password_entry(ctx2["user_id"], ctx2["cipher"], "site-b", "u2", "secret-b")

        rows1 = app.list_password_entries(ctx1["user_id"], ctx1["cipher"])
        rows2 = app.list_password_entries(ctx2["user_id"], ctx2["cipher"])

        self.assertEqual(len(rows1), 1)
        self.assertEqual(len(rows2), 1)
        self.assertEqual(rows1[0]["website"], "site-a")
        self.assertEqual(rows2[0]["website"], "site-b")

    def test_lockout_after_failed_attempts(self):
        email = "lock@test.local"
        password = "pw-lock"
        hash_key = app.create_user(email, password)

        ok1, _, _ = app.authenticate_user(email, "wrong-1", hash_key)
        ok2, _, _ = app.authenticate_user(email, "wrong-2", hash_key)
        ok3, err3, _ = app.authenticate_user(email, "wrong-3", hash_key)
        self.assertFalse(ok1)
        self.assertFalse(ok2)
        self.assertFalse(ok3)
        self.assertIn("Too many failed attempts", err3)

        ok_locked, err_locked, _ = app.authenticate_user(email, password, hash_key)
        self.assertFalse(ok_locked)
        self.assertIn("Account is locked", err_locked)

        conn = app.get_conn()
        try:
            conn.execute(
                "UPDATE users SET lock_until = ?, failed_attempts = 0 WHERE email = ?",
                (0, email),
            )
            conn.commit()
        finally:
            conn.close()

        ok_after_clear, err_after_clear, ctx_after_clear = app.authenticate_user(email, password, hash_key)
        self.assertTrue(ok_after_clear)
        self.assertEqual(err_after_clear, "")
        self.assertIsNotNone(ctx_after_clear)


if __name__ == "__main__":
    unittest.main()
