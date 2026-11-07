import time
import unittest

from app.security import jwt as J
from app.security.passwords import hash_password, password_problems, verify_password
from app.security.rbac import has_role
from app.security.throttle import LoginThrottle


class TestPasswords(unittest.TestCase):
    def test_hash_verify(self):
        h = hash_password("Correct-Horse9")
        self.assertTrue(verify_password("Correct-Horse9", h))
        self.assertFalse(verify_password("wrong", h))
        self.assertNotEqual(h, hash_password("Correct-Horse9"))  # salted

    def test_malformed_hash_is_false(self):
        self.assertFalse(verify_password("x", "garbage"))

    def test_policy(self):
        self.assertTrue(password_problems("short"))
        self.assertEqual(password_problems("Str0ngPassw0rd"), [])


class TestJWT(unittest.TestCase):
    def test_roundtrip(self):
        t = J.encode_token({"sub": "1", "role": "admin"}, "s" * 32, 60)
        self.assertEqual(J.decode_token(t, "s" * 32)["sub"], "1")

    def test_bad_signature_expired_and_alg_none(self):
        t = J.encode_token({"sub": "1"}, "s" * 32, 60)
        with self.assertRaises(J.TokenError):
            J.decode_token(t, "other-secret")
        with self.assertRaises(J.TokenError):
            J.decode_token(J.encode_token({"sub": "1"}, "s" * 32, -5), "s" * 32)
        head = J._b64e(b'{"alg":"none","typ":"JWT"}')
        body = t.split(".")[1]
        with self.assertRaises(J.TokenError):
            J.decode_token(f"{head}.{body}.", "s" * 32)
        with self.assertRaises(J.TokenError):
            J.decode_token("not-a-token", "s" * 32)

    def test_tampered_payload(self):
        h, b, s = J.encode_token({"sub": "1", "role": "viewer"}, "k" * 32, 60).split(".")
        forged = J._b64e(b'{"sub":"1","role":"admin","exp":9999999999}')
        with self.assertRaises(J.TokenError):
            J.decode_token(f"{h}.{forged}.{s}", "k" * 32)


class TestThrottleRbac(unittest.TestCase):
    def test_lockout_and_reset(self):
        t = LoginThrottle(3, 60)
        for _ in range(3):
            t.failure("a")
        self.assertGreater(t.retry_after("a"), 0)
        self.assertEqual(t.retry_after("b"), 0)
        t.success("a")
        self.assertEqual(t.retry_after("a"), 0)

    def test_window_expiry(self):
        t = LoginThrottle(1, 1)
        t.failure("a")
        time.sleep(1.1)
        self.assertEqual(t.retry_after("a"), 0)

    def test_roles(self):
        self.assertTrue(has_role("admin", "analyst"))
        self.assertFalse(has_role("viewer", "analyst"))
        self.assertFalse(has_role("nobody", "viewer"))


if __name__ == "__main__":
    unittest.main()
