"""Simple in-memory auth service with sign-up, login, logout."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Dict, Optional, Set


class AuthError(ValueError):
    """Raised for authentication and validation failures."""


@dataclass(frozen=True)
class UserRecord:
    username: str
    password_hash: str


class AuthService:
    """In-memory authentication service.

    Notes:
        - This is intentionally simple and not persistent.
        - Passwords are stored as PBKDF2 hashes.
        - Sessions are stored in memory as opaque tokens.
    """

    def __init__(self, *, min_password_length: int = 8, max_sessions_per_user: int = 5) -> None:
        self._min_password_length = min_password_length
        self._max_sessions_per_user = max_sessions_per_user
        self._users: Dict[str, UserRecord] = {}
        self._sessions: Dict[str, str] = {}
        self._user_sessions: Dict[str, Set[str]] = {}

    def sign_up(self, username: str, password: str) -> UserRecord:
        """Register a new user.

        Raises:
            AuthError: when validation fails or username already exists.
        """
        username = self._normalize_username(username)
        self._validate_password(password)
        if username in self._users:
            raise AuthError("Username already exists.")

        password_hash = self._hash_password(password)
        record = UserRecord(username=username, password_hash=password_hash)
        self._users[username] = record
        self._user_sessions[username] = set()
        return record

    def login(self, username: str, password: str) -> str:
        """Authenticate a user and create a session token."""
        username = self._normalize_username(username)
        record = self._users.get(username)
        if record is None or not self._verify_password(password, record.password_hash):
            raise AuthError("Invalid username or password.")

        return self._new_session(username)

    def logout(self, token: str) -> bool:
        """Invalidate a session token."""
        username = self._sessions.pop(token, None)
        if username is None:
            return False
        user_tokens = self._user_sessions.get(username)
        if user_tokens is not None:
            user_tokens.discard(token)
        return True

    def get_current_user(self, token: str) -> Optional[str]:
        """Return the username for a valid token, if any."""
        return self._sessions.get(token)

    def list_sessions(self, username: str) -> Set[str]:
        """Return a copy of all active session tokens for a user."""
        username = self._normalize_username(username)
        return set(self._user_sessions.get(username, set()))

    def _new_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = username
        user_tokens = self._user_sessions.setdefault(username, set())
        user_tokens.add(token)
        if len(user_tokens) > self._max_sessions_per_user:
            oldest_token = next(iter(user_tokens))
            user_tokens.discard(oldest_token)
            self._sessions.pop(oldest_token, None)
        return token

    def _normalize_username(self, username: str) -> str:
        if not isinstance(username, str):
            raise AuthError("Username must be a string.")
        normalized = username.strip()
        if len(normalized) < 3:
            raise AuthError("Username must be at least 3 characters.")
        if len(normalized) > 64:
            raise AuthError("Username must be at most 64 characters.")
        return normalized

    def _validate_password(self, password: str) -> None:
        if not isinstance(password, str):
            raise AuthError("Password must be a string.")
        if len(password) < self._min_password_length:
            raise AuthError(f"Password must be at least {self._min_password_length} characters.")

    def _hash_password(self, password: str) -> str:
        salt = secrets.token_bytes(16)
        iterations = 120_000
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"

    def _verify_password(self, password: str, password_hash: str) -> bool:
        try:
            algorithm, iterations_str, salt_hex, digest_hex = password_hash.split("$", 3)
        except ValueError:
            return False
        if algorithm != "pbkdf2_sha256":
            return False
        try:
            iterations = int(iterations_str)
        except ValueError:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
