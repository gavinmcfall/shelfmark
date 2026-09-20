"""Tests for the API_KEY environment-variable authentication."""

from __future__ import annotations

import os
import tempfile

import pytest

from shelfmark.core import api_key


@pytest.fixture
def user_db():
    from shelfmark.core.user_db import UserDB

    with tempfile.TemporaryDirectory() as tmpdir:
        db = UserDB(os.path.join(tmpdir, "users.db"))
        db.initialize()
        yield db


class TestExtractCandidate:
    def test_bearer(self):
        assert api_key.extract_api_key_candidate("Bearer abc", None) == "abc"

    def test_bearer_case_insensitive_and_trimmed(self):
        assert api_key.extract_api_key_candidate("bearer  abc ", None) == "abc"

    def test_non_bearer_scheme_ignored(self):
        assert api_key.extract_api_key_candidate("Basic dXNlcjpwYXNz", None) is None

    def test_x_api_key(self):
        assert api_key.extract_api_key_candidate(None, " abc ") == "abc"

    def test_bearer_wins(self):
        assert api_key.extract_api_key_candidate("Bearer a", "b") == "a"

    def test_empty(self):
        assert api_key.extract_api_key_candidate("Bearer ", "") is None
        assert api_key.extract_api_key_candidate(None, None) is None


class TestMatches:
    def test_unset_never_matches(self, monkeypatch):
        monkeypatch.setattr(api_key, "API_KEY", "")
        assert api_key.matches_api_key("anything") is False
        assert api_key.matches_api_key("") is False

    def test_match(self, monkeypatch):
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        assert api_key.matches_api_key("s3cret") is True

    def test_mismatch_and_prefix(self, monkeypatch):
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        assert api_key.matches_api_key("s3cre") is False
        assert api_key.matches_api_key("s3cret ") is False
        assert api_key.matches_api_key("") is False


class TestFirstAdmin:
    def test_none_when_no_admin(self, user_db):
        user_db.create_user(username="alice")
        assert user_db.get_first_admin() is None

    def test_first_admin_by_id(self, user_db):
        user_db.create_user(username="alice")
        root = user_db.create_user(username="root", role="admin")
        user_db.create_user(username="root2", role="admin")
        assert user_db.get_first_admin()["id"] == root["id"]
