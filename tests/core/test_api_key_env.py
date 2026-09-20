"""Tests for the API_KEY environment-variable authentication."""

from __future__ import annotations

import importlib
import os
import sqlite3
import tempfile
from unittest.mock import patch

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


@pytest.fixture(scope="module")
def main_module():
    with patch("shelfmark.download.orchestrator.start"):
        import shelfmark.main as main

        importlib.reload(main)
        return main


@pytest.fixture
def wired(main_module, user_db, monkeypatch):
    monkeypatch.setattr(main_module, "user_db", user_db)
    monkeypatch.setattr(api_key, "API_KEY", "s3cret")
    with patch.object(main_module, "get_auth_mode", return_value="builtin"):
        yield main_module


def _bearer(value):
    return {"Authorization": f"Bearer {value}"}


def _cookie_client(app, user, *, is_admin=False, permanent=False):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = user["username"]
        sess["is_admin"] = is_admin
        sess["db_user_id"] = user["id"]
        sess.permanent = permanent
    return client


class TestKeyedRequests:
    def test_match_reaches_login_required_route(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        assert (
            wired.app.test_client()
            .get("/api/downloads/active", headers=_bearer("s3cret"))
            .status_code
            == 200
        )

    def test_match_is_admin(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        assert (
            wired.app.test_client().get("/api/settings", headers=_bearer("s3cret")).status_code
            == 200
        )

    def test_match_without_any_admin_user_is_still_admin(self, wired):
        assert (
            wired.app.test_client().get("/api/settings", headers=_bearer("s3cret")).status_code
            == 200
        )

    def test_match_no_user_db(self, main_module, monkeypatch):
        monkeypatch.setattr(main_module, "user_db", None)
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        with patch.object(main_module, "get_auth_mode", return_value="builtin"):
            assert (
                main_module.app.test_client()
                .get("/api/downloads/active", headers=_bearer("s3cret"))
                .status_code
                == 200
            )

    def test_x_api_key(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        assert (
            wired.app.test_client()
            .get("/api/downloads/active", headers={"X-Api-Key": "s3cret"})
            .status_code
            == 200
        )

    def test_no_set_cookie_even_when_handler_dirties_session(self, wired, user_db, monkeypatch):
        user_db.create_user(username="root", role="admin")
        original = wired.app.view_functions["api_active_downloads"]

        def dirty(*args, **kwargs):
            from flask import session

            session["dirty"] = True
            return original(*args, **kwargs)

        monkeypatch.setitem(wired.app.view_functions, "api_active_downloads", dirty)
        response = wired.app.test_client().get("/api/downloads/active", headers=_bearer("s3cret"))
        assert response.status_code == 200
        assert "Set-Cookie" not in response.headers

    def test_incoming_non_admin_cookie_is_ignored(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        alice = user_db.create_user(username="alice")
        client = _cookie_client(wired.app, alice)
        assert client.get("/api/settings", headers=_bearer("s3cret")).status_code == 200

    def test_matched_key_leaves_browser_cookie_usable(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        alice = user_db.create_user(username="alice")
        client = _cookie_client(wired.app, alice)
        assert client.get("/api/settings", headers=_bearer("s3cret")).status_code == 200

        assert client.get("/api/downloads/active").status_code == 200
        assert client.get("/api/settings").status_code == 403

    def test_security_headers_present(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        response = wired.app.test_client().get("/api/downloads/active", headers=_bearer("s3cret"))
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_store_error_is_500_not_anonymous(self, wired, user_db, monkeypatch):
        monkeypatch.setattr(
            user_db,
            "get_first_admin",
            lambda: (_ for _ in ()).throw(sqlite3.OperationalError("boom")),
        )
        response = wired.app.test_client().get("/api/downloads/active", headers=_bearer("s3cret"))
        assert response.status_code == 500
        assert response.get_json() == {"error": "Authentication error"}


class TestMismatchFallsThrough:
    def test_mismatch_no_cookie_is_plain_unauthorized(self, wired):
        response = wired.app.test_client().get("/api/downloads/active", headers=_bearer("wrong"))
        assert response.status_code == 401
        assert response.get_json() == {"error": "Unauthorized"}

    def test_mismatch_with_cookie_uses_cookie(self, wired, user_db):
        alice = user_db.create_user(username="alice")
        client = _cookie_client(wired.app, alice)
        assert client.get("/api/downloads/active", headers=_bearer("wrong")).status_code == 200
        assert client.get("/api/settings", headers=_bearer("wrong")).status_code == 403

    def test_mismatch_leaves_browser_session_untouched(self, wired, user_db):
        alice = user_db.create_user(username="alice")
        client = _cookie_client(wired.app, alice, permanent=True)
        response = client.get("/api/downloads/active", headers=_bearer("wrong"))
        assert response.status_code == 200
        assert client.get("/api/downloads/active").status_code == 200

    def test_unset_key_is_noop(self, main_module, user_db, monkeypatch):
        monkeypatch.setattr(main_module, "user_db", user_db)
        monkeypatch.setattr(api_key, "API_KEY", "")
        with patch.object(main_module, "get_auth_mode", return_value="builtin"):
            response = main_module.app.test_client().get(
                "/api/downloads/active", headers=_bearer("s3cret")
            )
            assert response.status_code == 401
            assert response.get_json() == {"error": "Unauthorized"}

            alice = user_db.create_user(username="alice")
            client = _cookie_client(main_module.app, alice, permanent=True)
            cookie_response = client.get("/api/downloads/active", headers=_bearer("s3cret"))
        assert cookie_response.status_code == 200
        assert "Set-Cookie" in cookie_response.headers


class TestScopeAndModes:
    def test_health_and_auth_paths_and_root_ignore_key(self, wired):
        client = wired.app.test_client()
        assert client.get("/api/health", headers=_bearer("s3cret")).status_code == 200
        assert (
            client.get("/api/auth/check", headers=_bearer("s3cret")).get_json()["authenticated"]
            is False
        )
        assert client.get("/", headers=_bearer("s3cret")).status_code != 401

    def test_none_mode_noop(self, main_module, user_db, monkeypatch):
        monkeypatch.setattr(main_module, "user_db", user_db)
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        with patch.object(main_module, "get_auth_mode", return_value="none"):
            assert (
                main_module.app.test_client()
                .get("/api/downloads/active", headers=_bearer("s3cret"))
                .status_code
                == 200
            )

    def test_proxy_mode_keyed_request_needs_no_proxy_header(
        self, main_module, user_db, monkeypatch
    ):
        monkeypatch.setattr(main_module, "user_db", user_db)
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        user_db.create_user(username="root", role="admin", auth_source="proxy")
        with patch.object(main_module, "get_auth_mode", return_value="proxy"):
            assert (
                main_module.app.test_client()
                .get("/api/downloads/active", headers=_bearer("s3cret"))
                .status_code
                == 200
            )
